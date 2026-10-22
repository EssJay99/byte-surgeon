use anyhow::Result;
use tracing::{debug, info};

use crate::common::{RaidDisk, RaidLevel, RaidReconstructor};

pub struct Raid1 {
    disks: Vec<RaidDisk>,
    primary_disk: usize,
    healthy: bool,
}

impl RaidReconstructor for Raid1 {
    fn new(disks: Vec<RaidDisk>) -> Result<Self> {
        if disks.is_empty() {
            anyhow::bail!("RAID1 requires at least 1 disk");
        }

        let primary_disk = Self::select_primary_disk(&disks)?;

        info!(
            "RAID1 initialized with {} disks, primary: disk {}",
            disks.len(),
            primary_disk
        );

        Ok(Self {
            disks,
            primary_disk,
            healthy: true,
        })
    }

    fn reconstruct(&mut self) -> Result<Vec<u8>> {
        info!("Starting RAID1 reconstruction");

        let primary_data = &self.disks[self.primary_disk].data;
        let result = primary_data.clone();

        if self.disks.len() > 1 {
            self.verify_mirror_consistency()?;
        }

        info!("RAID1 reconstruction complete: {} bytes", result.len());
        Ok(result)
    }

    fn raid_level(&self) -> RaidLevel {
        RaidLevel::Raid1
    }

    fn is_healthy(&self) -> bool {
        self.healthy
    }

    fn degraded_disks(&self) -> Vec<usize> {
        let mut degraded = Vec::new();

        for (idx, disk) in self.disks.iter().enumerate() {
            if disk.data.is_empty() || idx != self.primary_disk && !self.is_disk_synced(idx) {
                degraded.push(idx);
            }
        }

        degraded
    }
}

impl Raid1 {
    fn select_primary_disk(disks: &[RaidDisk]) -> Result<usize> {
        let mut best_disk = 0;
        let mut best_score = 0;

        for (idx, disk) in disks.iter().enumerate() {
            let score = Self::calculate_disk_health_score(disk);
            debug!("Disk {} health score: {}", idx, score);

            if score > best_score {
                best_score = score;
                best_disk = idx;
            }
        }

        Ok(best_disk)
    }

    fn calculate_disk_health_score(disk: &RaidDisk) -> u32 {
        let mut score = 0u32;

        if !disk.data.is_empty() {
            score += 100;
        }

        score += std::cmp::min(disk.data.len() as u32 / 1024, 100);

        let non_zero_bytes = disk.data.iter().filter(|&&b| b != 0).count();
        score += std::cmp::min(non_zero_bytes as u32 / 1024, 50);

        score
    }

    fn verify_mirror_consistency(&self) -> Result<()> {
        info!("Verifying mirror consistency");

        let primary_data = &self.disks[self.primary_disk].data;
        let block_size = 512;
        let mut mismatches = 0;
        let mut blocks_checked = 0;

        for (idx, disk) in self.disks.iter().enumerate() {
            if idx == self.primary_disk {
                continue;
            }

            let compare_len = std::cmp::min(primary_data.len(), disk.data.len());

            for offset in (0..compare_len).step_by(block_size) {
                let end = std::cmp::min(offset + block_size, compare_len);
                let primary_block = &primary_data[offset..end];
                let mirror_block = &disk.data[offset..end];

                if primary_block != mirror_block {
                    mismatches += 1;
                    debug!(
                        "Mismatch found at offset {} between disk {} and primary",
                        offset, idx
                    );
                }

                blocks_checked += 1;
            }
        }

        if mismatches > 0 {
            debug!(
                "Mirror verification: {} mismatches in {} blocks",
                mismatches, blocks_checked
            );
        } else {
            debug!("Mirror verification: all blocks match");
        }

        Ok(())
    }

    fn is_disk_synced(&self, disk_idx: usize) -> bool {
        if disk_idx == self.primary_disk {
            return true;
        }

        let primary_data = &self.disks[self.primary_disk].data;
        let disk_data = &self.disks[disk_idx].data;

        let compare_len = std::cmp::min(primary_data.len(), disk_data.len());
        let sample_size = std::cmp::min(compare_len, 4096);

        let matching_bytes = primary_data[..sample_size]
            .iter()
            .zip(&disk_data[..sample_size])
            .filter(|(a, b)| a == b)
            .count();

        matching_bytes == sample_size
    }

    pub fn get_primary_disk(&self) -> usize {
        self.primary_disk
    }

    pub fn auto_select_healthy_disk(&mut self) -> Result<()> {
        let new_primary = Self::select_primary_disk(&self.disks)?;

        if new_primary != self.primary_disk {
            info!(
                "Switching primary disk from {} to {}",
                self.primary_disk, new_primary
            );
            self.primary_disk = new_primary;
        }

        Ok(())
    }
}
