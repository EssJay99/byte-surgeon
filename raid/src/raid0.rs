use anyhow::Result;
use tracing::{debug, info};

use crate::common::{RaidDisk, RaidLevel, RaidReconstructor};

pub struct Raid0 {
    disks: Vec<RaidDisk>,
    chunk_size: u64,
    healthy: bool,
}

impl RaidReconstructor for Raid0 {
    fn new(disks: Vec<RaidDisk>) -> Result<Self> {
        if disks.len() < 2 {
            anyhow::bail!("RAID0 requires at least 2 disks");
        }

        for disk in &disks {
            if disk.data.is_empty() {
                anyhow::bail!("Disk {} has no data", disk.path);
            }
        }

        let min_size = disks.iter().map(|d| d.size).min().unwrap_or(0);
        let chunk_size = Self::calculate_chunk_size(&disks, min_size);

        info!(
            "RAID0 initialized with {} disks, chunk size: {} bytes",
            disks.len(),
            chunk_size
        );

        Ok(Self {
            disks,
            chunk_size,
            healthy: true,
        })
    }

    fn reconstruct(&mut self) -> Result<Vec<u8>> {
        info!("Starting RAID0 reconstruction");

        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let min_disk_size = self.disks.iter().map(|d| d.data.len()).min().unwrap_or(0);
        let chunks_per_disk = min_disk_size / chunk_size;
        let total_size = chunks_per_disk * chunk_size * disk_count;

        let mut result = Vec::with_capacity(total_size);

        for chunk_idx in 0..chunks_per_disk {
            let disk_idx = chunk_idx % disk_count;
            let offset = (chunk_idx / disk_count) * chunk_size;

            let start = offset;
            let end = std::cmp::min(start + chunk_size, self.disks[disk_idx].data.len());

            if start < end {
                result.extend_from_slice(&self.disks[disk_idx].data[start..end]);
            }

            if end - start < chunk_size {
                let padding = chunk_size - (end - start);
                result.extend(vec![0u8; padding]);
            }
        }

        info!("RAID0 reconstruction complete: {} bytes", result.len());
        Ok(result)
    }

    fn raid_level(&self) -> RaidLevel {
        RaidLevel::Raid0
    }

    fn is_healthy(&self) -> bool {
        self.healthy
    }

    fn degraded_disks(&self) -> Vec<usize> {
        Vec::new()
    }
}

impl Raid0 {
    fn calculate_chunk_size(disks: &[RaidDisk], _min_size: u64) -> u64 {
        let common_sizes = [
            4096u64, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
        ];

        for chunk_size in &common_sizes {
            if disks.iter().all(|d| d.data.len() as u64 >= *chunk_size * 2) {
                let mut sequential_count = 0;

                for stripe_idx in 0..std::cmp::min(4, disks[0].data.len() / (*chunk_size as usize * disks.len())) {
                    for disk_idx in 0..disks.len() {
                        let offset = stripe_idx * *chunk_size as usize;
                        if offset + *chunk_size as usize <= disks[disk_idx].data.len() {
                            let has_data = disks[disk_idx].data[offset..offset + *chunk_size as usize]
                                .iter()
                                .any(|&b| b != 0);
                            if has_data {
                                sequential_count += 1;
                            }
                        }
                    }
                }

                if sequential_count > 0 {
                    debug!("Selected chunk size: {} bytes", chunk_size);
                    return *chunk_size;
                }
            }
        }

        65536
    }

    pub fn with_chunk_size(mut self, chunk_size: u64) -> Self {
        self.chunk_size = chunk_size;
        self
    }

    pub fn get_stripe_offset(&self, stripe_number: usize) -> u64 {
        stripe_number as u64 * self.chunk_size * self.disks.len() as u64
    }

    pub fn get_chunk_location(&self, logical_offset: u64) -> (usize, u64) {
        let chunk_size = self.chunk_size;
        let disk_count = self.disks.len() as u64;

        let chunk_number = logical_offset / chunk_size;
        let disk_idx = (chunk_number % disk_count) as usize;
        let offset_in_disk = (chunk_number / disk_count) * chunk_size;

        (disk_idx, offset_in_disk)
    }
}
