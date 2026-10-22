use anyhow::Result;
use tracing::{debug, info};

use crate::common::{RaidDisk, RaidInfo, RaidLevel};

pub struct RaidDetector;

impl RaidDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, disks: &[RaidDisk]) -> Result<RaidInfo> {
        if disks.is_empty() {
            anyhow::bail!("No disks provided for RAID detection");
        }

        info!("Starting RAID detection on {} disks", disks.len());

        if let Some(info) = self.detect_superblock(disks)? {
            info!("Detected RAID via superblock: {:?}", info.level);
            return Ok(info);
        }

        if let Some(info) = self.detect_by_content_analysis(disks)? {
            info!("Detected RAID via content analysis: {:?}", info.level);
            return Ok(info);
        }

        Ok(RaidInfo {
            level: RaidLevel::Unknown,
            disk_count: disks.len(),
            stripe_size: 0,
            chunk_size: 0,
        })
    }

    fn detect_superblock(&self, disks: &[RaidDisk]) -> Result<Option<RaidInfo>> {
        for disk in disks {
            if disk.data.len() < 4096 {
                continue;
            }

            if let Some(info) = self.check_linux_md_superblock(disk)? {
                return Ok(Some(info));
            }

            if let Some(info) = self.check_intel_rst_superblock(disk)? {
                return Ok(Some(info));
            }

            if let Some(info) = self.check_lsi_megraid_superblock(disk)? {
                return Ok(Some(info));
            }
        }

        Ok(None)
    }

    fn check_linux_md_superblock(&self, disk: &RaidDisk) -> Result<Option<RaidInfo>> {
        let data = &disk.data;
        if data.len() < 4096 {
            return Ok(None);
        }

        let md_magic = [0xa9, 0x2b, 0x4e, 0xfc];
        for offset in (0..std::cmp::min(data.len() - 4, 4096)).step_by(4) {
            if data[offset..offset + 4] == md_magic {
                debug!("Found Linux md RAID superblock at offset {}", offset);

                if offset + 40 <= data.len() {
                    let version = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);

                    if version == 1 || version == 0x90 {
                        let level_val = if offset + 16 + 4 <= data.len() {
                            i32::from_le_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ])
                        } else {
                            -1
                        };

                        let raid_level = match level_val {
                            0 => RaidLevel::Raid0,
                            1 => RaidLevel::Raid1,
                            5 => RaidLevel::Raid5,
                            6 => RaidLevel::Raid6,
                            _ => RaidLevel::Unknown,
                        };

                        let chunk_size = if offset + 24 + 4 <= data.len() {
                            u32::from_le_bytes([
                                data[offset + 24],
                                data[offset + 25],
                                data[offset + 26],
                                data[offset + 27],
                            ]) as u64
                        } else {
                            512 * 1024
                        };

                        let disk_count = if offset + 32 + 4 <= data.len() {
                            u32::from_le_bytes([
                                data[offset + 32],
                                data[offset + 33],
                                data[offset + 34],
                                data[offset + 35],
                            ]) as usize
                        } else {
                            0
                        };

                        return Ok(Some(RaidInfo {
                            level: raid_level,
                            disk_count,
                            stripe_size: chunk_size * disk_count as u64,
                            chunk_size,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    fn check_intel_rst_superblock(&self, disk: &RaidDisk) -> Result<Option<RaidInfo>> {
        let data = &disk.data;
        let signature = b"IntelRst";

        if data.len() < 1024 + signature.len() {
            return Ok(None);
        }

        for offset in (0..std::cmp::min(data.len() - signature.len(), 2048)).rev() {
            if data[offset..offset + signature.len()] == *signature {
                debug!("Found Intel RST metadata at offset {}", offset);

                let level_byte = if offset + signature.len() + 8 < data.len() {
                    data[offset + signature.len() + 8]
                } else {
                    0
                };

                let raid_level = match level_byte {
                    0 => RaidLevel::Raid0,
                    1 => RaidLevel::Raid1,
                    2 => RaidLevel::Raid5,
                    3 => RaidLevel::Raid6,
                    _ => RaidLevel::Unknown,
                };

                return Ok(Some(RaidInfo {
                    level: raid_level,
                    disk_count: 0,
                    stripe_size: 128 * 1024,
                    chunk_size: 64 * 1024,
                }));
            }
        }

        Ok(None)
    }

    fn check_lsi_megraid_superblock(&self, disk: &RaidDisk) -> Result<Option<RaidInfo>> {
        let data = &disk.data;
        if data.len() < 512 {
            return Ok(None);
        }

        let lsi_magic = [0x5C, 0x06, 0x00, 0x00];
        if data.len() >= 4 && data[0..4] == lsi_magic {
            debug!("Found LSI MegaRAID metadata");

            let level_val = if data.len() >= 8 {
                u32::from_le_bytes([data[4], data[5], data[6], data[7]])
            } else {
                0
            };

            let raid_level = match level_val {
                0 => RaidLevel::Raid0,
                1 => RaidLevel::Raid1,
                5 => RaidLevel::Raid5,
                6 => RaidLevel::Raid6,
                _ => RaidLevel::Unknown,
            };

            return Ok(Some(RaidInfo {
                level: raid_level,
                disk_count: 0,
                stripe_size: 256 * 1024,
                chunk_size: 64 * 1024,
            }));
        }

        Ok(None)
    }

    fn detect_by_content_analysis(&self, disks: &[RaidDisk]) -> Result<Option<RaidInfo>> {
        if disks.len() < 2 {
            return Ok(None);
        }

        if let Some(info) = self.detect_raid1(disks)? {
            return Ok(Some(info));
        }

        if let Some(info) = self.detect_raid0(disks)? {
            return Ok(Some(info));
        }

        if let Some(info) = self.detect_raid5(disks)? {
            return Ok(Some(info));
        }

        Ok(None)
    }

    fn detect_raid1(&self, disks: &[RaidDisk]) -> Result<Option<RaidInfo>> {
        if disks.len() < 2 {
            return Ok(None);
        }

        let disk0 = &disks[0];
        let disk1 = &disks[1];

        let compare_len = std::cmp::min(disk0.data.len(), disk1.data.len());
        let sample_size = std::cmp::min(compare_len, 64 * 1024);

        if sample_size == 0 {
            return Ok(None);
        }

        let mut match_count = 0;
        let block_size = 512;
        let mut blocks_checked = 0;

        for offset in (0..sample_size).step_by(block_size) {
            let end = std::cmp::min(offset + block_size, sample_size);
            if disk0.data[offset..end] == disk1.data[offset..end] {
                match_count += 1;
            }
            blocks_checked += 1;
        }

        let match_ratio = match_count as f64 / blocks_checked as f64;
        debug!("RAID1 detection: match ratio = {:.2}", match_ratio);

        if match_ratio > 0.95 {
            return Ok(Some(RaidInfo {
                level: RaidLevel::Raid1,
                disk_count: disks.len(),
                stripe_size: 0,
                chunk_size: 0,
            }));
        }

        Ok(None)
    }

    fn detect_raid0(&self, disks: &[RaidDisk]) -> Result<Option<RaidInfo>> {
        if disks.len() < 2 {
            return Ok(None);
        }

        let common_sizes = [
            4096u64,
            8192,
            16384,
            32768,
            65536,
            131072,
            262144,
            524288,
        ];

        for chunk_size in &common_sizes {
            let chunk_size = *chunk_size as usize;

            if disks.iter().all(|d| d.data.len() >= chunk_size * 2) {
                let mut score = 0.0;
                let mut checks = 0;

                for stripe_idx in 0..std::cmp::min(8, disks[0].data.len() / (chunk_size * disks.len())) {
                    let next_stripe_idx = stripe_idx + 1;
                    for disk_idx in 0..disks.len() {
                        let offset = stripe_idx * chunk_size;
                        let next_offset = next_stripe_idx * chunk_size + (disk_idx * chunk_size);

                        if next_offset + chunk_size <= disks[disk_idx].data.len() {
                            let current_block = &disks[disk_idx].data[offset..offset + chunk_size];
                            let next_block =
                                &disks[disk_idx].data[next_offset..next_offset + chunk_size];

                            if self.has_continuation_pattern(current_block, next_block) {
                                score += 1.0;
                            }
                            checks += 1;
                        }
                    }
                }

                if checks > 0 {
                    let ratio = score / checks as f64;
                    debug!(
                        "RAID0 detection (chunk={}): ratio = {:.2}",
                        chunk_size, ratio
                    );

                    if ratio > 0.7 {
                        return Ok(Some(RaidInfo {
                            level: RaidLevel::Raid0,
                            disk_count: disks.len(),
                            stripe_size: chunk_size as u64 * disks.len() as u64,
                            chunk_size: chunk_size as u64,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    fn has_continuation_pattern(&self, _block1: &[u8], _block2: &[u8]) -> bool {
        let is_sequential_ascii = |data: &[u8]| -> bool {
            let printable = data.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count();
            printable > data.len() / 2
        };

        let has_structure = |data: &[u8]| -> bool {
            let mut non_zero = 0;
            for &b in data {
                if b != 0 {
                    non_zero += 1;
                }
            }
            non_zero > data.len() / 4 && non_zero < data.len()
        };

        is_sequential_ascii(_block2) || has_structure(_block2)
    }

    fn detect_raid5(&self, disks: &[RaidDisk]) -> Result<Option<RaidInfo>> {
        if disks.len() < 3 {
            return Ok(None);
        }

        let common_sizes = [4096u64, 8192, 16384, 32768, 65536, 131072];

        for chunk_size in &common_sizes {
            let chunk_size = *chunk_size as usize;

            if disks.iter().all(|d| d.data.len() >= chunk_size * 3) {
                let mut parity_valid = 0;
                let mut checks = 0;

                for stripe_idx in 0..std::cmp::min(4, disks[0].data.len() / (chunk_size * disks.len())) {
                    let parity_disk = stripe_idx % disks.len();

                    for byte_idx in 0..std::cmp::min(chunk_size, 256) {
                        let mut xor_sum: u8 = 0;
                        let mut valid = true;

                        for disk_idx in 0..disks.len() {
                            let offset = stripe_idx * chunk_size + byte_idx;
                            if offset < disks[disk_idx].data.len() {
                                xor_sum ^= disks[disk_idx].data[offset];
                            } else {
                                valid = false;
                                break;
                            }
                        }

                        if valid && xor_sum == 0 {
                            parity_valid += 1;
                        }
                        checks += 1;
                    }

                    let _ = parity_disk;
                }

                if checks > 0 {
                    let ratio = parity_valid as f64 / checks as f64;
                    debug!(
                        "RAID5 detection (chunk={}): parity ratio = {:.2}",
                        chunk_size, ratio
                    );

                    if ratio > 0.9 {
                        return Ok(Some(RaidInfo {
                            level: RaidLevel::Raid5,
                            disk_count: disks.len(),
                            stripe_size: chunk_size as u64 * (disks.len() - 1) as u64,
                            chunk_size: chunk_size as u64,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl Default for RaidDetector {
    fn default() -> Self {
        Self::new()
    }
}
