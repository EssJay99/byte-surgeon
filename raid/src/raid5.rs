use anyhow::Result;
use tracing::{debug, info};

use crate::common::{RaidDisk, RaidLevel, RaidReconstructor, StripeRotation};

pub struct Raid5 {
    disks: Vec<RaidDisk>,
    chunk_size: u64,
    rotation: StripeRotation,
    healthy: bool,
}

impl RaidReconstructor for Raid5 {
    fn new(disks: Vec<RaidDisk>) -> Result<Self> {
        if disks.len() < 3 {
            anyhow::bail!("RAID5 requires at least 3 disks");
        }

        let chunk_size = Self::detect_chunk_size(&disks)?;

        info!(
            "RAID5 initialized with {} disks, chunk size: {} bytes",
            disks.len(),
            chunk_size
        );

        Ok(Self {
            disks,
            chunk_size,
            rotation: StripeRotation::LeftSymmetric,
            healthy: true,
        })
    }

    fn reconstruct(&mut self) -> Result<Vec<u8>> {
        info!("Starting RAID5 reconstruction");

        let degraded = self.degraded_disks();
        if degraded.len() > 1 {
            anyhow::bail!("RAID5 can only handle 1 failed disk, found {} failed", degraded.len());
        }

        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let min_disk_size = self.disks.iter().map(|d| d.data.len()).min().unwrap_or(0);
        let chunks_per_disk = min_disk_size / chunk_size;

        let data_disks = disk_count - 1;
        let total_data_size = chunks_per_disk * chunk_size * data_disks;
        let mut result = Vec::with_capacity(total_data_size);

        for stripe_idx in 0..chunks_per_disk {
            let parity_disk = match self.rotation {
                StripeRotation::LeftSymmetric => (disk_count - 1 - (stripe_idx % disk_count)) % disk_count,
                StripeRotation::LeftAsymmetric => (disk_count - 1 - (stripe_idx % disk_count)) % disk_count,
                StripeRotation::RightSymmetric => stripe_idx % disk_count,
                StripeRotation::RightAsymmetric => stripe_idx % disk_count,
            };

            for chunk_idx in 0..disk_count {
                if chunk_idx == parity_disk {
                    continue;
                }

                let disk_idx = match self.rotation {
                    StripeRotation::LeftSymmetric | StripeRotation::LeftAsymmetric => {
                        (parity_disk + 1 + chunk_idx) % disk_count
                    }
                    StripeRotation::RightSymmetric | StripeRotation::RightAsymmetric => {
                        (parity_disk + 1 + chunk_idx) % disk_count
                    }
                };

                let offset = stripe_idx * chunk_size;

                if self.disks[disk_idx].data.is_empty() || offset >= self.disks[disk_idx].data.len() {
                    let reconstructed = self.reconstruct_chunk(stripe_idx, disk_idx)?;
                    result.extend_from_slice(&reconstructed);
                } else {
                    let end = std::cmp::min(offset + chunk_size, self.disks[disk_idx].data.len());
                    result.extend_from_slice(&self.disks[disk_idx].data[offset..end]);

                    if end - offset < chunk_size {
                        let padding = chunk_size - (end - offset);
                        result.extend(vec![0u8; padding]);
                    }
                }
            }
        }

        info!("RAID5 reconstruction complete: {} bytes", result.len());
        Ok(result)
    }

    fn raid_level(&self) -> RaidLevel {
        RaidLevel::Raid5
    }

    fn is_healthy(&self) -> bool {
        self.healthy && self.degraded_disks().is_empty()
    }

    fn degraded_disks(&self) -> Vec<usize> {
        self.disks
            .iter()
            .enumerate()
            .filter(|(_, disk)| disk.data.is_empty())
            .map(|(idx, _)| idx)
            .collect()
    }
}

impl Raid5 {
    fn detect_chunk_size(disks: &[RaidDisk]) -> Result<u64> {
        let common_sizes = [4096u64, 8192, 16384, 32768, 65536, 131072];

        for chunk_size in &common_sizes {
            if disks.iter().all(|d| d.data.len() as u64 >= *chunk_size * 2) {
                let mut parity_valid = 0;
                let mut checks = 0;

                for stripe_idx in 0..std::cmp::min(4, disks[0].data.len() / (*chunk_size as usize * disks.len())) {
                    for byte_idx in 0..std::cmp::min(*chunk_size as usize, 256) {
                        let mut xor_sum: u8 = 0;
                        let mut valid = true;

                        for disk in disks {
                            let offset = stripe_idx * *chunk_size as usize + byte_idx;
                            if offset < disk.data.len() {
                                xor_sum ^= disk.data[offset];
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
                }

                if checks > 0 && parity_valid as f64 / checks as f64 > 0.9 {
                    debug!("Detected RAID5 chunk size: {} bytes", chunk_size);
                    return Ok(*chunk_size);
                }
            }
        }

        Ok(65536)
    }

    fn calculate_parity(data_chunks: &[&[u8]]) -> Vec<u8> {
        if data_chunks.is_empty() {
            return Vec::new();
        }

        let chunk_size = data_chunks[0].len();
        let mut parity = vec![0u8; chunk_size];

        for chunk in data_chunks {
            for (i, &byte) in chunk.iter().enumerate() {
                if i < parity.len() {
                    parity[i] ^= byte;
                }
            }
        }

        parity
    }

    pub fn reconstruct_from_parity(&self, stripe_idx: usize, failed_disk: usize) -> Result<Vec<u8>> {
        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let offset = stripe_idx * chunk_size;

        let mut data_chunks: Vec<&[u8]> = Vec::new();

        for disk_idx in 0..disk_count {
            if disk_idx == failed_disk {
                continue;
            }

            let end = std::cmp::min(offset + chunk_size, self.disks[disk_idx].data.len());
            if offset < end {
                data_chunks.push(&self.disks[disk_idx].data[offset..end]);
            } else {
                data_chunks.push(&[]);
            }
        }

        let reconstructed = Self::calculate_parity(&data_chunks);
        Ok(reconstructed)
    }

    fn reconstruct_chunk(&self, stripe_idx: usize, failed_disk: usize) -> Result<Vec<u8>> {
        self.reconstruct_from_parity(stripe_idx, failed_disk)
    }

    pub fn with_rotation(mut self, rotation: StripeRotation) -> Self {
        self.rotation = rotation;
        self
    }

    pub fn verify_parity(&self) -> Result<bool> {
        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let min_disk_size = self.disks.iter().map(|d| d.data.len()).min().unwrap_or(0);
        let chunks_per_disk = min_disk_size / chunk_size;

        for stripe_idx in 0..std::cmp::min(chunks_per_disk, 16) {
            let _parity_disk = match self.rotation {
                StripeRotation::LeftSymmetric => (disk_count - 1 - (stripe_idx % disk_count)) % disk_count,
                StripeRotation::LeftAsymmetric => (disk_count - 1 - (stripe_idx % disk_count)) % disk_count,
                StripeRotation::RightSymmetric => stripe_idx % disk_count,
                StripeRotation::RightAsymmetric => stripe_idx % disk_count,
            };

            for byte_idx in 0..std::cmp::min(chunk_size, 256) {
                let mut xor_sum: u8 = 0;

                for disk_idx in 0..disk_count {
                    let offset = stripe_idx * chunk_size + byte_idx;
                    if offset < self.disks[disk_idx].data.len() {
                        xor_sum ^= self.disks[disk_idx].data[offset];
                    }
                }

                if xor_sum != 0 {
                    debug!("Parity mismatch at stripe {}, byte {}", stripe_idx, byte_idx);
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}
