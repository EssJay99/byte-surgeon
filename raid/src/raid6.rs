use anyhow::Result;
use tracing::{debug, info};

use crate::common::{RaidDisk, RaidLevel, RaidReconstructor, StripeRotation};

pub struct Raid6 {
    disks: Vec<RaidDisk>,
    chunk_size: u64,
    rotation: StripeRotation,
    healthy: bool,
}

impl RaidReconstructor for Raid6 {
    fn new(disks: Vec<RaidDisk>) -> Result<Self> {
        if disks.len() < 4 {
            anyhow::bail!("RAID6 requires at least 4 disks");
        }

        let chunk_size = Self::detect_chunk_size(&disks)?;

        info!(
            "RAID6 initialized with {} disks, chunk size: {} bytes",
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
        info!("Starting RAID6 reconstruction");

        let degraded = self.degraded_disks();
        if degraded.len() > 2 {
            anyhow::bail!(
                "RAID6 can only handle 2 failed disks, found {} failed",
                degraded.len()
            );
        }

        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let min_disk_size = self.disks.iter().map(|d| d.data.len()).min().unwrap_or(0);
        let chunks_per_disk = min_disk_size / chunk_size;

        let data_disks = disk_count - 2;
        let total_data_size = chunks_per_disk * chunk_size * data_disks;
        let mut result = Vec::with_capacity(total_data_size);

        for stripe_idx in 0..chunks_per_disk {
            let (p_disk, q_disk) = match self.rotation {
                StripeRotation::LeftSymmetric | StripeRotation::LeftAsymmetric => {
                    let p = (disk_count - 1 - (stripe_idx % disk_count)) % disk_count;
                    let q = (disk_count - 2 - (stripe_idx % disk_count)) % disk_count;
                    (p, q)
                }
                StripeRotation::RightSymmetric | StripeRotation::RightAsymmetric => {
                    let p = stripe_idx % disk_count;
                    let q = (stripe_idx + 1) % disk_count;
                    (p, q)
                }
            };

            for chunk_idx in 0..disk_count {
                if chunk_idx == p_disk || chunk_idx == q_disk {
                    continue;
                }

                let disk_idx = (p_disk + 1 + chunk_idx) % disk_count;
                let offset = stripe_idx * chunk_size;

                if self.disks[disk_idx].data.is_empty() || offset >= self.disks[disk_idx].data.len() {
                    let reconstructed = self.reconstruct_chunk(stripe_idx, disk_idx, p_disk, q_disk)?;
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

        info!("RAID6 reconstruction complete: {} bytes", result.len());
        Ok(result)
    }

    fn raid_level(&self) -> RaidLevel {
        RaidLevel::Raid6
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

impl Raid6 {
    fn detect_chunk_size(disks: &[RaidDisk]) -> Result<u64> {
        let common_sizes = [4096u64, 8192, 16384, 32768, 65536, 131072];

        for chunk_size in &common_sizes {
            if disks.iter().all(|d| d.data.len() as u64 >= *chunk_size * 2) {
                let mut dual_parity_valid = 0;
                let mut checks = 0;

                for stripe_idx in 0..std::cmp::min(2, disks[0].data.len() / (*chunk_size as usize * disks.len())) {
                    for byte_idx in 0..std::cmp::min(*chunk_size as usize, 128) {
                        let mut p_sum: u8 = 0;
                        let _q_sum: u8 = 0;

                        let mut valid = true;
                        for disk in disks {
                            let offset = stripe_idx * *chunk_size as usize + byte_idx;
                            if offset < disk.data.len() {
                                let byte = disk.data[offset];
                                p_sum ^= byte;
                            } else {
                                valid = false;
                                break;
                            }
                        }

                        if valid && p_sum == 0 {
                            dual_parity_valid += 1;
                        }
                        checks += 1;
                    }
                }

                if checks > 0 && dual_parity_valid as f64 / checks as f64 > 0.9 {
                    debug!("Detected RAID6 chunk size: {} bytes", chunk_size);
                    return Ok(*chunk_size);
                }
            }
        }

        Ok(65536)
    }

    fn calculate_p_syndrome(data_chunks: &[&[u8]]) -> Vec<u8> {
        if data_chunks.is_empty() {
            return Vec::new();
        }

        let chunk_size = data_chunks[0].len();
        let mut p = vec![0u8; chunk_size];

        for chunk in data_chunks {
            for (i, &byte) in chunk.iter().enumerate() {
                if i < p.len() {
                    p[i] ^= byte;
                }
            }
        }

        p
    }

    fn calculate_q_syndrome(data_chunks: &[&[u8]]) -> Vec<u8> {
        if data_chunks.is_empty() {
            return Vec::new();
        }

        let chunk_size = data_chunks[0].len();
        let mut q = vec![0u8; chunk_size];

        for (idx, chunk) in data_chunks.iter().enumerate() {
            let coefficient = GaloisField::pow(2, idx);
            for (i, &byte) in chunk.iter().enumerate() {
                if i < q.len() {
                    q[i] ^= GaloisField::mul(coefficient, byte);
                }
            }
        }

        q
    }

    pub fn reconstruct_from_dual_parity(
        &self,
        stripe_idx: usize,
        failed_disk1: usize,
        failed_disk2: usize,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let offset = stripe_idx * chunk_size;

        let mut data_chunks: Vec<(usize, &[u8])> = Vec::new();

        for disk_idx in 0..disk_count {
            if disk_idx == failed_disk1 || disk_idx == failed_disk2 {
                continue;
            }

            let end = std::cmp::min(offset + chunk_size, self.disks[disk_idx].data.len());
            if offset < end {
                data_chunks.push((disk_idx, &self.disks[disk_idx].data[offset..end]));
            } else {
                data_chunks.push((disk_idx, &[]));
            }
        }

        let chunk_refs: Vec<&[u8]> = data_chunks.iter().map(|(_, chunk)| *chunk).collect();

        let p_syndrome = Self::calculate_p_syndrome(&chunk_refs);
        let q_syndrome = Self::calculate_q_syndrome(&chunk_refs);

        let reconstructed1 = Self::solve_dual_equation(
            &p_syndrome,
            &q_syndrome,
            failed_disk1,
            data_chunks.len(),
        )?;
        let reconstructed2 = Self::solve_dual_equation(
            &p_syndrome,
            &q_syndrome,
            failed_disk2,
            data_chunks.len(),
        )?;

        Ok((reconstructed1, reconstructed2))
    }

    fn solve_dual_equation(
        p_syndrome: &[u8],
        q_syndrome: &[u8],
        failed_disk_index: usize,
        _total_disks: usize,
    ) -> Result<Vec<u8>> {
        let chunk_size = p_syndrome.len();
        let mut reconstructed = vec![0u8; chunk_size];

        for i in 0..chunk_size {
            let p = p_syndrome[i];
            let q = q_syndrome[i];

            let coefficient = GaloisField::pow(2, failed_disk_index);
            let inv_coeff = GaloisField::inv(coefficient);

            if inv_coeff != 0 {
                reconstructed[i] = GaloisField::mul(inv_coeff, q ^ p);
            } else {
                reconstructed[i] = p;
            }
        }

        Ok(reconstructed)
    }

    fn reconstruct_chunk(
        &self,
        stripe_idx: usize,
        failed_disk: usize,
        p_disk: usize,
        _q_disk: usize,
    ) -> Result<Vec<u8>> {
        let (reconstructed1, _reconstructed2) =
            self.reconstruct_from_dual_parity(stripe_idx, failed_disk, p_disk)?;
        Ok(reconstructed1)
    }

    pub fn with_rotation(mut self, rotation: StripeRotation) -> Self {
        self.rotation = rotation;
        self
    }

    pub fn verify_dual_parity(&self) -> Result<bool> {
        let chunk_size = self.chunk_size as usize;
        let disk_count = self.disks.len();
        let min_disk_size = self.disks.iter().map(|d| d.data.len()).min().unwrap_or(0);
        let chunks_per_disk = min_disk_size / chunk_size;

        for stripe_idx in 0..std::cmp::min(chunks_per_disk, 8) {
            let (_p_disk, q_disk) = match self.rotation {
                StripeRotation::LeftSymmetric | StripeRotation::LeftAsymmetric => {
                    let p = (disk_count - 1 - (stripe_idx % disk_count)) % disk_count;
                    let q = (disk_count - 2 - (stripe_idx % disk_count)) % disk_count;
                    (p, q)
                }
                StripeRotation::RightSymmetric | StripeRotation::RightAsymmetric => {
                    let p = stripe_idx % disk_count;
                    let q = (stripe_idx + 1) % disk_count;
                    (p, q)
                }
            };

            for byte_idx in 0..std::cmp::min(chunk_size, 128) {
                let mut p_sum: u8 = 0;

                for disk_idx in 0..disk_count {
                    if disk_idx == q_disk {
                        continue;
                    }

                    let offset = stripe_idx * chunk_size + byte_idx;
                    if offset < self.disks[disk_idx].data.len() {
                        p_sum ^= self.disks[disk_idx].data[offset];
                    }
                }

                if p_sum != 0 {
                    debug!(
                        "P parity mismatch at stripe {}, byte {}",
                        stripe_idx, byte_idx
                    );
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}

struct GaloisField;

impl GaloisField {
    #[allow(dead_code)]
    fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }

        let mut result = 0u8;
        let mut a = a as u16;
        let mut b = b as u16;

        for _ in 0..8 {
            if b & 1 != 0 {
                result ^= a as u8;
            }

            let high_bit = a & 0x80;
            a <<= 1;

            if high_bit != 0 {
                a ^= 0x1D;
            }

            b >>= 1;
        }

        result
    }

    fn pow(base: u8, exp: usize) -> u8 {
        if exp == 0 {
            return 1;
        }

        let mut result = base;
        for _ in 1..exp {
            result = Self::mul(result, base);
        }
        result
    }

    fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }

        let mut result = a;
        for _ in 0..6 {
            result = Self::mul(result, result);
        }
        result
    }
}
