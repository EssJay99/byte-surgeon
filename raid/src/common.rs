use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait RaidReconstructor {
    fn new(disks: Vec<RaidDisk>) -> Result<Self>
    where
        Self: Sized;
    fn reconstruct(&mut self) -> Result<Vec<u8>>;
    fn raid_level(&self) -> RaidLevel;
    fn is_healthy(&self) -> bool;
    fn degraded_disks(&self) -> Vec<usize>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaidDisk {
    pub path: String,
    pub size: u64,
    pub position: usize,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaidLevel {
    Raid0,
    Raid1,
    Raid5,
    Raid6,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaidInfo {
    pub level: RaidLevel,
    pub disk_count: usize,
    pub stripe_size: u64,
    pub chunk_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StripeRotation {
    LeftSymmetric,
    LeftAsymmetric,
    RightSymmetric,
    RightAsymmetric,
}

impl Default for StripeRotation {
    fn default() -> Self {
        Self::LeftSymmetric
    }
}
