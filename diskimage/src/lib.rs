pub mod raw;
pub mod e01;
pub mod vmdk;
pub mod vhd;

use std::path::Path;
use bytesurgeon_core::Result;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    pub format: String,
    pub size_bytes: u64,
    pub sector_size: u32,
    pub total_sectors: u64,
    pub sha256: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub examiner: Option<String>,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub description: Option<String>,
}

pub trait DiskImage {
    fn open(path: &Path) -> Result<Self> where Self: Sized;
    fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> Result<usize>;
    fn total_sectors(&self) -> u64;
    fn sector_size(&self) -> u32;
    fn metadata(&self) -> ImageMetadata;
}
