pub mod malware;
pub mod compliance;
pub mod audit;

use bytesurgeon_core::{Result, ThreatStatus};
use std::path::Path;

pub trait SecurityScanner {
    fn scan_file(&self, path: &Path) -> Result<ThreatStatus>;
    fn scan_directory(&self, path: &Path) -> Result<Vec<(String, ThreatStatus)>>;
}
