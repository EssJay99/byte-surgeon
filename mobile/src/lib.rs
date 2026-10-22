pub mod android;
pub mod ios;

use bytesurgeon_core::{Result, DeviceInfo};

pub trait MobileDevice {
    fn connect(&self) -> Result<()>;
    fn disconnect(&self) -> Result<()>;
    fn list_files(&self, path: &str) -> Result<Vec<String>>;
    fn pull_file(&self, remote_path: &str, local_path: &str) -> Result<()>;
    fn get_device_info(&self) -> Result<DeviceInfo>;
}
