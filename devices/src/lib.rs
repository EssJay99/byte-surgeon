pub mod detector;
pub mod usb;
pub mod network;

pub use detector::DeviceDetector;

use datadoctor_core::{Result, DeviceInfo};

pub trait Device {
    fn info(&self) -> &DeviceInfo;
    fn is_accessible(&self) -> Result<bool>;
    fn get_capacity(&self) -> Result<u64>;
    fn read_sector(&self, sector: u64, buffer: &mut [u8]) -> Result<usize>;
}
