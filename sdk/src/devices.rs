use crate::error::{SdkError, SdkResult, DeviceSummary};
use bytesurgeon_core::{DeviceInfo, DeviceType, FileSystemType};
use bytesurgeon_devices::DeviceDetector;

pub struct DeviceScanner {
    detector: DeviceDetector,
    filter_type: Option<DeviceType>,
    filter_fs: Option<FileSystemType>,
    min_size: Option<u64>,
    max_size: Option<u64>,
}

impl DeviceScanner {
    pub fn new() -> Self {
        Self {
            detector: DeviceDetector::new(),
            filter_type: None,
            filter_fs: None,
            min_size: None,
            max_size: None,
        }
    }

    pub fn filter_by_type(mut self, device_type: DeviceType) -> Self {
        self.filter_type = Some(device_type);
        self
    }

    pub fn filter_by_filesystem(mut self, fs_type: FileSystemType) -> Self {
        self.filter_fs = Some(fs_type);
        self
    }

    pub fn min_size(mut self, bytes: u64) -> Self {
        self.min_size = Some(bytes);
        self
    }

    pub fn max_size(mut self, bytes: u64) -> Self {
        self.max_size = Some(bytes);
        self
    }

    pub fn usb_only(self) -> Self {
        self.filter_by_type(DeviceType::USB)
    }

    pub fn hard_drives_only(self) -> Self {
        self.filter_by_type(DeviceType::HardDrive)
    }

    pub fn ssd_only(self) -> Self {
        self.filter_by_type(DeviceType::SSD)
    }

    pub fn scan(self) -> SdkResult<Vec<DeviceSummary>> {
        let all_devices = self.detector.detect_all_devices()
            .map_err(|e| SdkError::Device(format!("Device detection failed: {}", e)))?;

        let filtered: Vec<DeviceSummary> = all_devices
            .into_iter()
            .filter(|d| self.matches_filters(d))
            .map(DeviceSummary::from)
            .collect();

        Ok(filtered)
    }

    pub fn scan_raw(self) -> SdkResult<Vec<DeviceInfo>> {
        let all_devices = self.detector.detect_all_devices()
            .map_err(|e| SdkError::Device(format!("Device detection failed: {}", e)))?;

        let filtered: Vec<DeviceInfo> = all_devices
            .into_iter()
            .filter(|d| self.matches_filters(d))
            .collect();

        Ok(filtered)
    }

    fn matches_filters(&self, device: &DeviceInfo) -> bool {
        if let Some(ref dt) = self.filter_type {
            if device.device_type != *dt {
                return false;
            }
        }

        if let Some(ref fs) = self.filter_fs {
            if device.file_system != *fs {
                return false;
            }
        }

        if let Some(min) = self.min_size {
            if device.total_size < min {
                return false;
            }
        }

        if let Some(max) = self.max_size {
            if device.total_size > max {
                return false;
            }
        }

        true
    }
}

impl Default for DeviceScanner {
    fn default() -> Self {
        Self::new()
    }
}
