use bytesurgeon_core::{Result, DeviceInfo, DeviceType};
use tracing::info;

pub struct DeviceDetector;

impl DeviceDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect_all_devices(&self) -> Result<Vec<DeviceInfo>> {
        info!("Detecting all connected devices");
        
        let mut devices = Vec::new();

        #[cfg(target_os = "linux")]
        {
            devices.extend(self.detect_linux_devices()?);
        }

        #[cfg(target_os = "macos")]
        {
            devices.extend(self.detect_macos_devices()?);
        }

        #[cfg(target_os = "windows")]
        {
            devices.extend(self.detect_windows_devices()?);
        }

        info!("Detected {} devices", devices.len());
        Ok(devices)
    }

    #[cfg(target_os = "linux")]
    fn detect_linux_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let path = entry.path();
                let device_name = path.file_name().unwrap().to_string_lossy().to_string();
                
                if device_name.starts_with("loop") || device_name.starts_with("ram") || device_name.starts_with("dm-") {
                    continue;
                }

                let device_path = format!("/dev/{}", device_name);
                let mut device_info = DeviceInfo::new(&device_path, &device_name);

                if let Ok(size_str) = std::fs::read_to_string(path.join("size")) {
                    if let Ok(sectors) = size_str.trim().parse::<u64>() {
                        device_info.total_size = sectors * 512;
                    }
                }

                device_info.device_type = self.classify_linux_device(&device_name);
                
                if let Ok(vendor) = std::fs::read_to_string(path.join("device/vendor")) {
                    device_info.vendor = Some(vendor.trim().to_string());
                }

                if let Ok(model) = std::fs::read_to_string(path.join("device/model")) {
                    device_info.model = Some(model.trim().to_string());
                }

                devices.push(device_info);
            }
        }

        Ok(devices)
    }

    #[cfg(target_os = "linux")]
    fn classify_linux_device(&self, device_name: &str) -> DeviceType {
        if device_name.starts_with("sd") {
            DeviceType::HardDrive
        } else if device_name.starts_with("nvme") {
            DeviceType::SSD
        } else if device_name.starts_with("sr") {
            DeviceType::Optical
        } else {
            DeviceType::Unknown
        }
    }

    #[cfg(target_os = "macos")]
    fn detect_macos_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                
                if name.starts_with("disk") && !name.contains("s") {
                    let device_path = path.to_string_lossy().to_string();
                    let mut device_info = DeviceInfo::new(&device_path, &name);

                    if let Ok(metadata) = std::fs::metadata(&device_path) {
                        device_info.total_size = metadata.len();
                    }

                    device_info.device_type = DeviceType::HardDrive;
                    devices.push(device_info);
                }
            }
        }

        Ok(devices)
    }

    #[cfg(target_os = "windows")]
    fn detect_windows_devices(&self) -> Result<Vec<DeviceInfo>> {
        let mut devices = Vec::new();

        for i in 0..26 {
            let drive_letter = (b'A' + i) as char;
            let drive_path = format!("{}:\\", drive_letter);
            
            if std::path::Path::new(&drive_path).exists() {
                let device_path = format!("\\\\.\\{}:", drive_letter);
                let mut device_info = DeviceInfo::new(&device_path, &format!("{}:", drive_letter));

                if let Ok(metadata) = std::fs::metadata(&drive_path) {
                    device_info.total_size = metadata.len();
                }

                device_info.device_type = DeviceType::HardDrive;
                device_info.mount_point = Some(drive_path);
                devices.push(device_info);
            }
        }

        Ok(devices)
    }

    pub fn is_device_accessible(&self, device_path: &str) -> Result<bool> {
        std::fs::metadata(device_path)?;
        Ok(true)
    }
}

impl Default for DeviceDetector {
    fn default() -> Self {
        Self::new()
    }
}
