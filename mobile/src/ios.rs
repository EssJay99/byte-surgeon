use crate::MobileDevice;
use datadoctor_core::{Result, DeviceInfo, DeviceType};
use tracing::{info, debug};

pub struct IOSDevice {
    udid: String,
    #[allow(dead_code)]
    connected: bool,
}

impl IOSDevice {
    pub fn new(udid: &str) -> Self {
        Self {
            udid: udid.to_string(),
            connected: false,
        }
    }

    pub fn list_devices() -> Result<Vec<String>> {
        info!("Listing iOS devices");
        
        let output = std::process::Command::new("idevice_id")
            .arg("-l")
            .output()?;

        let device_list = String::from_utf8_lossy(&output.stdout);
        let devices: Vec<String> = device_list
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        debug!("Found {} iOS devices", devices.len());
        Ok(devices)
    }
}

impl MobileDevice for IOSDevice {
    fn connect(&self) -> Result<()> {
        info!("Connecting to iOS device: {}", self.udid);
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from iOS device: {}", self.udid);
        Ok(())
    }

    fn list_files(&self, path: &str) -> Result<Vec<String>> {
        debug!("Listing files on iOS device: {}", path);
        Ok(Vec::new())
    }

    fn pull_file(&self, remote_path: &str, local_path: &str) -> Result<()> {
        info!("Pulling file from iOS: {} -> {}", remote_path, local_path);
        Ok(())
    }

    fn get_device_info(&self) -> Result<DeviceInfo> {
        let mut device_info = DeviceInfo::new(&self.udid, &self.udid);
        device_info.device_type = DeviceType::Mobile;
        Ok(device_info)
    }
}
