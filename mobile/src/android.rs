use crate::MobileDevice;
use datadoctor_core::{Result, DeviceInfo, DeviceType};
use tracing::{info, debug};

pub struct AndroidDevice {
    serial: String,
    #[allow(dead_code)]
    connected: bool,
}

impl AndroidDevice {
    pub fn new(serial: &str) -> Self {
        Self {
            serial: serial.to_string(),
            connected: false,
        }
    }

    pub fn list_devices() -> Result<Vec<String>> {
        info!("Listing Android devices");
        
        let output = std::process::Command::new("adb")
            .args(["devices"])
            .output()?;

        let device_list = String::from_utf8_lossy(&output.stdout);
        let devices: Vec<String> = device_list
            .lines()
            .skip(1)
            .filter(|line| line.contains("device"))
            .map(|line| line.split_whitespace().next().unwrap_or("").to_string())
            .filter(|s| !s.is_empty())
            .collect();

        debug!("Found {} Android devices", devices.len());
        Ok(devices)
    }
}

impl MobileDevice for AndroidDevice {
    fn connect(&self) -> Result<()> {
        info!("Connecting to Android device: {}", self.serial);
        Ok(())
    }

    fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from Android device: {}", self.serial);
        Ok(())
    }

    fn list_files(&self, path: &str) -> Result<Vec<String>> {
        debug!("Listing files on Android device: {}", path);
        
        let output = std::process::Command::new("adb")
            .args(["-s", &self.serial, "shell", "ls", path])
            .output()?;

        let files = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();

        Ok(files)
    }

    fn pull_file(&self, remote_path: &str, local_path: &str) -> Result<()> {
        info!("Pulling file from Android: {} -> {}", remote_path, local_path);
        
        std::process::Command::new("adb")
            .args(["-s", &self.serial, "pull", remote_path, local_path])
            .output()?;

        Ok(())
    }

    fn get_device_info(&self) -> Result<DeviceInfo> {
        let mut device_info = DeviceInfo::new(&self.serial, &self.serial);
        device_info.device_type = DeviceType::Mobile;
        Ok(device_info)
    }
}
