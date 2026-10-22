use crate::{Result, Error};
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteProtectionStatus {
    pub device_path: String,
    pub is_write_protected: bool,
    pub method_used: String,
    pub details: String,
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event: String,
    pub device_path: String,
    pub result: String,
    pub details: String,
}

pub struct WriteProtector {
    audit_log: Vec<AuditEntry>,
    strict_mode: bool,
}

impl WriteProtector {
    pub fn new() -> Self {
        Self {
            audit_log: Vec::new(),
            strict_mode: true,
        }
    }

    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    pub fn verify_device(&mut self, device_path: &str) -> Result<WriteProtectionStatus> {
        info!("Verifying write protection for device: {}", device_path);

        let status = self.check_platform(device_path)?;

        if status.is_write_protected {
            self.log_audit("WRITE_PROTECT_VERIFIED", device_path, "PASS", &status.details);
            info!("Device {} is write-protected (method: {})", device_path, status.method_used);
        } else {
            self.log_audit("WRITE_PROTECT_FAILED", device_path, "FAIL", &status.details);
            warn!("Device {} is NOT write-protected", device_path);
        }

        Ok(status)
    }

    pub fn assert_write_protected(&mut self, device_path: &str) -> Result<()> {
        let status = self.verify_device(device_path)?;

        if !status.is_write_protected {
            if self.strict_mode {
                return Err(Error::SecurityViolation(format!(
                    "Device {} is not write-protected. Aborting for safety.",
                    device_path
                )));
            } else {
                warn!(
                    "Device {} is not write-protected, but strict mode is disabled. Proceeding with caution.",
                    device_path
                );
            }
        }

        Ok(())
    }

    pub fn block_write_operation(&mut self, device_path: &str) -> Result<()> {
        let status = self.verify_device(device_path)?;

        if !status.is_write_protected {
            self.log_audit("WRITE_BLOCKED", device_path, "BLOCKED", "Write operation blocked: device not write-protected");
            return Err(Error::SecurityViolation(format!(
                "Write operation blocked: device {} is not write-protected",
                device_path
            )));
        }

        self.log_audit("WRITE_ALLOWED", device_path, "ALLOWED", "Device is write-protected, write operation logged");
        Err(Error::PermissionDenied(format!(
            "Write operations are not allowed on device {} regardless of write protection status",
            device_path
        )))
    }

    pub fn get_audit_log(&self) -> &[AuditEntry] {
        &self.audit_log
    }

    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    pub fn check_mount_flags(device_path: &str) -> Result<bool> {
        let path = Path::new(device_path);

        if let Some(_parent) = path.parent() {
            let mount_output = Self::read_mounts()?;

            for line in mount_output.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let mount_point = parts[1];
                    let flags = parts[3];
                    if device_path.starts_with(mount_point) || mount_point == device_path {
                        if flags.contains("ro") {
                            debug!("Found read-only mount for {}: {}", device_path, line);
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    fn check_platform(&self, device_path: &str) -> Result<WriteProtectionStatus> {
        #[cfg(target_os = "linux")]
        {
            return self.check_linux(device_path);
        }

        #[cfg(target_os = "macos")]
        {
            return self.check_macos(device_path);
        }

        #[cfg(target_os = "windows")]
        {
            return self.check_windows(device_path);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            self.check_fallback(device_path)
        }
    }

    #[cfg(target_os = "linux")]
    fn check_linux(&self, device_path: &str) -> Result<WriteProtectionStatus> {
        let device_name = Self::extract_device_name(device_path);

        if let Ok(content) = std::fs::read_to_string(format!("/sys/block/{}/ro", device_name)) {
            let ro = content.trim() == "1";
            let details = format!("/sys/block/{}/ro = {}", device_name, content.trim());
            return Ok(WriteProtectionStatus {
                device_path: device_path.to_string(),
                is_write_protected: ro,
                method_used: "linux_sysfs".to_string(),
                details,
                verified_at: chrono::Utc::now(),
            });
        }

        let mount_ro = Self::check_mount_flags(device_path)?;
        Ok(WriteProtectionStatus {
            device_path: device_path.to_string(),
            is_write_protected: mount_ro,
            method_used: "linux_mount_flags".to_string(),
            details: format!("Mount flags check: read-only={}", mount_ro),
            verified_at: chrono::Utc::now(),
        })
    }

    #[cfg(target_os = "macos")]
    fn check_macos(&self, device_path: &str) -> Result<WriteProtectionStatus> {
        let device_name = Self::extract_device_name(device_path);

        let output = std::process::Command::new("diskutil")
            .args(["info", &device_name])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let is_ro = stdout.contains("Read-Only Media:          Yes")
                    || stdout.contains("Read-only Media:           Yes")
                    || stdout.contains("Read-Only:                 Yes")
                    || stdout.contains("Volume Read Only:          Yes");

                Ok(WriteProtectionStatus {
                    device_path: device_path.to_string(),
                    is_write_protected: is_ro,
                    method_used: "macos_diskutil".to_string(),
                    details: format!("diskutil info for {}: read-only={}", device_name, is_ro),
                    verified_at: chrono::Utc::now(),
                })
            }
            Err(e) => {
                let mount_ro = Self::check_mount_flags(device_path)?;
                Ok(WriteProtectionStatus {
                    device_path: device_path.to_string(),
                    is_write_protected: mount_ro,
                    method_used: "macos_mount_flags".to_string(),
                    details: format!("diskutil failed ({}), mount flags check: ro={}", e, mount_ro),
                    verified_at: chrono::Utc::now(),
                })
            }
        }
    }

    #[cfg(target_os = "windows")]
    fn check_windows(&self, device_path: &str) -> Result<WriteProtectionStatus> {
        let output = std::process::Command::new("diskpart")
            .args(&["/s", "NUL"])
            .output();

        let _ = output;

        let drive_letter = device_path.chars().next().unwrap_or('C');
        let ro_key = format!(
            "SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies"
        );

        let _ = ro_key;
        let _ = drive_letter;

        Ok(WriteProtectionStatus {
            device_path: device_path.to_string(),
            is_write_protected: false,
            method_used: "windows_placeholder".to_string(),
            details: "Windows write protection check requires elevated privileges".to_string(),
            verified_at: chrono::Utc::now(),
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    fn check_fallback(&self, device_path: &str) -> Result<WriteProtectionStatus> {
        let mount_ro = Self::check_mount_flags(device_path)?;
        Ok(WriteProtectionStatus {
            device_path: device_path.to_string(),
            is_write_protected: mount_ro,
            method_used: "fallback_mount_flags".to_string(),
            details: format!("Fallback method: mount flags check ro={}", mount_ro),
            verified_at: chrono::Utc::now(),
        })
    }

    fn extract_device_name(device_path: &str) -> String {
        let path = Path::new(device_path);
        path.file_name()
            .map(|n| {
                let name = n.to_string_lossy().to_string();
                if name.starts_with("rdisk") {
                    name.replacen("rdisk", "disk", 1)
                } else {
                    name
                }
            })
            .unwrap_or_else(|| device_path.to_string())
    }

    fn read_mounts() -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/mounts") {
                Ok(content) => Ok(content),
                Err(_) => {
                    match std::fs::read_to_string("/etc/mtab") {
                        Ok(content) => Ok(content),
                        Err(e) => Err(Error::Io(e)),
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let output = std::process::Command::new("mount")
                .output()
                .map_err(|e| Error::Io(e))?;
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
    }

    fn log_audit(&mut self, event: &str, device: &str, result: &str, details: &str) {
        self.audit_log.push(AuditEntry {
            timestamp: chrono::Utc::now(),
            event: event.to_string(),
            device_path: device.to_string(),
            result: result.to_string(),
            details: details.to_string(),
        });
    }
}

impl Default for WriteProtector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_protector_creation() {
        let wp = WriteProtector::new();
        assert!(wp.strict_mode);
        assert!(wp.audit_log.is_empty());
    }

    #[test]
    fn test_with_strict_mode() {
        let wp = WriteProtector::new().with_strict_mode(false);
        assert!(!wp.strict_mode);
    }

    #[test]
    fn test_default() {
        let wp = WriteProtector::default();
        assert!(wp.strict_mode);
    }

    #[test]
    fn test_extract_device_name() {
        assert_eq!(WriteProtector::extract_device_name("/dev/sda"), "sda");
        assert_eq!(WriteProtector::extract_device_name("/dev/disk2"), "disk2");
        assert_eq!(WriteProtector::extract_device_name("/dev/rdisk2"), "disk2");
    }

    #[test]
    fn test_verify_nonexistent_device() {
        let mut wp = WriteProtector::new().with_strict_mode(false);
        let result = wp.verify_device("/dev/nonexistent_device_12345");
        #[cfg(target_os = "macos")]
        {
            assert!(result.is_ok());
            let status = result.unwrap();
            assert!(!status.is_write_protected);
        }
        #[cfg(target_os = "linux")]
        {
            assert!(result.is_ok());
            let status = result.unwrap();
            assert!(!status.is_write_protected);
        }
    }

    #[test]
    fn test_assert_write_protected_non_strict() {
        let mut wp = WriteProtector::new().with_strict_mode(false);
        let result = wp.assert_write_protected("/dev/nonexistent_device_12345");
        assert!(result.is_ok());
    }

    #[test]
    fn test_assert_write_protected_strict() {
        let mut wp = WriteProtector::new().with_strict_mode(true);
        let result = wp.assert_write_protected("/dev/nonexistent_device_12345");
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_audit_log_populated() {
        let mut wp = WriteProtector::new().with_strict_mode(false);
        let _ = wp.verify_device("/dev/test_device_12345");
        assert!(!wp.audit_log.is_empty());
        let entry = &wp.audit_log[0];
        assert!(entry.event == "WRITE_PROTECT_VERIFIED" || entry.event == "WRITE_PROTECT_FAILED");
    }

    #[test]
    fn test_clear_audit_log() {
        let mut wp = WriteProtector::new().with_strict_mode(false);
        let _ = wp.verify_device("/dev/test_device_12345");
        assert!(!wp.audit_log.is_empty());
        wp.clear_audit_log();
        assert!(wp.audit_log.is_empty());
    }

    #[test]
    fn test_block_write_operation() {
        let mut wp = WriteProtector::new();
        let result = wp.block_write_operation("/dev/sda");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_mount_flags_nonexistent() {
        let result = WriteProtector::check_mount_flags("/nonexistent/path");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_write_protection_status_fields() {
        let status = WriteProtectionStatus {
            device_path: "/dev/sda".to_string(),
            is_write_protected: true,
            method_used: "test".to_string(),
            details: "test details".to_string(),
            verified_at: chrono::Utc::now(),
        };
        assert!(status.is_write_protected);
        assert_eq!(status.device_path, "/dev/sda");
    }

    #[test]
    fn test_audit_entry_fields() {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            event: "TEST".to_string(),
            device_path: "/dev/sda".to_string(),
            result: "PASS".to_string(),
            details: "test details".to_string(),
        };
        assert_eq!(entry.event, "TEST");
        assert_eq!(entry.result, "PASS");
    }
}
