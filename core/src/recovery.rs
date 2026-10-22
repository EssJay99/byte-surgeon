use crate::{
    Result, DeviceInfo, RecoverySession, RecoveredFile, ScanType, SessionStatus,
    Database, DiskScanner, FileCarver, ThreatScanner, AuditLogger, SecurityPolicy,
};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

pub struct RecoveryEngine {
    db: Database,
    threat_scanner: ThreatScanner,
    audit_logger: AuditLogger,
    security_policy: SecurityPolicy,
    active_sessions: Arc<Mutex<Vec<String>>>,
}

impl RecoveryEngine {
    pub fn new(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;

        let db_path = data_dir.join("bytesurgeon.db");
        let db = Database::new(&db_path)?;

        let audit_path = data_dir.join("audit.log");
        let audit_logger = AuditLogger::new(&audit_path);

        let threat_scanner = ThreatScanner::new();
        let security_policy = SecurityPolicy::default();

        let engine = Self {
            db,
            threat_scanner,
            audit_logger,
            security_policy,
            active_sessions: Arc::new(Mutex::new(Vec::new())),
        };

        engine.audit_logger.log_operation("ENGINE_INIT", "Recovery engine initialized")?;
        Ok(engine)
    }

    pub fn enumerate_devices(&self) -> Result<Vec<DeviceInfo>> {
        info!("Enumerating connected devices");
        self.audit_logger.log_operation("DEVICE_ENUM", "Starting device enumeration")?;

        let mut devices = Vec::new();

        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/sys/block") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let device_name = path.file_name().unwrap().to_string_lossy();
                    
                    if device_name.starts_with("loop") || device_name.starts_with("ram") {
                        continue;
                    }

                    let device_path = format!("/dev/{}", device_name);
                    let mut device_info = DeviceInfo::new(&device_path, &device_name);
                    
                    if let Ok(metadata) = std::fs::metadata(&device_path) {
                        device_info.total_size = metadata.len();
                    }

                    device_info.device_type = self.detect_device_type(&device_name);
                    devices.push(device_info);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(entries) = std::fs::read_dir("/dev") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name().unwrap().to_string_lossy();
                    
                    if name.starts_with("disk") && !name.contains("s") {
                        let device_path = path.to_string_lossy().to_string();
                        let mut device_info = DeviceInfo::new(&device_path, &name);
                        
                        if let Ok(metadata) = std::fs::metadata(&device_path) {
                            device_info.total_size = metadata.len();
                        }

                        device_info.device_type = self.detect_device_type(&name);
                        devices.push(device_info);
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            for i in 0..26 {
                let drive_letter = (b'A' + i) as char;
                let device_path = format!("\\\\.\\{}:", drive_letter);
                
                if Path::new(&format!("{}:\\", drive_letter)).exists() {
                    let mut device_info = DeviceInfo::new(&device_path, &format!("{}:", drive_letter));
                    
                    if let Ok(metadata) = std::fs::metadata(&device_path) {
                        device_info.total_size = metadata.len();
                    }

                    device_info.device_type = crate::DeviceType::HardDrive;
                    devices.push(device_info);
                }
            }
        }

        for device in &devices {
            self.db.save_device(device)?;
        }

        self.audit_logger.log_operation(
            "DEVICE_ENUM",
            &format!("Found {} devices", devices.len())
        )?;

        info!("Found {} devices", devices.len());
        Ok(devices)
    }

    fn detect_device_type(&self, device_name: &str) -> crate::DeviceType {
        if device_name.starts_with("sd") || device_name.starts_with("hd") {
            crate::DeviceType::HardDrive
        } else if device_name.starts_with("nvme") {
            crate::DeviceType::SSD
        } else if device_name.starts_with("sr") || device_name.starts_with("cd") {
            crate::DeviceType::Optical
        } else {
            crate::DeviceType::Unknown
        }
    }

    pub fn start_recovery(
        &self,
        device: &DeviceInfo,
        scan_type: ScanType,
        output_dir: &Path,
    ) -> Result<String> {
        info!("Starting {:?} recovery on device: {}", scan_type, device.name);
        
        self.audit_logger.log_operation(
            "RECOVERY_START",
            &format!("Device: {}, Type: {:?}", device.name, scan_type)
        )?;

        let session = RecoverySession::new(device.clone(), scan_type.clone(), &output_dir.to_string_lossy());
        self.db.save_session(&session)?;

        {
            let mut sessions = self.active_sessions.lock().unwrap();
            sessions.push(session.id.clone());
        }

        match scan_type {
            ScanType::Signature => self.perform_signature_recovery(&session, device, output_dir)?,
            ScanType::Quick => self.perform_quick_scan(&session, device, output_dir)?,
            ScanType::Deep => self.perform_deep_scan(&session, device, output_dir)?,
            ScanType::FileSystem => self.perform_filesystem_scan(&session, device, output_dir)?,
            ScanType::Raw => self.perform_raw_recovery(&session, device, output_dir)?,
        }

        Ok(session.id)
    }

    fn perform_signature_recovery(
        &self,
        session: &RecoverySession,
        device: &DeviceInfo,
        output_dir: &Path,
    ) -> Result<()> {
        let scanner = DiskScanner::new(&device.path);
        let signatures = scanner.find_signatures()?;

        let carver = FileCarver::new(output_dir, &session.id);
        let mut recovered = carver.carve_files(&device.path, &signatures, |current, total| {
            info!("Carving file {}/{}", current, total);
        })?;

        if self.security_policy.require_threat_scan {
            for file in &mut recovered {
                match self.threat_scanner.scan_file(Path::new(&file.recovered_path)) {
                    Ok(status) => file.threat_scan = status,
                    Err(e) => {
                        warn!("Threat scan failed for {}: {}", file.recovered_path, e);
                        file.threat_scan = crate::ThreatStatus::NotScanned;
                    }
                }
                self.db.save_recovered_file(file)?;
            }
        }

        let mut updated_session = session.clone();
        updated_session.files_found = recovered.len() as u64;
        updated_session.files_recovered = recovered.len() as u64;
        updated_session.total_size_recovered = recovered.iter().map(|f| f.file_size).sum();
        updated_session.status = SessionStatus::Completed;
        updated_session.completed_at = Some(chrono::Utc::now());

        self.db.save_session(&updated_session)?;

        self.audit_logger.log_operation(
            "RECOVERY_COMPLETE",
            &format!("Session: {}, Files recovered: {}", session.id, recovered.len())
        )?;

        Ok(())
    }

    fn perform_quick_scan(
        &self,
        session: &RecoverySession,
        device: &DeviceInfo,
        output_dir: &Path,
    ) -> Result<()> {
        info!("Performing quick scan on {}", device.name);
        self.perform_signature_recovery(session, device, output_dir)
    }

    fn perform_deep_scan(
        &self,
        session: &RecoverySession,
        device: &DeviceInfo,
        output_dir: &Path,
    ) -> Result<()> {
        info!("Performing deep scan on {}", device.name);
        self.perform_signature_recovery(session, device, output_dir)
    }

    fn perform_filesystem_scan(
        &self,
        session: &RecoverySession,
        device: &DeviceInfo,
        output_dir: &Path,
    ) -> Result<()> {
        info!("Performing filesystem scan on {}", device.name);
        self.perform_signature_recovery(session, device, output_dir)
    }

    fn perform_raw_recovery(
        &self,
        session: &RecoverySession,
        device: &DeviceInfo,
        output_dir: &Path,
    ) -> Result<()> {
        info!("Performing raw recovery on {}", device.name);
        self.perform_signature_recovery(session, device, output_dir)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<RecoverySession>> {
        self.db.get_session(session_id)
    }

    pub fn get_recovered_files(&self, session_id: &str) -> Result<Vec<RecoveredFile>> {
        self.db.get_recovered_files(session_id)
    }

    pub fn get_all_devices(&self) -> Result<Vec<DeviceInfo>> {
        self.db.get_all_devices()
    }

    pub fn get_sessions_for_device(&self, device_id: &str) -> Result<Vec<RecoverySession>> {
        self.db.get_sessions_for_device(device_id)
    }

    pub fn cancel_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.active_sessions.lock().unwrap();
        sessions.retain(|id| id != session_id);
        
        self.audit_logger.log_operation(
            "SESSION_CANCEL",
            &format!("Session: {}", session_id)
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_recovery_engine_creation() {
        let temp_dir = TempDir::new().unwrap();
        let engine = RecoveryEngine::new(temp_dir.path());
        assert!(engine.is_ok());
    }

    #[test]
    fn test_recovery_engine_creates_data_dir() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().join("subdir");
        assert!(!data_dir.exists());
        let _engine = RecoveryEngine::new(&data_dir).unwrap();
        assert!(data_dir.exists());
    }

    #[test]
    fn test_device_enumeration_does_not_panic() {
        let temp_dir = TempDir::new().unwrap();
        let engine = RecoveryEngine::new(temp_dir.path()).unwrap();
        let result = engine.enumerate_devices();
        assert!(result.is_ok());
    }
}
