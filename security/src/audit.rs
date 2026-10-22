use bytesurgeon_core::Result;
use std::path::{Path, PathBuf};
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;

pub struct AuditTrail {
    log_path: PathBuf,
}

impl AuditTrail {
    pub fn new(log_path: &Path) -> Self {
        Self {
            log_path: log_path.to_path_buf(),
        }
    }

    pub fn log_event(&self, event_type: &str, details: &str) -> Result<()> {
        let timestamp = Utc::now().to_rfc3339();
        let log_entry = format!("[{}] {} - {}\n", timestamp, event_type, details);
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        
        file.write_all(log_entry.as_bytes())?;
        Ok(())
    }

    pub fn log_security_event(&self, event_type: &str, details: &str) -> Result<()> {
        self.log_event(&format!("SECURITY: {}", event_type), details)
    }

    pub fn log_recovery_event(&self, session_id: &str, files_recovered: u64) -> Result<()> {
        self.log_event(
            "RECOVERY",
            &format!("Session: {}, Files: {}", session_id, files_recovered)
        )
    }
}
