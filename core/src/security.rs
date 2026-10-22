use crate::{Result, ThreatStatus};
use std::path::Path;
use std::fs::File;
use std::io::Read;
use sha2::{Sha256, Digest};
use tracing::{warn, debug};

pub struct ThreatScanner {
    suspicious_patterns: Vec<String>,
    max_file_size: u64,
}

impl ThreatScanner {
    pub fn new() -> Self {
        Self {
            suspicious_patterns: Self::load_threat_patterns(),
            max_file_size: 100 * 1024 * 1024,
        }
    }

    fn load_threat_patterns() -> Vec<String> {
        vec![
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR".to_string(),
            "eval(".to_string(),
            "exec(".to_string(),
            "base64_decode".to_string(),
            "shell_exec".to_string(),
            "powershell".to_string(),
            "cmd.exe".to_string(),
            "/bin/sh".to_string(),
            "/bin/bash".to_string(),
            "WScript.Shell".to_string(),
            "AutoRun".to_string(),
            "Registry".to_string(),
            "HKEY_".to_string(),
        ]
    }

    pub fn scan_file(&self, file_path: &Path) -> Result<ThreatStatus> {
        let metadata = std::fs::metadata(file_path)?;
        
        if metadata.len() > self.max_file_size {
            debug!("File too large for threat scan: {}", file_path.display());
            return Ok(ThreatStatus::NotScanned);
        }

        let mut file = File::open(file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let content = String::from_utf8_lossy(&buffer);

        for pattern in &self.suspicious_patterns {
            if content.contains(pattern) {
                warn!("Suspicious pattern found in {}: {}", file_path.display(), pattern);
                return Ok(ThreatStatus::Suspicious);
            }
        }

        if self.is_executable(&buffer)
            && self.has_suspicious_headers(&buffer) {
                return Ok(ThreatStatus::Suspicious);
            }

        Ok(ThreatStatus::Clean)
    }

    fn is_executable(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        (data[0] == 0x4D && data[1] == 0x5A) ||
        (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46)
    }

    fn has_suspicious_headers(&self, data: &[u8]) -> bool {
        if data.len() < 512 {
            return false;
        }

        let suspicious_strings = [
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "NtUnmapViewOfSection",
            "SetWindowsHookEx",
        ];

        let content = String::from_utf8_lossy(&data[..512.min(data.len())]);
        
        for s in &suspicious_strings {
            if content.contains(s) {
                return true;
            }
        }

        false
    }

    pub fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        let mut file = File::open(file_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hex::encode(hasher.finalize()))
    }

    pub fn verify_file_integrity(&self, file_path: &Path, expected_hash: &str) -> Result<bool> {
        let actual_hash = self.calculate_file_hash(file_path)?;
        Ok(actual_hash == expected_hash)
    }
}

impl Default for ThreatScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SecurityPolicy {
    pub allow_network_recovery: bool,
    pub allow_mobile_recovery: bool,
    pub require_threat_scan: bool,
    pub max_concurrent_operations: usize,
    pub audit_logging: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_network_recovery: true,
            allow_mobile_recovery: true,
            require_threat_scan: true,
            max_concurrent_operations: 4,
            audit_logging: true,
        }
    }
}

pub struct AuditLogger {
    log_path: std::path::PathBuf,
}

impl AuditLogger {
    pub fn new(log_path: &Path) -> Self {
        Self {
            log_path: log_path.to_path_buf(),
        }
    }

    pub fn log_operation(&self, operation: &str, details: &str) -> Result<()> {
        use std::io::Write;
        
        let timestamp = chrono::Utc::now().to_rfc3339();
        let log_entry = format!("[{}] {} - {}\n", timestamp, operation, details);
        
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        
        file.write_all(log_entry.as_bytes())?;
        Ok(())
    }

    pub fn log_security_event(&self, event_type: &str, details: &str) -> Result<()> {
        self.log_operation(&format!("SECURITY: {}", event_type), details)
    }

    pub fn log_threat_detection(&self, file_path: &Path, threat_type: &str) -> Result<()> {
        self.log_security_event(
            "THREAT_DETECTED",
            &format!("File: {}, Threat: {}", file_path.display(), threat_type)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_threat_scanner_creation() {
        let scanner = ThreatScanner::new();
        assert!(!scanner.suspicious_patterns.is_empty());
    }

    #[test]
    fn test_threat_scanner_default() {
        let scanner = ThreatScanner::default();
        assert!(!scanner.suspicious_patterns.is_empty());
    }

    #[test]
    fn test_scan_clean_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("clean.txt");
        std::fs::write(&file_path, "Hello, this is a perfectly clean file with no issues.").unwrap();

        let scanner = ThreatScanner::new();
        let result = scanner.scan_file(&file_path).unwrap();
        assert_eq!(result, ThreatStatus::Clean);
    }

    #[test]
    fn test_scan_suspicious_file_eval() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("suspicious.js");
        std::fs::write(&file_path, "var x = eval(user_input);").unwrap();

        let scanner = ThreatScanner::new();
        let result = scanner.scan_file(&file_path).unwrap();
        assert_eq!(result, ThreatStatus::Suspicious);
    }

    #[test]
    fn test_scan_suspicious_file_shell() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("suspicious.sh");
        std::fs::write(&file_path, "#!/bin/sh\necho hello").unwrap();

        let scanner = ThreatScanner::new();
        let result = scanner.scan_file(&file_path).unwrap();
        assert_eq!(result, ThreatStatus::Suspicious);
    }

    #[test]
    fn test_file_hash_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("hashme.txt");
        std::fs::write(&file_path, b"test content").unwrap();

        let scanner = ThreatScanner::new();
        let hash = scanner.calculate_file_hash(&file_path).unwrap();
        assert_eq!(hash.len(), 64);

        let hash2 = scanner.calculate_file_hash(&file_path).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_integrity_verification() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("verify.txt");
        std::fs::write(&file_path, b"verify this content").unwrap();

        let scanner = ThreatScanner::new();
        let hash = scanner.calculate_file_hash(&file_path).unwrap();

        assert!(scanner.verify_file_integrity(&file_path, &hash).unwrap());
        assert!(!scanner.verify_file_integrity(&file_path, "badhash").unwrap());
    }

    #[test]
    fn test_audit_logger_creates_log_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path);

        logger.log_operation("TEST", "Test operation").unwrap();
        assert!(log_path.exists());

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("TEST"));
        assert!(content.contains("Test operation"));
    }

    #[test]
    fn test_audit_logger_multiple_entries() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path);

        logger.log_operation("OP1", "First").unwrap();
        logger.log_operation("OP2", "Second").unwrap();

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("OP1"));
        assert!(content.contains("OP2"));
        assert!(content.lines().count() >= 2);
    }

    #[test]
    fn test_audit_logger_security_event() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path);

        logger.log_security_event("BREACH", "Unauthorized access").unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("SECURITY: BREACH"));
    }

    #[test]
    fn test_audit_logger_threat_detection() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("audit.log");
        let logger = AuditLogger::new(&log_path);

        logger.log_threat_detection(Path::new("/tmp/bad.exe"), "malware").unwrap();
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("THREAT_DETECTED"));
        assert!(content.contains("/tmp/bad.exe"));
    }
}
