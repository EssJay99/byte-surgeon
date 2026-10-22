use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub examiner_id: String,
    pub operation: String,
    pub details: String,
    pub hash: String,
    pub prev_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<CryptoAuditEntry>,
    pub verification_key: String,
    pub created_at: DateTime<Utc>,
    pub examiner_id: String,
    pub entry_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedAuditLog {
    pub log: AuditLog,
    pub signature: String,
    pub exported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub is_valid: bool,
    pub entry_count: usize,
    pub first_invalid_index: Option<usize>,
    pub message: String,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct TamperProofLogger {
    entries: Vec<CryptoAuditEntry>,
    examiner_id: String,
    last_hash: String,
    created_at: DateTime<Utc>,
    sealed: bool,
}

impl TamperProofLogger {
    pub fn new(examiner_id: &str) -> Self {
        Self {
            entries: Vec::new(),
            examiner_id: examiner_id.to_string(),
            last_hash: GENESIS_HASH.to_string(),
            created_at: Utc::now(),
            sealed: false,
        }
    }

    pub fn log_event(&mut self, operation: &str, details: &str) -> Result<&CryptoAuditEntry> {
        if self.sealed {
            return Err(Error::SecurityViolation(
                "Audit log is sealed; no further entries permitted".into(),
            ));
        }

        let timestamp = Utc::now();
        let prev_hash = self.last_hash.clone();
        let hash = Self::compute_hash(&timestamp, &self.examiner_id, operation, details, &prev_hash);

        let entry = CryptoAuditEntry {
            timestamp,
            examiner_id: self.examiner_id.clone(),
            operation: operation.to_string(),
            details: details.to_string(),
            hash: hash.clone(),
            prev_hash,
        };

        self.last_hash = hash;
        self.entries.push(entry);

        Ok(self.entries.last().unwrap())
    }

    pub fn verify_log(&self) -> Result<VerificationResult> {
        if self.entries.is_empty() {
            return Ok(VerificationResult {
                is_valid: true,
                entry_count: 0,
                first_invalid_index: None,
                message: "Empty log is valid".into(),
            });
        }

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for (i, entry) in self.entries.iter().enumerate() {
            let computed = Self::compute_hash(
                &entry.timestamp,
                &entry.examiner_id,
                &entry.operation,
                &entry.details,
                &expected_prev_hash,
            );

            if computed != entry.hash {
                return Ok(VerificationResult {
                    is_valid: false,
                    entry_count: self.entries.len(),
                    first_invalid_index: Some(i),
                    message: format!(
                        "Hash mismatch at entry {}: expected {}, found {}",
                        i, computed, entry.hash
                    ),
                });
            }

            if entry.prev_hash != expected_prev_hash {
                return Ok(VerificationResult {
                    is_valid: false,
                    entry_count: self.entries.len(),
                    first_invalid_index: Some(i),
                    message: format!(
                        "Chain broken at entry {}: prev_hash mismatch",
                        i
                    ),
                });
            }

            expected_prev_hash = entry.hash.clone();
        }

        Ok(VerificationResult {
            is_valid: true,
            entry_count: self.entries.len(),
            first_invalid_index: None,
            message: format!("Log valid: {} entries verified", self.entries.len()),
        })
    }

    pub fn export_log(&self) -> Result<String> {
        let verification = self.verify_log()?;
        if !verification.is_valid {
            return Err(Error::SecurityViolation(
                "Cannot export tampered audit log".into(),
            ));
        }

        let verification_key = self.compute_verification_key();

        let audit_log = AuditLog {
            entries: self.entries.clone(),
            verification_key,
            created_at: self.created_at,
            examiner_id: self.examiner_id.clone(),
            entry_count: self.entries.len(),
        };

        let signature = Self::compute_signature(&audit_log);

        let exported = ExportedAuditLog {
            log: audit_log,
            signature,
            exported_at: Utc::now(),
        };

        serde_json::to_string_pretty(&exported).map_err(Error::Serialization)
    }

    pub fn seal(&mut self) -> Result<()> {
        self.sealed = true;
        Ok(())
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[CryptoAuditEntry] {
        &self.entries
    }

    pub fn import_and_verify(json: &str) -> Result<VerificationResult> {
        let exported: ExportedAuditLog =
            serde_json::from_str(json).map_err(Error::Serialization)?;

        let expected_signature = Self::compute_signature(&exported.log);
        if expected_signature != exported.signature {
            return Ok(VerificationResult {
                is_valid: false,
                entry_count: exported.log.entries.len(),
                first_invalid_index: None,
                message: "Export signature mismatch; log may have been altered".into(),
            });
        }

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for (i, entry) in exported.log.entries.iter().enumerate() {
            let computed = Self::compute_hash(
                &entry.timestamp,
                &entry.examiner_id,
                &entry.operation,
                &entry.details,
                &expected_prev_hash,
            );

            if computed != entry.hash {
                return Ok(VerificationResult {
                    is_valid: false,
                    entry_count: exported.log.entries.len(),
                    first_invalid_index: Some(i),
                    message: format!("Hash mismatch at entry {}", i),
                });
            }

            expected_prev_hash = entry.hash.clone();
        }

        Ok(VerificationResult {
            is_valid: true,
            entry_count: exported.log.entries.len(),
            first_invalid_index: None,
            message: "Imported log verified successfully".into(),
        })
    }

    fn compute_hash(
        timestamp: &DateTime<Utc>,
        examiner_id: &str,
        operation: &str,
        details: &str,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(examiner_id.as_bytes());
        hasher.update(operation.as_bytes());
        hasher.update(details.as_bytes());
        hasher.update(prev_hash.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn compute_verification_key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"TAMPER_PROOF_AUDIT_V1");
        hasher.update(self.examiner_id.as_bytes());
        hasher.update(self.created_at.to_rfc3339().as_bytes());
        hasher.update(self.last_hash.as_bytes());
        hasher.update(self.entries.len().to_le_bytes());
        hex::encode(hasher.finalize())
    }

    fn compute_signature(log: &AuditLog) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"AUDIT_EXPORT_SIGNATURE");
        hasher.update(log.verification_key.as_bytes());
        hasher.update(log.entry_count.to_le_bytes());
        for entry in &log.entries {
            hasher.update(entry.hash.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_event_creates_entry() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Scanned /dev/sda1").unwrap();

        let entry = logger.entries().last().unwrap();
        assert_eq!(entry.examiner_id, "examiner-001");
        assert_eq!(entry.operation, "SCAN");
        assert_eq!(entry.details, "Scanned /dev/sda1");
        assert_eq!(entry.prev_hash, GENESIS_HASH);
        assert!(!entry.hash.is_empty());
        assert_eq!(logger.entry_count(), 1);
    }

    #[test]
    fn test_hash_chaining() {
        let mut logger = TamperProofLogger::new("examiner-001");

        logger.log_event("SCAN", "First scan").unwrap();
        let hash1 = logger.entries().last().unwrap().hash.clone();

        logger.log_event("RECOVER", "Recovered file").unwrap();
        let hash2 = logger.entries().last().unwrap().hash.clone();
        assert_eq!(logger.entries().last().unwrap().prev_hash, hash1);

        logger.log_event("EXPORT", "Exported report").unwrap();
        assert_eq!(logger.entries().last().unwrap().prev_hash, hash2);
    }

    #[test]
    fn test_verify_valid_log() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Scan operation").unwrap();
        logger.log_event("RECOVER", "Recovery operation").unwrap();
        logger.log_event("EXPORT", "Export operation").unwrap();

        let result = logger.verify_log().unwrap();
        assert!(result.is_valid);
        assert_eq!(result.entry_count, 3);
        assert!(result.first_invalid_index.is_none());
    }

    #[test]
    fn test_detects_tampered_entry() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Original data").unwrap();
        logger.log_event("RECOVER", "Recovery op").unwrap();

        logger.entries[0].details = "TAMPERED DATA".to_string();

        let result = logger.verify_log().unwrap();
        assert!(!result.is_valid);
        assert_eq!(result.first_invalid_index, Some(0));
    }

    #[test]
    fn test_detects_inserted_entry() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "First").unwrap();
        logger.log_event("RECOVER", "Second").unwrap();

        let fake_entry = CryptoAuditEntry {
            timestamp: Utc::now(),
            examiner_id: "examiner-001".into(),
            operation: "FAKE".into(),
            details: "Injected".into(),
            hash: "aaaa".into(),
            prev_hash: logger.entries[0].hash.clone(),
        };
        logger.entries.insert(1, fake_entry);

        let result = logger.verify_log().unwrap();
        assert!(!result.is_valid);
        assert!(result.first_invalid_index.is_some());
    }

    #[test]
    fn test_export_and_import() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Disk scan").unwrap();
        logger.log_event("RECOVER", "File recovery").unwrap();
        logger.log_event("VERIFY", "Integrity check").unwrap();

        let exported_json = logger.export_log().unwrap();
        let result = TamperProofLogger::import_and_verify(&exported_json).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.entry_count, 3);
    }

    #[test]
    fn test_export_detects_tampering() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Data").unwrap();

        logger.entries[0].details = "Modified".to_string();

        let export_result = logger.export_log();
        assert!(export_result.is_err());
    }

    #[test]
    fn test_sealed_log_rejects_writes() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Before seal").unwrap();
        logger.seal().unwrap();

        let result = logger.log_event("RECOVER", "After seal");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_log_is_valid() {
        let logger = TamperProofLogger::new("examiner-001");
        let result = logger.verify_log().unwrap();
        assert!(result.is_valid);
        assert_eq!(result.entry_count, 0);
    }

    #[test]
    fn test_different_examiner_produces_different_hashes() {
        let mut logger1 = TamperProofLogger::new("examiner-001");
        let mut logger2 = TamperProofLogger::new("examiner-002");

        let e1 = logger1.log_event("SCAN", "Same data").unwrap();
        let e2 = logger2.log_event("SCAN", "Same data").unwrap();

        assert_ne!(e1.hash, e2.hash);
    }

    #[test]
    fn test_import_detects_altered_signature() {
        let mut logger = TamperProofLogger::new("examiner-001");
        logger.log_event("SCAN", "Test").unwrap();

        let mut exported: ExportedAuditLog =
            serde_json::from_str(&logger.export_log().unwrap()).unwrap();
        exported.signature = "bad_signature".to_string();

        let json = serde_json::to_string(&exported).unwrap();
        let result = TamperProofLogger::import_and_verify(&json).unwrap();
        assert!(!result.is_valid);
    }

    #[test]
    fn test_deterministic_hash() {
        let ts = Utc::now();
        let h1 = TamperProofLogger::compute_hash(&ts, "exam1", "OP", "detail", GENESIS_HASH);
        let h2 = TamperProofLogger::compute_hash(&ts, "exam1", "OP", "detail", GENESIS_HASH);
        assert_eq!(h1, h2);
    }
}
