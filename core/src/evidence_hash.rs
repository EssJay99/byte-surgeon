use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChainEntry {
    pub item_id: String,
    pub content_hash: String,
    pub chain_hash: String,
    pub timestamp: DateTime<Utc>,
    pub examiner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub chain_id: String,
    pub entries: Vec<HashChainEntry>,
    pub created_at: DateTime<Utc>,
    pub examiner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub total_entries: usize,
    pub verified_entries: usize,
    pub failed_entry: Option<usize>,
    pub failure_reason: Option<String>,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct EvidenceHasher {
    examiner: String,
}

impl EvidenceHasher {
    pub fn new(examiner: &str) -> Self {
        Self {
            examiner: examiner.to_string(),
        }
    }

    pub fn create_chain(&self) -> EvidenceChain {
        debug!("Creating new evidence chain for examiner: {}", self.examiner);
        EvidenceChain {
            chain_id: Uuid::new_v4().to_string(),
            entries: Vec::new(),
            created_at: Utc::now(),
            examiner: self.examiner.clone(),
        }
    }

    pub fn add_item(&self, chain: &mut EvidenceChain, item_id: &str, content: &[u8]) -> Result<HashChainEntry> {
        let content_hash = Self::compute_content_hash(content);
        let previous_chain_hash = chain
            .entries
            .last()
            .map(|e| e.chain_hash.as_str())
            .unwrap_or(GENESIS_HASH);

        let chain_hash = Self::compute_chain_hash(
            &content_hash,
            previous_chain_hash,
            item_id,
            &self.examiner,
        );

        let entry = HashChainEntry {
            item_id: item_id.to_string(),
            content_hash,
            chain_hash,
            timestamp: Utc::now(),
            examiner: self.examiner.clone(),
        };

        chain.entries.push(entry.clone());
        debug!(
            "Added item {} to chain {} (entry #{})",
            item_id,
            chain.chain_id,
            chain.entries.len()
        );

        Ok(entry)
    }

    pub fn verify_chain(&self, chain: &EvidenceChain) -> Result<VerificationResult> {
        if chain.entries.is_empty() {
            return Ok(VerificationResult {
                valid: true,
                total_entries: 0,
                verified_entries: 0,
                failed_entry: None,
                failure_reason: None,
            });
        }

        let mut previous_hash = GENESIS_HASH.to_string();

        for (index, entry) in chain.entries.iter().enumerate() {
            let expected_chain_hash = Self::compute_chain_hash(
                &entry.content_hash,
                &previous_hash,
                &entry.item_id,
                &entry.examiner,
            );

            if expected_chain_hash != entry.chain_hash {
                return Ok(VerificationResult {
                    valid: false,
                    total_entries: chain.entries.len(),
                    verified_entries: index,
                    failed_entry: Some(index),
                    failure_reason: Some(format!(
                        "Chain hash mismatch at entry {}: expected {}, found {}",
                        index, expected_chain_hash, entry.chain_hash
                    )),
                });
            }

            if !Self::is_valid_hash(&entry.content_hash) {
                return Ok(VerificationResult {
                    valid: false,
                    total_entries: chain.entries.len(),
                    verified_entries: index,
                    failed_entry: Some(index),
                    failure_reason: Some(format!(
                        "Invalid content hash format at entry {}",
                        index
                    )),
                });
            }

            previous_hash = entry.chain_hash.clone();
        }

        Ok(VerificationResult {
            valid: true,
            total_entries: chain.entries.len(),
            verified_entries: chain.entries.len(),
            failed_entry: None,
            failure_reason: None,
        })
    }

    pub fn export_chain_json(&self, chain: &EvidenceChain) -> Result<String> {
        serde_json::to_string_pretty(chain).map_err(|e| Error::Serialization(e))
    }

    pub fn export_chain_csv(&self, chain: &EvidenceChain) -> Result<String> {
        let mut csv = String::from(
            "item_id,content_hash,chain_hash,timestamp,examiner\n",
        );

        for entry in &chain.entries {
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                Self::csv_escape(&entry.item_id),
                Self::csv_escape(&entry.content_hash),
                Self::csv_escape(&entry.chain_hash),
                entry.timestamp.to_rfc3339(),
                Self::csv_escape(&entry.examiner),
            ));
        }

        Ok(csv)
    }

    fn compute_content_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }



    fn compute_chain_hash(
        content_hash: &str,
        previous_chain_hash: &str,
        item_id: &str,
        examiner: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content_hash.as_bytes());
        hasher.update(previous_chain_hash.as_bytes());
        hasher.update(item_id.as_bytes());
        hasher.update(examiner.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn is_valid_hash(hash: &str) -> bool {
        hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn csv_escape(value: &str) -> String {
        if value.contains(',') || value.contains('"') || value.contains('\n') {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hasher() -> EvidenceHasher {
        EvidenceHasher::new("TestExaminer")
    }

    #[test]
    fn test_create_chain() {
        let hasher = test_hasher();
        let chain = hasher.create_chain();
        assert!(chain.entries.is_empty());
        assert_eq!(chain.examiner, "TestExaminer");
        assert!(!chain.chain_id.is_empty());
    }

    #[test]
    fn test_add_item() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        let entry = hasher.add_item(&mut chain, "item-001", b"evidence data").unwrap();

        assert_eq!(entry.item_id, "item-001");
        assert_eq!(entry.examiner, "TestExaminer");
        assert_eq!(chain.entries.len(), 1);
        assert!(EvidenceHasher::is_valid_hash(&entry.content_hash));
        assert!(EvidenceHasher::is_valid_hash(&entry.chain_hash));
    }

    #[test]
    fn test_chained_hashes_differ() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        let entry1 = hasher.add_item(&mut chain, "item-001", b"data-a").unwrap();
        let entry2 = hasher.add_item(&mut chain, "item-002", b"data-b").unwrap();

        assert_ne!(entry1.chain_hash, entry2.chain_hash);
        assert_ne!(entry1.content_hash, entry2.content_hash);
    }

    #[test]
    fn test_same_content_same_hash() {
        let content = b"identical content";
        let hash1 = EvidenceHasher::compute_content_hash(content);
        let hash2 = EvidenceHasher::compute_content_hash(content);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_verify_valid_chain() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"alpha").unwrap();
        hasher.add_item(&mut chain, "item-002", b"bravo").unwrap();
        hasher.add_item(&mut chain, "item-003", b"charlie").unwrap();

        let result = hasher.verify_chain(&chain).unwrap();
        assert!(result.valid);
        assert_eq!(result.total_entries, 3);
        assert_eq!(result.verified_entries, 3);
        assert!(result.failed_entry.is_none());
    }

    #[test]
    fn test_verify_empty_chain() {
        let hasher = test_hasher();
        let chain = hasher.create_chain();

        let result = hasher.verify_chain(&chain).unwrap();
        assert!(result.valid);
        assert_eq!(result.total_entries, 0);
    }

    #[test]
    fn test_detect_tampered_content_hash() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"alpha").unwrap();
        hasher.add_item(&mut chain, "item-002", b"bravo").unwrap();

        chain.entries[0].content_hash = "a".repeat(64);

        let result = hasher.verify_chain(&chain).unwrap();
        assert!(!result.valid);
        assert_eq!(result.failed_entry, Some(0));
    }

    #[test]
    fn test_detect_tampered_chain_hash() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"alpha").unwrap();
        hasher.add_item(&mut chain, "item-002", b"bravo").unwrap();

        chain.entries[1].chain_hash = "b".repeat(64);

        let result = hasher.verify_chain(&chain).unwrap();
        assert!(!result.valid);
        assert_eq!(result.failed_entry, Some(1));
    }

    #[test]
    fn test_detect_inserted_entry() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"alpha").unwrap();
        hasher.add_item(&mut chain, "item-003", b"charlie").unwrap();

        let fake_entry = hasher.add_item(&mut EvidenceChain {
            chain_id: chain.chain_id.clone(),
            entries: Vec::new(),
            created_at: chain.created_at,
            examiner: chain.examiner.clone(),
        }, "item-002-inserted", b"tampered").unwrap();

        chain.entries.insert(1, fake_entry);

        let result = hasher.verify_chain(&chain).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_detect_deleted_entry() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"alpha").unwrap();
        hasher.add_item(&mut chain, "item-002", b"bravo").unwrap();
        hasher.add_item(&mut chain, "item-003", b"charlie").unwrap();

        chain.entries.remove(1);

        let result = hasher.verify_chain(&chain).unwrap();
        assert!(!result.valid);
        assert_eq!(result.failed_entry, Some(1));
    }

    #[test]
    fn test_export_json() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"data").unwrap();

        let json = hasher.export_chain_json(&chain).unwrap();
        assert!(json.contains("item-001"));
        assert!(json.contains("TestExaminer"));

        let parsed: EvidenceChain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].item_id, "item-001");
    }

    #[test]
    fn test_export_csv() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"data").unwrap();
        hasher.add_item(&mut chain, "item-002", b"more data").unwrap();

        let csv = hasher.export_chain_csv(&chain).unwrap();
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("item_id"));
        assert!(lines[1].contains("item-001"));
        assert!(lines[2].contains("item-002"));
    }

    #[test]
    fn test_genesis_hash_used_for_first_entry() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "first", b"content").unwrap();

        let expected = EvidenceHasher::compute_chain_hash(
            &chain.entries[0].content_hash,
            GENESIS_HASH,
            "first",
            "TestExaminer",
        );
        assert_eq!(chain.entries[0].chain_hash, expected);
    }

    #[test]
    fn test_different_examiners_produce_different_chains() {
        let hasher_a = EvidenceHasher::new("ExaminerA");
        let hasher_b = EvidenceHasher::new("ExaminerB");

        let mut chain_a = hasher_a.create_chain();
        let mut chain_b = hasher_b.create_chain();

        hasher_a.add_item(&mut chain_a, "item", b"same content").unwrap();
        hasher_b.add_item(&mut chain_b, "item", b"same content").unwrap();

        assert_ne!(chain_a.entries[0].chain_hash, chain_b.entries[0].chain_hash);
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(EvidenceHasher::csv_escape("simple"), "simple");
        assert_eq!(EvidenceHasher::csv_escape("has,comma"), "\"has,comma\"");
        assert_eq!(EvidenceHasher::csv_escape("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn test_verify_after_json_roundtrip() {
        let hasher = test_hasher();
        let mut chain = hasher.create_chain();
        hasher.add_item(&mut chain, "item-001", b"alpha").unwrap();
        hasher.add_item(&mut chain, "item-002", b"bravo").unwrap();

        let json = hasher.export_chain_json(&chain).unwrap();
        let restored: EvidenceChain = serde_json::from_str(&json).unwrap();

        let result = hasher.verify_chain(&restored).unwrap();
        assert!(result.valid);
        assert_eq!(result.verified_entries, 2);
    }}
