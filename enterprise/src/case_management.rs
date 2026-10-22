use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub case_number: String,
    pub examiner: String,
    pub title: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub closed_at: Option<DateTime<Utc>>,
    pub status: CaseStatus,
    pub evidence_items: Vec<String>,
    pub notes: Vec<CaseNote>,
    pub legal_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CaseStatus {
    Open,
    UnderReview,
    Closed,
    OnHold,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseNote {
    pub id: String,
    pub author: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub case_id: String,
    pub item_number: String,
    pub description: String,
    pub device_type: String,
    pub serial_number: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub capacity_bytes: Option<u64>,
    pub acquisition_date: DateTime<Utc>,
    pub examiner: String,
    pub hash_md5: Option<String>,
    pub hash_sha1: Option<String>,
    pub hash_sha256: Option<String>,
    pub storage_location: String,
    pub custody_chain: Vec<ChainOfCustodyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyEntry {
    pub id: String,
    pub evidence_id: String,
    pub timestamp: DateTime<Utc>,
    pub released_by: String,
    pub received_by: String,
    pub purpose: String,
    pub location: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedFile {
    pub id: String,
    pub evidence_id: String,
    pub file_path: String,
    pub file_size: u64,
    pub file_hash: Option<String>,
    pub tags: Vec<String>,
    pub category: Option<String>,
    pub flagged: bool,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub case_number: String,
    pub examiner: String,
    pub title: String,
    pub description: String,
}

pub struct CaseManager {
    cases: Arc<RwLock<HashMap<String, Case>>>,
    evidence: Arc<RwLock<HashMap<String, EvidenceItem>>>,
    tagged_files: Arc<RwLock<HashMap<String, TaggedFile>>>,
}

impl CaseManager {
    pub fn new() -> Self {
        Self {
            cases: Arc::new(RwLock::new(HashMap::new())),
            evidence: Arc::new(RwLock::new(HashMap::new())),
            tagged_files: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_case(&self, case_info: CaseInfo) -> Result<Case> {
        let case = Case {
            id: uuid::Uuid::new_v4().to_string(),
            case_number: case_info.case_number,
            examiner: case_info.examiner,
            title: case_info.title,
            description: case_info.description,
            created_at: Utc::now(),
            closed_at: None,
            status: CaseStatus::Open,
            evidence_items: Vec::new(),
            notes: Vec::new(),
            legal_hold: false,
        };
        
        let mut cases = self.cases.write().await;
        cases.insert(case.id.clone(), case.clone());
        
        info!("Created case: {} ({})", case.case_number, case.id);
        Ok(case)
    }

    pub async fn get_case(&self, case_id: &str) -> Result<Case> {
        let cases = self.cases.read().await;
        cases
            .get(case_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Case not found: {}", case_id))
    }

    pub async fn add_evidence(&self, case_id: &str, mut evidence: EvidenceItem) -> Result<String> {
        let mut cases = self.cases.write().await;
        let case = cases
            .get_mut(case_id)
            .ok_or_else(|| anyhow::anyhow!("Case not found: {}", case_id))?;
        
        evidence.case_id = case_id.to_string();
        let evidence_id = evidence.id.clone();
        
        case.evidence_items.push(evidence_id.clone());
        
        let mut evidence_store = self.evidence.write().await;
        evidence_store.insert(evidence_id.clone(), evidence);
        
        info!("Added evidence {} to case {}", evidence_id, case_id);
        Ok(evidence_id)
    }

    pub async fn get_evidence(&self, evidence_id: &str) -> Result<EvidenceItem> {
        let evidence = self.evidence.read().await;
        evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Evidence not found: {}", evidence_id))
    }

    pub async fn log_custody_transfer(
        &self,
        evidence_id: &str,
        entry: ChainOfCustodyEntry,
    ) -> Result<()> {
        let mut evidence = self.evidence.write().await;
        let evidence_item = evidence
            .get_mut(evidence_id)
            .ok_or_else(|| anyhow::anyhow!("Evidence not found: {}", evidence_id))?;
        
        evidence_item.custody_chain.push(entry);
        
        info!("Logged custody transfer for evidence: {}", evidence_id);
        Ok(())
    }

    pub async fn tag_file(&self, file_id: &str, tag: &str) -> Result<()> {
        let mut files = self.tagged_files.write().await;
        let file = files
            .get_mut(file_id)
            .ok_or_else(|| anyhow::anyhow!("File not found: {}", file_id))?;
        
        if !file.tags.contains(&tag.to_string()) {
            file.tags.push(tag.to_string());
        }
        
        info!("Tagged file {} with: {}", file_id, tag);
        Ok(())
    }

    pub async fn add_tagged_file(&self, file: TaggedFile) -> Result<String> {
        let file_id = file.id.clone();
        let mut files = self.tagged_files.write().await;
        files.insert(file_id.clone(), file);
        Ok(file_id)
    }

    pub async fn flag_file(&self, file_id: &str, flagged: bool) -> Result<()> {
        let mut files = self.tagged_files.write().await;
        let file = files
            .get_mut(file_id)
            .ok_or_else(|| anyhow::anyhow!("File not found: {}", file_id))?;
        
        file.flagged = flagged;
        Ok(())
    }

    pub async fn set_legal_hold(&self, case_id: &str, hold: bool) -> Result<()> {
        let mut cases = self.cases.write().await;
        let case = cases
            .get_mut(case_id)
            .ok_or_else(|| anyhow::anyhow!("Case not found: {}", case_id))?;
        
        case.legal_hold = hold;
        info!("Set legal hold for case {}: {}", case_id, hold);
        Ok(())
    }

    pub async fn close_case(&self, case_id: &str) -> Result<()> {
        let mut cases = self.cases.write().await;
        let case = cases
            .get_mut(case_id)
            .ok_or_else(|| anyhow::anyhow!("Case not found: {}", case_id))?;
        
        if case.legal_hold {
            anyhow::bail!("Cannot close case with legal hold");
        }
        
        case.status = CaseStatus::Closed;
        case.closed_at = Some(Utc::now());
        
        info!("Closed case: {}", case_id);
        Ok(())
    }

    pub async fn add_case_note(&self, case_id: &str, author: &str, content: &str) -> Result<()> {
        let mut cases = self.cases.write().await;
        let case = cases
            .get_mut(case_id)
            .ok_or_else(|| anyhow::anyhow!("Case not found: {}", case_id))?;
        
        let note = CaseNote {
            id: uuid::Uuid::new_v4().to_string(),
            author: author.to_string(),
            content: content.to_string(),
            created_at: Utc::now(),
        };
        
        case.notes.push(note);
        Ok(())
    }

    pub async fn generate_case_report(&self, case_id: &str) -> Result<String> {
        let cases = self.cases.read().await;
        let case = cases
            .get(case_id)
            .ok_or_else(|| anyhow::anyhow!("Case not found: {}", case_id))?;
        
        let evidence_store = self.evidence.read().await;
        let files_store = self.tagged_files.read().await;
        
        let mut report = String::new();
        report.push_str("=== FORENSIC CASE REPORT ===\n\n");
        report.push_str(&format!("Case Number: {}\n", case.case_number));
        report.push_str(&format!("Title: {}\n", case.title));
        report.push_str(&format!("Examiner: {}\n", case.examiner));
        report.push_str(&format!("Created: {}\n", case.created_at.format("%Y-%m-%d %H:%M:%S UTC")));
        
        if let Some(closed) = case.closed_at {
            report.push_str(&format!("Closed: {}\n", closed.format("%Y-%m-%d %H:%M:%S UTC")));
        }
        
        report.push_str(&format!("Status: {:?}\n", case.status));
        report.push_str(&format!("Legal Hold: {}\n", if case.legal_hold { "YES" } else { "NO" }));
        report.push_str("\n");
        
        report.push_str("--- Case Description ---\n");
        report.push_str(&format!("{}\n\n", case.description));
        
        report.push_str(&format!("--- Evidence Items ({}) ---\n", case.evidence_items.len()));
        for (idx, evidence_id) in case.evidence_items.iter().enumerate() {
            if let Some(ev) = evidence_store.get(evidence_id) {
                report.push_str(&format!("\n{}. {} ({})\n", idx + 1, ev.item_number, ev.description));
                report.push_str(&format!("   Device Type: {}\n", ev.device_type));
                if let Some(serial) = &ev.serial_number {
                    report.push_str(&format!("   Serial Number: {}\n", serial));
                }
                report.push_str(&format!("   Acquisition Date: {}\n", ev.acquisition_date.format("%Y-%m-%d %H:%M:%S UTC")));
                report.push_str(&format!("   Examiner: {}\n", ev.examiner));
                
                if let Some(sha256) = &ev.hash_sha256 {
                    report.push_str(&format!("   SHA-256: {}\n", sha256));
                }
                
                report.push_str(&format!("   Custody Transfers: {}\n", ev.custody_chain.len()));
            }
        }
        
        let case_files: Vec<_> = files_store
            .values()
            .filter(|f| case.evidence_items.contains(&f.evidence_id))
            .collect();
        
        report.push_str(&format!("\n--- Recovered Files ({}) ---\n", case_files.len()));
        for file in case_files {
            report.push_str(&format!("\n- {}\n", file.file_path));
            report.push_str(&format!("  Size: {} bytes\n", file.file_size));
            if !file.tags.is_empty() {
                report.push_str(&format!("  Tags: {}\n", file.tags.join(", ")));
            }
            if file.flagged {
                report.push_str("  ** FLAGGED **\n");
            }
        }
        
        if !case.notes.is_empty() {
            report.push_str(&format!("\n--- Case Notes ({}) ---\n", case.notes.len()));
            for note in &case.notes {
                report.push_str(&format!("\n[{}] {}: {}\n", 
                    note.created_at.format("%Y-%m-%d %H:%M:%S"),
                    note.author,
                    note.content
                ));
            }
        }
        
        report.push_str("\n=== END OF REPORT ===\n");
        
        Ok(report)
    }

    pub async fn list_cases(&self) -> Result<Vec<Case>> {
        let cases = self.cases.read().await;
        Ok(cases.values().cloned().collect())
    }
}

impl EvidenceItem {
    pub fn new(
        item_number: String,
        description: String,
        device_type: String,
        examiner: String,
        storage_location: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            case_id: String::new(),
            item_number,
            description,
            device_type,
            serial_number: None,
            manufacturer: None,
            model: None,
            capacity_bytes: None,
            acquisition_date: Utc::now(),
            examiner,
            hash_md5: None,
            hash_sha1: None,
            hash_sha256: None,
            storage_location,
            custody_chain: Vec::new(),
        }
    }

    pub fn with_hashes(
        mut self,
        md5: Option<String>,
        sha1: Option<String>,
        sha256: Option<String>,
    ) -> Self {
        self.hash_md5 = md5;
        self.hash_sha1 = sha1;
        self.hash_sha256 = sha256;
        self
    }
}

impl TaggedFile {
    pub fn new(
        evidence_id: String,
        file_path: String,
        file_size: u64,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_id,
            file_path,
            file_size,
            file_hash: None,
            tags: Vec::new(),
            category: None,
            flagged: false,
            notes: None,
            created_at: Utc::now(),
        }
    }
}

impl ChainOfCustodyEntry {
    pub fn new(
        evidence_id: String,
        released_by: String,
        received_by: String,
        purpose: String,
        location: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_id,
            timestamp: Utc::now(),
            released_by,
            received_by,
            purpose,
            location,
            notes: None,
        }
    }
}

impl Default for CaseManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_case() -> Result<()> {
        let manager = CaseManager::new();
        
        let case_info = CaseInfo {
            case_number: "CASE-001".to_string(),
            examiner: "John Doe".to_string(),
            title: "Test Case".to_string(),
            description: "Test description".to_string(),
        };
        
        let case = manager.create_case(case_info).await?;
        assert_eq!(case.case_number, "CASE-001");
        assert_eq!(case.status, CaseStatus::Open);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_add_evidence() -> Result<()> {
        let manager = CaseManager::new();
        
        let case_info = CaseInfo {
            case_number: "CASE-001".to_string(),
            examiner: "John Doe".to_string(),
            title: "Test Case".to_string(),
            description: "Test description".to_string(),
        };
        
        let case = manager.create_case(case_info).await?;
        
        let evidence = EvidenceItem::new(
            "E001".to_string(),
            "Hard Drive".to_string(),
            "HDD".to_string(),
            "John Doe".to_string(),
            "Evidence Locker A".to_string(),
        );
        
        let evidence_id = manager.add_evidence(&case.id, evidence).await?;
        
        let updated_case = manager.get_case(&case.id).await?;
        assert_eq!(updated_case.evidence_items.len(), 1);
        assert_eq!(updated_case.evidence_items[0], evidence_id);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_custody_chain() -> Result<()> {
        let manager = CaseManager::new();
        
        let case_info = CaseInfo {
            case_number: "CASE-001".to_string(),
            examiner: "John Doe".to_string(),
            title: "Test Case".to_string(),
            description: "Test description".to_string(),
        };
        
        let case = manager.create_case(case_info).await?;
        
        let evidence = EvidenceItem::new(
            "E001".to_string(),
            "Hard Drive".to_string(),
            "HDD".to_string(),
            "John Doe".to_string(),
            "Evidence Locker A".to_string(),
        );
        
        let evidence_id = manager.add_evidence(&case.id, evidence).await?;
        
        let custody_entry = ChainOfCustodyEntry::new(
            evidence_id.clone(),
            "John Doe".to_string(),
            "Jane Smith".to_string(),
            "Forensic Analysis".to_string(),
            "Lab Room 1".to_string(),
        );
        
        manager.log_custody_transfer(&evidence_id, custody_entry).await?;
        
        let updated_evidence = manager.get_evidence(&evidence_id).await?;
        assert_eq!(updated_evidence.custody_chain.len(), 1);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_tag_file() -> Result<()> {
        let manager = CaseManager::new();
        
        let file = TaggedFile::new(
            "evidence1".to_string(),
            "/path/to/file.txt".to_string(),
            1024,
        );
        
        let file_id = manager.add_tagged_file(file).await?;
        manager.tag_file(&file_id, "important").await?;
        manager.tag_file(&file_id, "suspicious").await?;
        
        let files = manager.tagged_files.read().await;
        let tagged_file = files.get(&file_id).unwrap();
        assert_eq!(tagged_file.tags.len(), 2);
        assert!(tagged_file.tags.contains(&"important".to_string()));
        assert!(tagged_file.tags.contains(&"suspicious".to_string()));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_legal_hold() -> Result<()> {
        let manager = CaseManager::new();
        
        let case_info = CaseInfo {
            case_number: "CASE-001".to_string(),
            examiner: "John Doe".to_string(),
            title: "Test Case".to_string(),
            description: "Test description".to_string(),
        };
        
        let case = manager.create_case(case_info).await?;
        manager.set_legal_hold(&case.id, true).await?;
        
        let result = manager.close_case(&case.id).await;
        assert!(result.is_err());
        
        manager.set_legal_hold(&case.id, false).await?;
        manager.close_case(&case.id).await?;
        
        let closed_case = manager.get_case(&case.id).await?;
        assert_eq!(closed_case.status, CaseStatus::Closed);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_case_report() -> Result<()> {
        let manager = CaseManager::new();
        
        let case_info = CaseInfo {
            case_number: "CASE-001".to_string(),
            examiner: "John Doe".to_string(),
            title: "Test Case".to_string(),
            description: "Test description".to_string(),
        };
        
        let case = manager.create_case(case_info).await?;
        
        let evidence = EvidenceItem::new(
            "E001".to_string(),
            "Hard Drive".to_string(),
            "HDD".to_string(),
            "John Doe".to_string(),
            "Evidence Locker A".to_string(),
        );
        
        let evidence_id = manager.add_evidence(&case.id, evidence).await?;
        
        let file = TaggedFile::new(evidence_id, "/test/file.txt".to_string(), 1024);
        manager.add_tagged_file(file).await?;
        
        let report = manager.generate_case_report(&case.id).await?;
        
        assert!(report.contains("FORENSIC CASE REPORT"));
        assert!(report.contains("CASE-001"));
        assert!(report.contains("John Doe"));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_add_case_note() -> Result<()> {
        let manager = CaseManager::new();
        
        let case_info = CaseInfo {
            case_number: "CASE-001".to_string(),
            examiner: "John Doe".to_string(),
            title: "Test Case".to_string(),
            description: "Test description".to_string(),
        };
        
        let case = manager.create_case(case_info).await?;
        manager.add_case_note(&case.id, "John Doe", "Test note").await?;
        
        let updated_case = manager.get_case(&case.id).await?;
        assert_eq!(updated_case.notes.len(), 1);
        
        Ok(())
    }
}
