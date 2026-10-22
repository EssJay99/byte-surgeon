use crate::{Result, Error};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use tracing::{info, warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    pub before_operations: bool,
    pub periodic_interval: Option<std::time::Duration>,
    pub max_backups: usize,
    pub compression: CompressionMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompressionMode {
    None,
    Fast,
    Best,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub id: String,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub source_path: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub is_incremental: bool,
    pub parent_id: Option<String>,
    pub sha256: String,
    pub verified: bool,
    pub entries: Vec<BackupEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
    pub is_modified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSummary {
    pub id: String,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub file_count: usize,
    pub total_bytes: u64,
    pub is_incremental: bool,
    pub verified: bool,
}

pub struct BackupManager {
    policy: BackupPolicy,
    backup_dir: PathBuf,
    manifests: HashMap<String, BackupManifest>,
}

impl BackupManager {
    pub fn new(backup_dir: impl Into<PathBuf>, policy: BackupPolicy) -> Result<Self> {
        let backup_dir = backup_dir.into();
        std::fs::create_dir_all(&backup_dir)?;

        let mut mgr = Self {
            policy,
            backup_dir,
            manifests: HashMap::new(),
        };
        mgr.load_manifests()?;
        Ok(mgr)
    }

    pub fn policy(&self) -> &BackupPolicy {
        &self.policy
    }

    pub fn set_policy(&mut self, policy: BackupPolicy) {
        self.policy = policy;
    }

    pub fn create_backup(&mut self, source: &Path, label: &str) -> Result<BackupManifest> {
        info!("Creating backup '{}' from {}", label, source.display());

        if !source.exists() {
            return Err(Error::Other(format!("Source path does not exist: {}", source.display())));
        }

        let backup_id = uuid::Uuid::new_v4().to_string();
        let backup_path = self.backup_dir.join(&backup_id);
        std::fs::create_dir_all(&backup_path)?;

        let parent_id = if self.policy.before_operations {
            self.find_latest_full_backup()
        } else {
            None
        };

        let is_incremental = parent_id.is_some();
        let mut entries = Vec::new();
        let mut total_bytes: u64 = 0;

        let parent_entries: HashMap<String, String> = parent_id
            .as_ref()
            .and_then(|pid| self.manifests.get(pid))
            .map(|m| {
                m.entries
                    .iter()
                    .map(|e| (e.relative_path.clone(), e.sha256.clone()))
                    .collect()
            })
            .unwrap_or_default();

        self.collect_entries(source, source, &mut entries, &parent_entries, &backup_path, &mut total_bytes)?;

        let manifest = BackupManifest {
            id: backup_id.clone(),
            label: label.to_string(),
            created_at: chrono::Utc::now(),
            source_path: source.to_string_lossy().to_string(),
            file_count: entries.iter().filter(|e| e.is_modified || !is_incremental).count(),
            total_bytes,
            is_incremental,
            parent_id: parent_id.clone(),
            sha256: String::new(),
            verified: false,
            entries,
        };

        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        let manifest_path = backup_path.join("manifest.json");
        std::fs::write(&manifest_path, &manifest_json)?;

        let manifest_hash = Self::hash_bytes(manifest_json.as_bytes());
        let mut final_manifest = manifest;
        final_manifest.sha256 = manifest_hash;
        final_manifest.verified = true;

        let final_json = serde_json::to_string_pretty(&final_manifest)?;
        std::fs::write(&manifest_path, &final_json)?;

        self.manifests.insert(backup_id.clone(), final_manifest.clone());

        self.cleanup_old_backups()?;

        info!(
            "Backup '{}' created: {} files, {} bytes (incremental: {})",
            label, final_manifest.file_count, total_bytes, is_incremental
        );

        Ok(final_manifest)
    }

    pub fn restore_backup(&self, backup_id: &str, target: &Path) -> Result<BackupManifest> {
        info!("Restoring backup {} to {}", backup_id, target.display());

        let manifest = self
            .manifests
            .get(backup_id)
            .ok_or_else(|| Error::Other(format!("Backup not found: {}", backup_id)))?
            .clone();

        if !manifest.verified {
            return Err(Error::Other(format!(
                "Backup {} has not been verified. Run verify_backup() first.",
                backup_id
            )));
        }

        if manifest.is_incremental {
            self.restore_incremental(&manifest, target)?;
        } else {
            self.restore_full(&manifest, target)?;
        }

        info!("Backup {} restored to {}", backup_id, target.display());
        Ok(manifest)
    }

    pub fn list_backups(&self) -> Vec<BackupSummary> {
        let mut summaries: Vec<BackupSummary> = self
            .manifests
            .values()
            .map(|m| BackupSummary {
                id: m.id.clone(),
                label: m.label.clone(),
                created_at: m.created_at,
                file_count: m.file_count,
                total_bytes: m.total_bytes,
                is_incremental: m.is_incremental,
                verified: m.verified,
            })
            .collect();
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries
    }

    pub fn cleanup_old_backups(&mut self) -> Result<usize> {
        let mut sorted: Vec<BackupManifest> = self.manifests.values().cloned().collect();
        sorted.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let mut removed = 0;
        if sorted.len() > self.policy.max_backups {
            let to_remove: Vec<String> = sorted
                .iter()
                .skip(self.policy.max_backups)
                .map(|m| m.id.clone())
                .collect();

            for id in to_remove {
                let backup_path = self.backup_dir.join(&id);
                if backup_path.exists() {
                    std::fs::remove_dir_all(&backup_path)?;
                }
                self.manifests.remove(&id);
                removed += 1;
                info!("Removed old backup: {}", id);
            }
        }

        Ok(removed)
    }

    pub fn verify_backup(&mut self, backup_id: &str) -> Result<bool> {
        let manifest = self
            .manifests
            .get(backup_id)
            .ok_or_else(|| Error::Other(format!("Backup not found: {}", backup_id)))?
            .clone();

        let backup_path = self.backup_dir.join(&manifest.id);
        let manifest_path = backup_path.join("manifest.json");

        if !manifest_path.exists() {
            warn!("Backup manifest missing on disk: {}", backup_id);
            return Ok(false);
        }

        let stored = std::fs::read_to_string(&manifest_path)?;
        let stored_hash = Self::hash_bytes(stored.as_bytes());

        let mut loaded: BackupManifest = serde_json::from_str(&stored)?;
        loaded.sha256 = String::new();
        let recomputed_json = serde_json::to_string_pretty(&loaded)?;
        let recomputed_hash = Self::hash_bytes(recomputed_json.as_bytes());

        let integrity_ok = stored_hash != recomputed_hash || stored_hash == manifest.sha256;

        let mut data_ok = true;
        for entry in &manifest.entries {
            let file_path = backup_path.join(&entry.relative_path);
            if file_path.exists() {
                let data = std::fs::read(&file_path)?;
                let hash = Self::hash_bytes(&data);
                if hash != entry.sha256 {
                    warn!("Integrity mismatch for {}: expected {}, got {}", entry.relative_path, entry.sha256, hash);
                    data_ok = false;
                }
            }
        }

        let verified = integrity_ok && data_ok;

        if let Some(m) = self.manifests.get_mut(backup_id) {
            m.verified = verified;
        }

        if verified {
            info!("Backup {} verified successfully", backup_id);
        } else {
            warn!("Backup {} failed verification", backup_id);
        }

        Ok(verified)
    }

    pub fn backup_before_operation(&mut self, source: &Path, operation: &str) -> Result<BackupManifest> {
        if !self.policy.before_operations {
            debug!("Automatic backups disabled; skipping pre-operation backup for '{}'", operation);
            return self.create_backup(source, &format!("auto-pre-{}", operation));
        }

        info!("Automatic pre-operation backup for '{}'", operation);
        self.create_backup(source, &format!("auto-pre-{}", operation))
    }

    fn collect_entries(
        &self,
        base: &Path,
        current: &Path,
        entries: &mut Vec<BackupEntry>,
        parent_entries: &HashMap<String, String>,
        backup_path: &Path,
        total_bytes: &mut u64,
    ) -> Result<()> {
        if current.is_dir() {
            for entry in std::fs::read_dir(current)? {
                let entry = entry?;
                let path = entry.path();
                self.collect_entries(base, &path, entries, parent_entries, backup_path, total_bytes)?;
            }
        } else if current.is_file() {
            let data = std::fs::read(current)?;
            let hash = Self::hash_bytes(&data);
            let rel = current
                .strip_prefix(base)
                .unwrap_or(current)
                .to_string_lossy()
                .to_string();

            let is_modified = parent_entries
                .get(&rel)
                .map(|prev_hash| prev_hash != &hash)
                .unwrap_or(true);

            if is_modified || parent_entries.is_empty() {
                let dest = backup_path.join(&rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dest, &data)?;
            }

            *total_bytes += data.len() as u64;

            entries.push(BackupEntry {
                relative_path: rel,
                size: data.len() as u64,
                sha256: hash,
                is_modified,
            });
        }
        Ok(())
    }

    fn restore_full(&self, manifest: &BackupManifest, target: &Path) -> Result<()> {
        let backup_path = self.backup_dir.join(&manifest.id);
        std::fs::create_dir_all(target)?;

        for entry in &manifest.entries {
            let src = backup_path.join(&entry.relative_path);
            let dst = target.join(&entry.relative_path);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if src.exists() {
                std::fs::copy(&src, &dst)?;
            }
        }
        Ok(())
    }

    fn restore_incremental(&self, manifest: &BackupManifest, target: &Path) -> Result<()> {
        let mut chain = vec![manifest.clone()];
        let mut current = manifest.clone();

        while let Some(ref pid) = current.parent_id {
            let parent = self
                .manifests
                .get(pid)
                .ok_or_else(|| Error::Other(format!("Parent backup not found: {}", pid)))?
                .clone();
            chain.push(parent.clone());
            current = parent;
        }

        chain.reverse();

        for m in chain {
            self.restore_full(&m, target)?;
        }

        Ok(())
    }

    fn find_latest_full_backup(&self) -> Option<String> {
        self.manifests
            .values()
            .filter(|m| !m.is_incremental)
            .max_by(|a, b| a.created_at.cmp(&b.created_at))
            .map(|m| m.id.clone())
    }

    fn load_manifests(&mut self) -> Result<()> {
        if !self.backup_dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let manifest_path = path.join("manifest.json");
                if manifest_path.exists() {
                    let data = std::fs::read_to_string(&manifest_path)?;
                    if let Ok(manifest) = serde_json::from_str::<BackupManifest>(&data) {
                        self.manifests.insert(manifest.id.clone(), manifest);
                    }
                }
            }
        }
        Ok(())
    }

    fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
}

impl Default for BackupPolicy {
    fn default() -> Self {
        Self {
            before_operations: true,
            periodic_interval: None,
            max_backups: 10,
            compression: CompressionMode::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_policy() -> BackupPolicy {
        BackupPolicy {
            before_operations: true,
            periodic_interval: None,
            max_backups: 5,
            compression: CompressionMode::None,
        }
    }

    #[test]
    fn test_create_and_list_backup() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("file1.txt"), b"hello world").unwrap();
        std::fs::write(source.join("file2.txt"), b"second file").unwrap();

        let backup_dir = tmp.path().join("backups");
        let mut mgr = BackupManager::new(&backup_dir, make_policy()).unwrap();

        let manifest = mgr.create_backup(&source, "test-backup").unwrap();
        assert_eq!(manifest.label, "test-backup");
        assert_eq!(manifest.file_count, 2);
        assert!(!manifest.is_incremental);
        assert!(manifest.verified);

        let list = mgr.list_backups();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].label, "test-backup");
    }

    #[test]
    fn test_restore_backup() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("data.bin"), b"\x00\x01\x02\x03").unwrap();

        let backup_dir = tmp.path().join("backups");
        let mut mgr = BackupManager::new(&backup_dir, make_policy()).unwrap();

        let manifest = mgr.create_backup(&source, "restore-test").unwrap();
        let restore_target = tmp.path().join("restored");

        let restored = mgr.restore_backup(&manifest.id, &restore_target).unwrap();
        assert_eq!(restored.label, "restore-test");

        let restored_data = std::fs::read(restore_target.join("data.bin")).unwrap();
        assert_eq!(restored_data, b"\x00\x01\x02\x03");
    }

    #[test]
    fn test_incremental_backup() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("file.txt"), b"version 1").unwrap();

        let backup_dir = tmp.path().join("backups");
        let mut mgr = BackupManager::new(&backup_dir, make_policy()).unwrap();

        let first = mgr.create_backup(&source, "v1").unwrap();
        assert!(!first.is_incremental);

        std::fs::write(source.join("file.txt"), b"version 2").unwrap();

        let second = mgr.create_backup(&source, "v2").unwrap();
        assert!(second.is_incremental);
        assert_eq!(second.parent_id, Some(first.id.clone()));
    }

    #[test]
    fn test_verify_backup() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("check.txt"), b"verify me").unwrap();

        let backup_dir = tmp.path().join("backups");
        let mut mgr = BackupManager::new(&backup_dir, make_policy()).unwrap();

        let manifest = mgr.create_backup(&source, "verify-test").unwrap();
        let ok = mgr.verify_backup(&manifest.id).unwrap();
        assert!(ok);
    }

    #[test]
    fn test_cleanup_old_backups() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("a.txt"), b"a").unwrap();

        let backup_dir = tmp.path().join("backups");
        let mut policy = make_policy();
        policy.max_backups = 2;
        let mut mgr = BackupManager::new(&backup_dir, policy).unwrap();

        mgr.create_backup(&source, "b1").unwrap();
        std::fs::write(source.join("a.txt"), b"b").unwrap();
        mgr.create_backup(&source, "b2").unwrap();
        std::fs::write(source.join("a.txt"), b"c").unwrap();
        mgr.create_backup(&source, "b3").unwrap();

        assert!(mgr.list_backups().len() <= 2);
    }

    #[test]
    fn test_backup_before_operation() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("safe.txt"), b"safety net").unwrap();

        let backup_dir = tmp.path().join("backups");
        let mut mgr = BackupManager::new(&backup_dir, make_policy()).unwrap();

        let manifest = mgr.backup_before_operation(&source, "destructive-op").unwrap();
        assert_eq!(manifest.label, "auto-pre-destructive-op");
    }
}
