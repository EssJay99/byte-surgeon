use crate::{Error, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const CURRENT_VERSION: u32 = 1;
const CHECKPOINT_EXTENSION: &str = "ckpt";
const DEFAULT_OPS_INTERVAL: u64 = 100;
const DEFAULT_TIME_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Checkpoint {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub operation_state: String,
    pub progress_data: serde_json::Value,
    #[serde(default = "default_version")]
    pub version: u32,
}

fn default_version() -> u32 {
    CURRENT_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointManifest {
    pub version: u32,
    pub checkpoints: BTreeMap<String, CheckpointEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointEntry {
    pub id: String,
    pub file_name: String,
    pub timestamp: DateTime<Utc>,
    pub operation_state: String,
}

#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    pub ops_interval: u64,
    pub time_interval_secs: u64,
    pub max_checkpoints: Option<usize>,
}

impl Default for CheckpointConfig {
    fn default() -> Self {
        Self {
            ops_interval: DEFAULT_OPS_INTERVAL,
            time_interval_secs: DEFAULT_TIME_INTERVAL_SECS,
            max_checkpoints: None,
        }
    }
}

struct AutoState {
    ops_since_checkpoint: u64,
    last_checkpoint_time: DateTime<Utc>,
}

pub struct CheckpointManager {
    dir: PathBuf,
    config: CheckpointConfig,
    auto_state: Mutex<AutoState>,
}

impl CheckpointManager {
    pub fn new(dir: &Path) -> Result<Self> {
        Self::with_config(dir, CheckpointConfig::default())
    }

    pub fn with_config(dir: &Path, config: CheckpointConfig) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        info!("CheckpointManager initialized at {}", dir.display());
        Ok(Self {
            dir: dir.to_path_buf(),
            config,
            auto_state: Mutex::new(AutoState {
                ops_since_checkpoint: 0,
                last_checkpoint_time: Utc::now(),
            }),
        })
    }

    pub fn save_checkpoint(
        &self,
        operation_state: &str,
        progress_data: &serde_json::Value,
    ) -> Result<Checkpoint> {
        let checkpoint = Checkpoint {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            operation_state: operation_state.to_string(),
            progress_data: progress_data.clone(),
            version: CURRENT_VERSION,
        };

        let file_name = format!("{}.{}", checkpoint.id, CHECKPOINT_EXTENSION);
        let final_path = self.dir.join(&file_name);
        let temp_path = self.dir.join(format!(".{}.tmp", file_name));

        let json = serde_json::to_vec_pretty(&checkpoint)?;
        std::fs::write(&temp_path, &json)?;
        std::fs::rename(&temp_path, &final_path)?;

        self.update_manifest(|manifest| {
            manifest.checkpoints.insert(
                checkpoint.id.clone(),
                CheckpointEntry {
                    id: checkpoint.id.clone(),
                    file_name,
                    timestamp: checkpoint.timestamp,
                    operation_state: checkpoint.operation_state.clone(),
                },
            );
        })?;

        self.prune_old()?;

        {
            let mut state = self.auto_state.lock();
            state.ops_since_checkpoint = 0;
            state.last_checkpoint_time = Utc::now();
        }

        info!("Checkpoint saved: {}", checkpoint.id);
        Ok(checkpoint)
    }

    pub fn load_checkpoint(&self, id: &str) -> Result<Checkpoint> {
        let manifest = self.read_manifest()?;
        let entry = manifest
            .checkpoints
            .get(id)
            .ok_or_else(|| Error::Other(format!("Checkpoint not found: {}", id)))?;

        let path = self.dir.join(&entry.file_name);
        let data = std::fs::read(&path)?;
        let checkpoint: Checkpoint = serde_json::from_slice(&data)?;

        if checkpoint.version > CURRENT_VERSION {
            return Err(Error::Other(format!(
                "Checkpoint version {} is newer than supported version {}",
                checkpoint.version, CURRENT_VERSION
            )));
        }

        Ok(checkpoint)
    }

    pub fn list_checkpoints(&self) -> Result<Vec<CheckpointEntry>> {
        let manifest = self.read_manifest()?;
        let mut entries: Vec<CheckpointEntry> = manifest.checkpoints.into_values().collect();
        entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(entries)
    }

    pub fn delete_checkpoint(&self, id: &str) -> Result<()> {
        let mut manifest = self.read_manifest()?;
        let entry = manifest
            .checkpoints
            .remove(id)
            .ok_or_else(|| Error::Other(format!("Checkpoint not found: {}", id)))?;

        let path = self.dir.join(&entry.file_name);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        self.write_manifest(&manifest)?;
        info!("Checkpoint deleted: {}", id);
        Ok(())
    }

    pub fn should_auto_checkpoint(&self) -> bool {
        let state = self.auto_state.lock();
        if state.ops_since_checkpoint >= self.config.ops_interval {
            return true;
        }
        let elapsed = Utc::now()
            .signed_duration_since(state.last_checkpoint_time)
            .num_seconds();
        elapsed >= self.config.time_interval_secs as i64
    }

    pub fn record_operation(&self) {
        let mut state = self.auto_state.lock();
        state.ops_since_checkpoint += 1;
    }

    pub fn latest_checkpoint(&self) -> Result<Option<Checkpoint>> {
        let entries = self.list_checkpoints()?;
        match entries.last() {
            Some(entry) => Ok(Some(self.load_checkpoint(&entry.id)?)),
            None => Ok(None),
        }
    }

    fn read_manifest(&self) -> Result<CheckpointManifest> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(CheckpointManifest {
                version: CURRENT_VERSION,
                checkpoints: BTreeMap::new(),
            });
        }
        let data = std::fs::read(&path)?;
        let manifest: CheckpointManifest = serde_json::from_slice(&data)?;
        Ok(manifest)
    }

    fn write_manifest(&self, manifest: &CheckpointManifest) -> Result<()> {
        let path = self.manifest_path();
        let temp_path = self.dir.join(".manifest.json.tmp");
        let json = serde_json::to_vec_pretty(manifest)?;
        std::fs::write(&temp_path, &json)?;
        std::fs::rename(&temp_path, &path)?;
        Ok(())
    }

    fn update_manifest<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut CheckpointManifest),
    {
        let mut manifest = self.read_manifest()?;
        f(&mut manifest);
        self.write_manifest(&manifest)
    }

    fn prune_old(&self) -> Result<()> {
        let max = match self.config.max_checkpoints {
            Some(m) => m,
            None => return Ok(()),
        };
        let mut manifest = self.read_manifest()?;
        if manifest.checkpoints.len() <= max {
            return Ok(());
        }

        let mut entries: Vec<_> = manifest.checkpoints.iter().collect();
        entries.sort_by(|a, b| a.1.timestamp.cmp(&b.1.timestamp));

        let to_remove = entries.len() - max;
        let ids_to_remove: Vec<String> = entries
            .into_iter()
            .take(to_remove)
            .map(|(id, entry)| {
                let path = self.dir.join(&entry.file_name);
                if path.exists() {
                    if let Err(e) = std::fs::remove_file(&path) {
                        warn!("Failed to remove old checkpoint file {}: {}", id, e);
                    }
                }
                id.clone()
            })
            .collect();

        for id in ids_to_remove {
            manifest.checkpoints.remove(&id);
        }

        self.write_manifest(&manifest)
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("manifest.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_manager() -> (TempDir, CheckpointManager) {
        let dir = TempDir::new().unwrap();
        let mgr = CheckpointManager::new(dir.path()).unwrap();
        (dir, mgr)
    }

    #[test]
    fn test_save_and_load_checkpoint() {
        let (_dir, mgr) = make_manager();
        let progress = json!({"sector": 4096, "files_found": 12});
        let cp = mgr.save_checkpoint("disk_scan", &progress).unwrap();

        assert_eq!(cp.operation_state, "disk_scan");
        assert_eq!(cp.progress_data, progress);
        assert_eq!(cp.version, CURRENT_VERSION);

        let loaded = mgr.load_checkpoint(&cp.id).unwrap();
        assert_eq!(loaded.id, cp.id);
        assert_eq!(loaded.operation_state, loaded.operation_state);
        assert_eq!(loaded.progress_data, progress);
    }

    #[test]
    fn test_list_checkpoints_ordered() {
        let (_dir, mgr) = make_manager();
        let p1 = json!({"step": 1});
        let p2 = json!({"step": 2});
        let p3 = json!({"step": 3});

        let c1 = mgr.save_checkpoint("op", &p1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let c2 = mgr.save_checkpoint("op", &p2).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let c3 = mgr.save_checkpoint("op", &p3).unwrap();

        let list = mgr.list_checkpoints().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].id, c1.id);
        assert_eq!(list[1].id, c2.id);
        assert_eq!(list[2].id, c3.id);
    }

    #[test]
    fn test_delete_checkpoint() {
        let (_dir, mgr) = make_manager();
        let cp = mgr.save_checkpoint("op", &json!(null)).unwrap();
        assert_eq!(mgr.list_checkpoints().unwrap().len(), 1);

        mgr.delete_checkpoint(&cp.id).unwrap();
        assert_eq!(mgr.list_checkpoints().unwrap().len(), 0);
        assert!(mgr.load_checkpoint(&cp.id).is_err());
    }

    #[test]
    fn test_load_missing_checkpoint() {
        let (_dir, mgr) = make_manager();
        let result = mgr.load_checkpoint("nonexistent-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_resume_from_latest() {
        let (_dir, mgr) = make_manager();
        mgr.save_checkpoint("phase_1", &json!({"offset": 100})).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        mgr.save_checkpoint("phase_2", &json!({"offset": 200})).unwrap();

        let latest = mgr.latest_checkpoint().unwrap().unwrap();
        assert_eq!(latest.operation_state, "phase_2");
        assert_eq!(latest.progress_data["offset"], 200);
    }

    #[test]
    fn test_auto_checkpoint_trigger_by_ops() {
        let dir = TempDir::new().unwrap();
        let config = CheckpointConfig {
            ops_interval: 3,
            time_interval_secs: 9999,
            max_checkpoints: None,
        };
        let mgr = CheckpointManager::with_config(dir.path(), config).unwrap();

        assert!(!mgr.should_auto_checkpoint());
        mgr.record_operation();
        mgr.record_operation();
        assert!(!mgr.should_auto_checkpoint());
        mgr.record_operation();
        assert!(mgr.should_auto_checkpoint());
    }

    #[test]
    fn test_auto_checkpoint_trigger_by_time() {
        let dir = TempDir::new().unwrap();
        let config = CheckpointConfig {
            ops_interval: 9999,
            time_interval_secs: 0,
            max_checkpoints: None,
        };
        let mgr = CheckpointManager::with_config(dir.path(), config).unwrap();
        assert!(mgr.should_auto_checkpoint());
    }

    #[test]
    fn test_prune_old_checkpoints() {
        let dir = TempDir::new().unwrap();
        let config = CheckpointConfig {
            ops_interval: DEFAULT_OPS_INTERVAL,
            time_interval_secs: DEFAULT_TIME_INTERVAL_SECS,
            max_checkpoints: Some(2),
        };
        let mgr = CheckpointManager::with_config(dir.path(), config).unwrap();

        let c1 = mgr.save_checkpoint("op", &json!(1)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let c2 = mgr.save_checkpoint("op", &json!(2)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        mgr.save_checkpoint("op", &json!(3)).unwrap();

        let list = mgr.list_checkpoints().unwrap();
        assert_eq!(list.len(), 2);
        
        let loaded2 = mgr.load_checkpoint(&list[0].id).unwrap();
        let loaded3 = mgr.load_checkpoint(&list[1].id).unwrap();
        assert_eq!(loaded2.progress_data, json!(2));
        assert_eq!(loaded3.progress_data, json!(3));
        
        assert!(mgr.load_checkpoint(&c1.id).is_err());
        assert!(mgr.load_checkpoint(&c2.id).is_ok());
    }

    #[test]
    fn test_atomic_write_no_partial_file() {
        let (dir, mgr) = make_manager();
        mgr.save_checkpoint("op", &json!("test")).unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .collect();
        assert!(entries.is_empty(), "No .tmp files should remain");
    }

    #[test]
    fn test_version_compatibility() {
        let (_dir, mgr) = make_manager();
        let cp = mgr.save_checkpoint("op", &json!({"v": 1})).unwrap();
        let loaded = mgr.load_checkpoint(&cp.id).unwrap();
        assert_eq!(loaded.version, CURRENT_VERSION);
    }

    #[test]
    fn test_empty_manager_latest_returns_none() {
        let (_dir, mgr) = make_manager();
        assert!(mgr.latest_checkpoint().unwrap().is_none());
    }

    #[test]
    fn test_save_resets_auto_state() {
        let dir = TempDir::new().unwrap();
        let config = CheckpointConfig {
            ops_interval: 3,
            time_interval_secs: 9999,
            max_checkpoints: None,
        };
        let mgr = CheckpointManager::with_config(dir.path(), config).unwrap();

        mgr.record_operation();
        mgr.record_operation();
        mgr.record_operation();
        assert!(mgr.should_auto_checkpoint());

        mgr.save_checkpoint("op", &json!(null)).unwrap();
        assert!(!mgr.should_auto_checkpoint());
    }
}
