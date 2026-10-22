use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub id: String,
    pub device_path: String,
    pub scan_type: String,
    pub current_offset: u64,
    pub total_size: u64,
    pub files_found: Vec<String>,
    pub output_dir: PathBuf,
    pub started_at: DateTime<Utc>,
    pub last_checkpoint: DateTime<Utc>,
    pub status: ScanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Running,
    Interrupted,
    Completed,
    Failed,
}

pub struct ResumeManager {
    state_dir: PathBuf,
    checkpoint_interval_secs: u64,
    checkpoint_file_count: usize,
}

impl ResumeManager {
    pub fn new(state_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&state_dir)?;
        Ok(Self {
            state_dir,
            checkpoint_interval_secs: 60,
            checkpoint_file_count: 100,
        })
    }

    pub fn with_checkpoint_settings(
        state_dir: PathBuf,
        checkpoint_interval_secs: u64,
        checkpoint_file_count: usize,
    ) -> Result<Self> {
        fs::create_dir_all(&state_dir)?;
        Ok(Self {
            state_dir,
            checkpoint_interval_secs,
            checkpoint_file_count,
        })
    }

    pub fn save_state(&self, state: &ScanState) -> Result<()> {
        let state_file = self.state_dir.join(format!("{}.json", state.id));
        let json = serde_json::to_string_pretty(state)?;
        fs::write(&state_file, json)?;
        info!("Saved scan state for device: {}", state.device_path);
        Ok(())
    }

    pub fn load_state(&self, device_path: &str) -> Result<Option<ScanState>> {
        for entry in fs::read_dir(&self.state_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                let state: ScanState = serde_json::from_str(&content)?;
                if state.device_path == device_path {
                    return Ok(Some(state));
                }
            }
        }
        Ok(None)
    }

    pub fn list_interrupted_scans(&self) -> Result<Vec<ScanState>> {
        let mut interrupted = Vec::new();
        
        for entry in fs::read_dir(&self.state_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                if let Ok(state) = serde_json::from_str(&content) {
                    let state: ScanState = state;
                    if state.status == ScanStatus::Interrupted || state.status == ScanStatus::Running {
                        interrupted.push(state);
                    }
                }
            }
        }
        
        Ok(interrupted)
    }

    pub fn cleanup_old_states(&self, max_age_days: u32) -> Result<usize> {
        let cutoff = Utc::now() - chrono::Duration::days(max_age_days as i64);
        let mut cleaned = 0;
        
        for entry in fs::read_dir(&self.state_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)?;
                if let Ok(state) = serde_json::from_str::<ScanState>(&content) {
                    if state.last_checkpoint < cutoff {
                        fs::remove_file(&path)?;
                        info!("Cleaned up old scan state: {}", state.id);
                        cleaned += 1;
                    }
                }
            }
        }
        
        Ok(cleaned)
    }

    pub fn should_checkpoint(&self, state: &ScanState) -> bool {
        let time_elapsed = (Utc::now() - state.last_checkpoint).num_seconds() as u64;
        let file_threshold_met = !state.files_found.is_empty() && state.files_found.len() % self.checkpoint_file_count == 0;
        time_elapsed >= self.checkpoint_interval_secs || file_threshold_met
    }

    pub fn mark_interrupted(&self, state_id: &str) -> Result<()> {
        let state_file = self.state_dir.join(format!("{}.json", state_id));
        if state_file.exists() {
            let content = fs::read_to_string(&state_file)?;
            let mut state: ScanState = serde_json::from_str(&content)?;
            state.status = ScanStatus::Interrupted;
            self.save_state(&state)?;
            warn!("Marked scan as interrupted: {}", state_id);
        }
        Ok(())
    }

    pub fn delete_state(&self, state_id: &str) -> Result<()> {
        let state_file = self.state_dir.join(format!("{}.json", state_id));
        if state_file.exists() {
            fs::remove_file(&state_file)?;
        }
        Ok(())
    }
}

impl ScanState {
    pub fn new(
        device_path: String,
        scan_type: String,
        total_size: u64,
        output_dir: PathBuf,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            device_path,
            scan_type,
            current_offset: 0,
            total_size,
            files_found: Vec::new(),
            output_dir,
            started_at: now,
            last_checkpoint: now,
            status: ScanStatus::Running,
        }
    }

    pub fn progress_percentage(&self) -> f64 {
        if self.total_size == 0 {
            0.0
        } else {
            (self.current_offset as f64 / self.total_size as f64) * 100.0
        }
    }

    pub fn add_file(&mut self, file_path: String) {
        self.files_found.push(file_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_scan_state() {
        let state = ScanState::new(
            "/dev/sda".to_string(),
            "deep".to_string(),
            1_000_000_000,
            PathBuf::from("/output"),
        );
        
        assert_eq!(state.device_path, "/dev/sda");
        assert_eq!(state.scan_type, "deep");
        assert_eq!(state.total_size, 1_000_000_000);
        assert_eq!(state.current_offset, 0);
        assert_eq!(state.status, ScanStatus::Running);
    }

    #[test]
    fn test_progress_percentage() {
        let mut state = ScanState::new(
            "/dev/sda".to_string(),
            "deep".to_string(),
            1000,
            PathBuf::from("/output"),
        );
        
        state.current_offset = 500;
        assert_eq!(state.progress_percentage(), 50.0);
        
        state.current_offset = 0;
        assert_eq!(state.progress_percentage(), 0.0);
    }

    #[test]
    fn test_save_and_load_state() -> Result<()> {
        let temp_dir = tempdir()?;
        let manager = ResumeManager::new(temp_dir.path().to_path_buf())?;
        
        let state = ScanState::new(
            "/dev/sda".to_string(),
            "quick".to_string(),
            1_000_000,
            PathBuf::from("/output"),
        );
        
        manager.save_state(&state)?;
        let loaded = manager.load_state("/dev/sda")?;
        
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.device_path, "/dev/sda");
        assert_eq!(loaded.scan_type, "quick");
        
        Ok(())
    }

    #[test]
    fn test_list_interrupted_scans() -> Result<()> {
        let temp_dir = tempdir()?;
        let manager = ResumeManager::new(temp_dir.path().to_path_buf())?;
        
        let mut state1 = ScanState::new(
            "/dev/sda".to_string(),
            "deep".to_string(),
            1_000_000,
            PathBuf::from("/output"),
        );
        state1.status = ScanStatus::Interrupted;
        
        let mut state2 = ScanState::new(
            "/dev/sdb".to_string(),
            "quick".to_string(),
            2_000_000,
            PathBuf::from("/output"),
        );
        state2.status = ScanStatus::Completed;
        
        manager.save_state(&state1)?;
        manager.save_state(&state2)?;
        
        let interrupted = manager.list_interrupted_scans()?;
        assert_eq!(interrupted.len(), 1);
        assert_eq!(interrupted[0].device_path, "/dev/sda");
        
        Ok(())
    }

    #[test]
    fn test_mark_interrupted() -> Result<()> {
        let temp_dir = tempdir()?;
        let manager = ResumeManager::new(temp_dir.path().to_path_buf())?;
        
        let state = ScanState::new(
            "/dev/sda".to_string(),
            "deep".to_string(),
            1_000_000,
            PathBuf::from("/output"),
        );
        
        manager.save_state(&state)?;
        manager.mark_interrupted(&state.id)?;
        
        let loaded = manager.load_state("/dev/sda")?.unwrap();
        assert_eq!(loaded.status, ScanStatus::Interrupted);
        
        Ok(())
    }

    #[test]
    fn test_should_checkpoint() -> Result<()> {
        let temp_dir = tempdir()?;
        let manager = ResumeManager::with_checkpoint_settings(
            temp_dir.path().to_path_buf(),
            60,
            100,
        )?;
        
        let mut state = ScanState::new(
            "/dev/sda".to_string(),
            "deep".to_string(),
            1_000_000,
            PathBuf::from("/output"),
        );
        
        assert!(!manager.should_checkpoint(&state));
        
        state.files_found = (0..100).map(|i| format!("file_{}", i)).collect();
        assert!(manager.should_checkpoint(&state));
        
        Ok(())
    }

    #[test]
    fn test_cleanup_old_states() -> Result<()> {
        let temp_dir = tempdir()?;
        let manager = ResumeManager::new(temp_dir.path().to_path_buf())?;
        
        let mut state = ScanState::new(
            "/dev/sda".to_string(),
            "deep".to_string(),
            1_000_000,
            PathBuf::from("/output"),
        );
        state.last_checkpoint = Utc::now() - chrono::Duration::days(10);
        
        manager.save_state(&state)?;
        
        let cleaned = manager.cleanup_old_states(5)?;
        assert_eq!(cleaned, 1);
        
        let loaded = manager.load_state("/dev/sda")?;
        assert!(loaded.is_none());
        
        Ok(())
    }
}
