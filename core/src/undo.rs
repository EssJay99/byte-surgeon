use crate::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Operation {
    FileCreated,
    FileDeleted,
    FileMoved,
    FileRenamed,
    FileCopied,
    MetadataChanged,
    PermissionsChanged,
    OwnershipChanged,
    TimestampsChanged,
    ContentModified,
    FileRecovered,
    FileDeduplicated,
    DirectoryCreated,
    DirectoryDeleted,
    DirectoryMoved,
    BatchOperation,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileState {
    pub path: Option<PathBuf>,
    pub size: Option<u64>,
    pub is_directory: bool,
    pub metadata_snapshot: Option<String>,
    pub content_hash: Option<String>,
    pub extra: std::collections::HashMap<String, String>,
}

impl FileState {
    pub fn new() -> Self {
        Self {
            path: None,
            size: None,
            is_directory: false,
            metadata_snapshot: None,
            content_hash: None,
            extra: std::collections::HashMap::new(),
        }
    }

    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    pub fn with_metadata(mut self, snapshot: String) -> Self {
        self.metadata_snapshot = Some(snapshot);
        self
    }

    pub fn with_hash(mut self, hash: String) -> Self {
        self.content_hash = Some(hash);
        self
    }
}

impl Default for FileState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoAction {
    pub id: String,
    pub operation: Operation,
    pub before_state: FileState,
    pub after_state: FileState,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub reversible: bool,
}

impl UndoAction {
    pub fn new(operation: Operation, before: FileState, after: FileState) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let description = Self::generate_description(&operation, &before, &after);
        let reversible = Self::is_reversible(&operation);

        Self {
            id,
            operation,
            before_state: before,
            after_state: after,
            timestamp,
            description,
            reversible,
        }
    }

    fn generate_description(operation: &Operation, before: &FileState, after: &FileState) -> String {
        match operation {
            Operation::FileCreated => {
                let path = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Created file: {}", path)
            }
            Operation::FileDeleted => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Deleted file: {}", path)
            }
            Operation::FileMoved => {
                let from = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let to = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Moved file: {} -> {}", from, to)
            }
            Operation::FileRenamed => {
                let from = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let to = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Renamed file: {} -> {}", from, to)
            }
            Operation::FileCopied => {
                let to = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Copied file to: {}", to)
            }
            Operation::MetadataChanged => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Changed metadata for: {}", path)
            }
            Operation::PermissionsChanged => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Changed permissions for: {}", path)
            }
            Operation::OwnershipChanged => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Changed ownership for: {}", path)
            }
            Operation::TimestampsChanged => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Changed timestamps for: {}", path)
            }
            Operation::ContentModified => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Modified content of: {}", path)
            }
            Operation::FileRecovered => {
                let path = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Recovered file: {}", path)
            }
            Operation::FileDeduplicated => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Deduplicated file: {}", path)
            }
            Operation::DirectoryCreated => {
                let path = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Created directory: {}", path)
            }
            Operation::DirectoryDeleted => {
                let path = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Deleted directory: {}", path)
            }
            Operation::DirectoryMoved => {
                let from = before.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let to = after.path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                format!("Moved directory: {} -> {}", from, to)
            }
            Operation::BatchOperation => "Batch operation".to_string(),
            Operation::Custom(desc) => desc.clone(),
        }
    }

    fn is_reversible(operation: &Operation) -> bool {
        matches!(
            operation,
            Operation::FileCreated
                | Operation::FileDeleted
                | Operation::FileMoved
                | Operation::FileRenamed
                | Operation::FileCopied
                | Operation::MetadataChanged
                | Operation::PermissionsChanged
                | Operation::OwnershipChanged
                | Operation::TimestampsChanged
                | Operation::ContentModified
                | Operation::FileRecovered
                | Operation::FileDeduplicated
                | Operation::DirectoryCreated
                | Operation::DirectoryDeleted
                | Operation::DirectoryMoved
                | Operation::BatchOperation
        )
    }
}

pub struct UndoManager {
    undo_stack: VecDeque<UndoAction>,
    redo_stack: VecDeque<UndoAction>,
    max_depth: usize,
}

impl UndoManager {
    pub fn new(max_depth: usize) -> Self {
        assert!(max_depth > 0, "max_depth must be greater than 0");
        Self {
            undo_stack: VecDeque::new(),
            redo_stack: VecDeque::new(),
            max_depth,
        }
    }

    pub fn record_action(&mut self, action: UndoAction) -> Result<()> {
        if !action.reversible {
            warn!(operation = ?action.operation, "Recording non-reversible action");
        }

        if self.undo_stack.len() >= self.max_depth {
            self.undo_stack.pop_front();
            debug!("Undo stack at capacity, dropped oldest action");
        }

        self.redo_stack.clear();
        info!(
            id = %action.id,
            operation = ?action.operation,
            description = %action.description,
            "Recorded undo action"
        );
        self.undo_stack.push_back(action);
        Ok(())
    }

    pub fn undo(&mut self) -> Result<Option<UndoAction>> {
        match self.undo_stack.pop_back() {
            Some(action) => {
                info!(
                    id = %action.id,
                    operation = ?action.operation,
                    "Undoing action"
                );
                self.redo_stack.push_back(action.clone());
                Ok(Some(action))
            }
            None => {
                debug!("Nothing to undo");
                Ok(None)
            }
        }
    }

    pub fn redo(&mut self) -> Result<Option<UndoAction>> {
        match self.redo_stack.pop_back() {
            Some(action) => {
                info!(
                    id = %action.id,
                    operation = ?action.operation,
                    "Redoing action"
                );
                self.undo_stack.push_back(action.clone());
                Ok(Some(action))
            }
            None => {
                debug!("Nothing to redo");
                Ok(None)
            }
        }
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn clear_history(&mut self) {
        let undo_len = self.undo_stack.len();
        let redo_len = self.redo_stack.len();
        self.undo_stack.clear();
        self.redo_stack.clear();
        info!(
            undo_cleared = undo_len,
            redo_cleared = redo_len,
            "Cleared undo/redo history"
        );
    }

    pub fn undo_depth(&self) -> usize {
        self.undo_stack.len()
    }

    pub fn redo_depth(&self) -> usize {
        self.redo_stack.len()
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    pub fn set_max_depth(&mut self, max_depth: usize) {
        assert!(max_depth > 0, "max_depth must be greater than 0");
        self.max_depth = max_depth;
        while self.undo_stack.len() > self.max_depth {
            self.undo_stack.pop_front();
        }
        while self.redo_stack.len() > self.max_depth {
            self.redo_stack.pop_front();
        }
    }

    pub fn peek_undo(&self) -> Option<&UndoAction> {
        self.undo_stack.back()
    }

    pub fn peek_redo(&self) -> Option<&UndoAction> {
        self.redo_stack.back()
    }

    pub fn undo_history(&self) -> Vec<&UndoAction> {
        self.undo_stack.iter().collect()
    }

    pub fn redo_history(&self) -> Vec<&UndoAction> {
        self.redo_stack.iter().collect()
    }

    pub fn serialize(&self) -> Result<String> {
        let state = UndoManagerState {
            undo_stack: self.undo_stack.iter().cloned().collect(),
            redo_stack: self.redo_stack.iter().cloned().collect(),
            max_depth: self.max_depth,
        };
        serde_json::to_string(&state).map_err(|e| Error::Serialization(e))
    }

    pub fn deserialize(json: &str) -> Result<Self> {
        let state: UndoManagerState = serde_json::from_str(json).map_err(|e| Error::Serialization(e))?;
        let mut manager = Self::new(state.max_depth);
        manager.undo_stack = state.undo_stack.into_iter().collect();
        manager.redo_stack = state.redo_stack.into_iter().collect();
        Ok(manager)
    }
}

impl Default for UndoManager {
    fn default() -> Self {
        Self::new(100)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UndoManagerState {
    undo_stack: Vec<UndoAction>,
    redo_stack: Vec<UndoAction>,
    max_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_action(op: Operation, from: &str, to: &str) -> UndoAction {
        let before = FileState::new().with_path(PathBuf::from(from));
        let after = FileState::new().with_path(PathBuf::from(to));
        UndoAction::new(op, before, after)
    }

    #[test]
    fn test_record_action() {
        let mut manager = UndoManager::new(10);
        let action = make_action(Operation::FileCreated, "/tmp/old", "/tmp/new");
        manager.record_action(action).unwrap();
        assert_eq!(manager.undo_depth(), 1);
        assert!(manager.can_undo());
        assert!(!manager.can_redo());
    }

    #[test]
    fn test_undo() {
        let mut manager = UndoManager::new(10);
        let action = make_action(Operation::FileDeleted, "/tmp/file.txt", "/tmp/file.txt");
        manager.record_action(action).unwrap();

        let undone = manager.undo().unwrap();
        assert!(undone.is_some());
        assert_eq!(undone.unwrap().operation, Operation::FileDeleted);
        assert!(!manager.can_undo());
        assert!(manager.can_redo());
    }

    #[test]
    fn test_redo() {
        let mut manager = UndoManager::new(10);
        let action = make_action(Operation::FileMoved, "/tmp/a.txt", "/tmp/b.txt");
        manager.record_action(action).unwrap();
        manager.undo().unwrap();

        let redone = manager.redo().unwrap();
        assert!(redone.is_some());
        assert_eq!(redone.unwrap().operation, Operation::FileMoved);
        assert!(manager.can_undo());
        assert!(!manager.can_redo());
    }

    #[test]
    fn test_undo_empty() {
        let mut manager = UndoManager::new(10);
        assert!(manager.undo().unwrap().is_none());
    }

    #[test]
    fn test_redo_empty() {
        let mut manager = UndoManager::new(10);
        assert!(manager.redo().unwrap().is_none());
    }

    #[test]
    fn test_max_depth() {
        let mut manager = UndoManager::new(3);
        for i in 0..5 {
            let action = make_action(
                Operation::MetadataChanged,
                &format!("/tmp/file{}.txt", i),
                &format!("/tmp/file{}.txt", i),
            );
            manager.record_action(action).unwrap();
        }
        assert_eq!(manager.undo_depth(), 3);
    }

    #[test]
    fn test_clear_history() {
        let mut manager = UndoManager::new(10);
        for i in 0..5 {
            let action = make_action(
                Operation::FileCreated,
                &format!("/tmp/file{}.txt", i),
                &format!("/tmp/file{}.txt", i),
            );
            manager.record_action(action).unwrap();
        }
        manager.undo().unwrap();
        manager.undo().unwrap();

        assert_eq!(manager.undo_depth(), 3);
        assert_eq!(manager.redo_depth(), 2);

        manager.clear_history();
        assert_eq!(manager.undo_depth(), 0);
        assert_eq!(manager.redo_depth(), 0);
        assert!(!manager.can_undo());
        assert!(!manager.can_redo());
    }

    #[test]
    fn test_record_clears_redo_stack() {
        let mut manager = UndoManager::new(10);
        let a1 = make_action(Operation::FileCreated, "/tmp/a.txt", "/tmp/a.txt");
        let a2 = make_action(Operation::FileDeleted, "/tmp/b.txt", "/tmp/b.txt");

        manager.record_action(a1).unwrap();
        manager.undo().unwrap();
        assert!(manager.can_redo());

        manager.record_action(a2).unwrap();
        assert!(!manager.can_redo());
        assert_eq!(manager.redo_depth(), 0);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut manager = UndoManager::new(50);
        let action = make_action(Operation::FileRenamed, "/tmp/old.txt", "/tmp/new.txt");
        manager.record_action(action).unwrap();

        let serialized = manager.serialize().unwrap();
        let mut restored = UndoManager::deserialize(&serialized).unwrap();

        assert_eq!(restored.undo_depth(), 1);
        assert_eq!(restored.max_depth(), 50);
        let undone = restored.undo().unwrap().unwrap();
        assert_eq!(undone.operation, Operation::FileRenamed);
    }

    #[test]
    fn test_peek_undo_redo() {
        let mut manager = UndoManager::new(10);
        assert!(manager.peek_undo().is_none());
        assert!(manager.peek_redo().is_none());

        let action = make_action(Operation::FileCreated, "/tmp/f.txt", "/tmp/f.txt");
        manager.record_action(action).unwrap();

        assert!(manager.peek_undo().is_some());
        assert!(manager.peek_redo().is_none());

        manager.undo().unwrap();
        assert!(manager.peek_undo().is_none());
        assert!(manager.peek_redo().is_some());
    }

    #[test]
    fn test_action_description_generation() {
        let action = make_action(Operation::FileMoved, "/tmp/src.txt", "/tmp/dst.txt");
        assert!(action.description.contains("/tmp/src.txt"));
        assert!(action.description.contains("/tmp/dst.txt"));
        assert!(action.description.contains("Moved"));
    }

    #[test]
    fn test_action_reversibility() {
        let action = UndoAction::new(
            Operation::FileCreated,
            FileState::new(),
            FileState::new(),
        );
        assert!(action.reversible);
    }

    #[test]
    fn test_default_undo_manager() {
        let manager = UndoManager::default();
        assert_eq!(manager.max_depth(), 100);
        assert_eq!(manager.undo_depth(), 0);
        assert_eq!(manager.redo_depth(), 0);
    }

    #[test]
    fn test_set_max_depth_trims() {
        let mut manager = UndoManager::new(10);
        for i in 0..10 {
            let action = make_action(
                Operation::FileCreated,
                &format!("/tmp/f{}.txt", i),
                &format!("/tmp/f{}.txt", i),
            );
            manager.record_action(action).unwrap();
        }
        manager.set_max_depth(5);
        assert_eq!(manager.undo_depth(), 5);
        assert_eq!(manager.max_depth(), 5);
    }

    #[test]
    #[should_panic(expected = "max_depth must be greater than 0")]
    fn test_zero_max_depth_panics() {
        UndoManager::new(0);
    }

    #[test]
    fn test_undo_redo_multiple() {
        let mut manager = UndoManager::new(10);
        for i in 0..5 {
            let action = make_action(
                Operation::ContentModified,
                &format!("/tmp/f{}.txt", i),
                &format!("/tmp/f{}.txt", i),
            );
            manager.record_action(action).unwrap();
        }

        for _ in 0..5 {
            manager.undo().unwrap();
        }
        assert_eq!(manager.redo_depth(), 5);
        assert_eq!(manager.undo_depth(), 0);

        for _ in 0..5 {
            manager.redo().unwrap();
        }
        assert_eq!(manager.undo_depth(), 5);
        assert_eq!(manager.redo_depth(), 0);
    }

    #[test]
    fn test_file_state_builder() {
        let state = FileState::new()
            .with_path(PathBuf::from("/tmp/test.txt"))
            .with_size(1024)
            .with_metadata("snapshot_data".to_string())
            .with_hash("abc123".to_string());

        assert_eq!(state.path, Some(PathBuf::from("/tmp/test.txt")));
        assert_eq!(state.size, Some(1024));
        assert_eq!(state.metadata_snapshot, Some("snapshot_data".to_string()));
        assert_eq!(state.content_hash, Some("abc123".to_string()));
        assert!(!state.is_directory);
    }

    #[test]
    fn test_custom_operation() {
        let action = make_action(
            Operation::Custom("User-defined operation".to_string()),
            "/tmp/x.txt",
            "/tmp/y.txt",
        );
        assert_eq!(action.description, "User-defined operation");
    }

    #[test]
    fn test_undo_history_listing() {
        let mut manager = UndoManager::new(10);
        for i in 0..3 {
            let action = make_action(
                Operation::PermissionsChanged,
                &format!("/tmp/f{}.txt", i),
                &format!("/tmp/f{}.txt", i),
            );
            manager.record_action(action).unwrap();
        }
        let history = manager.undo_history();
        assert_eq!(history.len(), 3);
    }
}
