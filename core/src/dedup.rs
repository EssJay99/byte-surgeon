use crate::{Result, Error};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use tracing::debug;
use serde::{Deserialize, Serialize};

pub struct DeduplicationEngine {
    full_hashes: HashSet<String>,
    file_map: HashMap<String, Vec<PathBuf>>,
    partial_hashes: HashMap<String, String>,
    partial_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupResult {
    pub hash: String,
    pub file_path: PathBuf,
    pub is_duplicate: bool,
    pub existing_paths: Vec<PathBuf>,
}

impl DeduplicationEngine {
    pub fn new() -> Self {
        Self {
            full_hashes: HashSet::new(),
            file_map: HashMap::new(),
            partial_hashes: HashMap::new(),
            partial_size: 1024 * 1024,
        }
    }

    pub fn with_partial_size(mut self, size: usize) -> Self {
        self.partial_size = size;
        self
    }

    pub fn is_duplicate(&mut self, file_path: &Path) -> Result<bool> {
        if !file_path.exists() {
            return Err(Error::Other(format!("File not found: {}", file_path.display())));
        }

        let partial_hash = self.compute_partial_hash(file_path)?;

        if let Some(_expected_full) = self.partial_hashes.get(&partial_hash) {
            let full_hash = self.compute_full_hash(file_path)?;
            if self.full_hashes.contains(&full_hash) {
                debug!("Duplicate detected: {}", file_path.display());
                return Ok(true);
            }
            self.partial_hashes.insert(partial_hash, full_hash);
            return Ok(false);
        }

        Ok(false)
    }

    pub fn record_file(&mut self, file_path: &Path) -> Result<String> {
        if !file_path.exists() {
            return Err(Error::Other(format!("File not found: {}", file_path.display())));
        }

        let partial_hash = self.compute_partial_hash(file_path)?;
        let full_hash = self.compute_full_hash(file_path)?;

        if let Some(existing_paths) = self.file_map.get_mut(&full_hash) {
            if !existing_paths.contains(&file_path.to_path_buf()) {
                existing_paths.push(file_path.to_path_buf());
            }
        } else {
            self.file_map.insert(full_hash.clone(), vec![file_path.to_path_buf()]);
        }

        self.full_hashes.insert(full_hash.clone());
        self.partial_hashes.insert(partial_hash, full_hash.clone());

        debug!("Recorded file: {} (hash: {})", file_path.display(), &full_hash[..16]);

        Ok(full_hash)
    }

    pub fn check_and_record(&mut self, file_path: &Path) -> Result<DedupResult> {
        if !file_path.exists() {
            return Err(Error::Other(format!("File not found: {}", file_path.display())));
        }

        let full_hash = self.compute_full_hash(file_path)?;
        let is_dup = self.full_hashes.contains(&full_hash);

        let existing_paths = self.file_map.get(&full_hash)
            .cloned()
            .unwrap_or_default();

        if let Some(existing_paths) = self.file_map.get_mut(&full_hash) {
            if !existing_paths.contains(&file_path.to_path_buf()) {
                existing_paths.push(file_path.to_path_buf());
            }
        } else {
            self.file_map.insert(full_hash.clone(), vec![file_path.to_path_buf()]);
        }

        self.full_hashes.insert(full_hash.clone());

        Ok(DedupResult {
            hash: full_hash,
            file_path: file_path.to_path_buf(),
            is_duplicate: is_dup,
            existing_paths,
        })
    }

    pub fn get_duplicates(&self) -> Result<Vec<(String, Vec<PathBuf>)>> {
        let mut duplicates: Vec<(String, Vec<PathBuf>)> = self.file_map
            .iter()
            .filter(|(_, paths)| paths.len() > 1)
            .map(|(hash, paths)| (hash.clone(), paths.clone()))
            .collect();

        duplicates.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

        Ok(duplicates)
    }

    pub fn get_duplicate_count(&self) -> usize {
        self.file_map.values().filter(|paths| paths.len() > 1).count()
    }

    pub fn get_total_files(&self) -> usize {
        self.file_map.values().map(|paths| paths.len()).sum()
    }

    pub fn get_unique_count(&self) -> usize {
        self.file_map.len()
    }

    pub fn get_duplicate_bytes_saved(&self) -> Result<u64> {
        let mut saved = 0u64;

        for (hash, paths) in &self.file_map {
            if paths.len() > 1 {
                if let Ok(metadata) = paths[0].metadata() {
                    saved += metadata.len() * (paths.len() as u64 - 1);
                } else {
                    let _ = hash;
                }
            }
        }

        Ok(saved)
    }

    pub fn clear(&mut self) {
        self.full_hashes.clear();
        self.file_map.clear();
        self.partial_hashes.clear();
    }

    pub fn hash_file(file_path: &Path) -> Result<String> {
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

    fn compute_partial_hash(&self, file_path: &Path) -> Result<String> {
        let mut file = File::open(file_path)?;
        let file_size = file.metadata()?.len() as usize;
        let read_size = std::cmp::min(self.partial_size, file_size);
        let mut buffer = vec![0u8; read_size];
        file.read_exact(&mut buffer)?;

        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        let size_bytes = (file_size as u64).to_le_bytes();
        hasher.update(&size_bytes);

        Ok(hex::encode(hasher.finalize()))
    }

    fn compute_full_hash(&self, file_path: &Path) -> Result<String> {
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
}

impl Default for DeduplicationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_engine_creation() {
        let engine = DeduplicationEngine::new();
        assert_eq!(engine.get_total_files(), 0);
        assert_eq!(engine.get_unique_count(), 0);
        assert_eq!(engine.get_duplicate_count(), 0);
    }

    #[test]
    fn test_with_partial_size() {
        let engine = DeduplicationEngine::new().with_partial_size(2048);
        assert_eq!(engine.partial_size, 2048);
    }

    #[test]
    fn test_default() {
        let engine = DeduplicationEngine::default();
        assert_eq!(engine.get_total_files(), 0);
    }

    #[test]
    fn test_record_single_file() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "test.txt", b"hello world");

        let mut engine = DeduplicationEngine::new();
        let hash = engine.record_file(&path).unwrap();

        assert_eq!(hash.len(), 64);
        assert_eq!(engine.get_total_files(), 1);
        assert_eq!(engine.get_unique_count(), 1);
        assert_eq!(engine.get_duplicate_count(), 0);
    }

    #[test]
    fn test_record_duplicate_files() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"same content");
        let path2 = write_test_file(dir.path(), "file2.txt", b"same content");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path1).unwrap();
        engine.record_file(&path2).unwrap();

        assert_eq!(engine.get_total_files(), 2);
        assert_eq!(engine.get_unique_count(), 1);
        assert_eq!(engine.get_duplicate_count(), 1);
    }

    #[test]
    fn test_record_unique_files() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"content A");
        let path2 = write_test_file(dir.path(), "file2.txt", b"content B");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path1).unwrap();
        engine.record_file(&path2).unwrap();

        assert_eq!(engine.get_total_files(), 2);
        assert_eq!(engine.get_unique_count(), 2);
        assert_eq!(engine.get_duplicate_count(), 0);
    }

    #[test]
    fn test_is_duplicate() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "original.txt", b"duplicate content");
        let path2 = write_test_file(dir.path(), "copy.txt", b"duplicate content");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path1).unwrap();

        assert!(engine.is_duplicate(&path2).unwrap());
    }

    #[test]
    fn test_is_not_duplicate() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"content A");
        let path2 = write_test_file(dir.path(), "file2.txt", b"content B");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path1).unwrap();

        assert!(!engine.is_duplicate(&path2).unwrap());
    }

    #[test]
    fn test_is_duplicate_nonexistent() {
        let mut engine = DeduplicationEngine::new();
        let result = engine.is_duplicate(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_check_and_record() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"test data");
        let path2 = write_test_file(dir.path(), "file2.txt", b"test data");

        let mut engine = DeduplicationEngine::new();

        let result1 = engine.check_and_record(&path1).unwrap();
        assert!(!result1.is_duplicate);
        assert!(result1.existing_paths.is_empty());

        let result2 = engine.check_and_record(&path2).unwrap();
        assert!(result2.is_duplicate);
        assert_eq!(result2.existing_paths.len(), 1);
    }

    #[test]
    fn test_get_duplicates() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "a.txt", b"dup content");
        let path2 = write_test_file(dir.path(), "b.txt", b"dup content");
        let path3 = write_test_file(dir.path(), "c.txt", b"unique content");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path1).unwrap();
        engine.record_file(&path2).unwrap();
        engine.record_file(&path3).unwrap();

        let dups = engine.get_duplicates().unwrap();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].1.len(), 2);
    }

    #[test]
    fn test_get_duplicates_empty() {
        let engine = DeduplicationEngine::new();
        let dups = engine.get_duplicates().unwrap();
        assert!(dups.is_empty());
    }

    #[test]
    fn test_get_duplicate_bytes_saved() {
        let dir = TempDir::new().unwrap();
        let content = b"some test content for size calculation";
        let path1 = write_test_file(dir.path(), "file1.txt", content);
        let path2 = write_test_file(dir.path(), "file2.txt", content);

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path1).unwrap();
        engine.record_file(&path2).unwrap();

        let saved = engine.get_duplicate_bytes_saved().unwrap();
        assert_eq!(saved, content.len() as u64);
    }

    #[test]
    fn test_hash_file_static() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "hash_test.txt", b"hash this content");

        let hash1 = DeduplicationEngine::hash_file(&path).unwrap();
        let hash2 = DeduplicationEngine::hash_file(&path).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_hash_file_different_content() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "a.txt", b"content A");
        let path2 = write_test_file(dir.path(), "b.txt", b"content B");

        let hash1 = DeduplicationEngine::hash_file(&path1).unwrap();
        let hash2 = DeduplicationEngine::hash_file(&path2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_clear() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "test.txt", b"content");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path).unwrap();
        assert_eq!(engine.get_total_files(), 1);

        engine.clear();
        assert_eq!(engine.get_total_files(), 0);
        assert_eq!(engine.get_unique_count(), 0);
    }

    #[test]
    fn test_record_same_file_twice() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "test.txt", b"content");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&path).unwrap();
        engine.record_file(&path).unwrap();

        assert_eq!(engine.get_total_files(), 1);
        assert_eq!(engine.get_unique_count(), 1);
    }

    #[test]
    fn test_multiple_duplicate_groups() {
        let dir = TempDir::new().unwrap();
        let p1 = write_test_file(dir.path(), "a1.txt", b"group A");
        let p2 = write_test_file(dir.path(), "a2.txt", b"group A");
        let p3 = write_test_file(dir.path(), "b1.txt", b"group B");
        let p4 = write_test_file(dir.path(), "b2.txt", b"group B");
        let p5 = write_test_file(dir.path(), "b3.txt", b"group B");

        let mut engine = DeduplicationEngine::new();
        engine.record_file(&p1).unwrap();
        engine.record_file(&p2).unwrap();
        engine.record_file(&p3).unwrap();
        engine.record_file(&p4).unwrap();
        engine.record_file(&p5).unwrap();

        assert_eq!(engine.get_total_files(), 5);
        assert_eq!(engine.get_unique_count(), 2);
        assert_eq!(engine.get_duplicate_count(), 2);

        let dups = engine.get_duplicates().unwrap();
        assert_eq!(dups.len(), 2);
        assert_eq!(dups[0].1.len(), 3);
        assert_eq!(dups[1].1.len(), 2);
    }
}
