use crate::{Result, Error};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use tracing::debug;
use serde::{Deserialize, Serialize};

const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "md", "csv", "json", "xml", "html", "css", "js", "ts", "rs", "py",
    "java", "c", "cpp", "h", "hpp", "go", "rb", "php", "sh", "bash", "yaml",
    "yml", "toml", "ini", "cfg", "conf", "log", "sql", "r", "swift", "kt",
];

const IMAGE_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "bmp", "gif", "tiff", "tif", "webp", "ico",
];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Custom(f64),
}

impl Sensitivity {
    pub fn threshold(&self) -> f64 {
        match self {
            Sensitivity::Low => 0.95,
            Sensitivity::Medium => 0.80,
            Sensitivity::High => 0.60,
            Sensitivity::Custom(t) => *t,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub content_fingerprint: ContentFingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentFingerprint {
    Text {
        line_count: usize,
        word_hashes: Vec<u64>,
        char_distribution: Vec<u32>,
    },
    Image {
        perceptual_hash: u64,
        dimensions: Option<(u32, u32)>,
    },
    Binary {
        block_hashes: Vec<String>,
        byte_distribution: Vec<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub representative: FileEntry,
    pub duplicates: Vec<(FileEntry, f64)>,
    pub similarity_score: f64,
}

pub struct SmartDeduplicator {
    files: Vec<FileEntry>,
    sensitivity: Sensitivity,
    groups: Vec<DuplicateGroup>,
}

impl SmartDeduplicator {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            sensitivity: Sensitivity::Medium,
            groups: Vec::new(),
        }
    }

    pub fn with_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    pub fn add_file(&mut self, path: &Path) -> Result<FileEntry> {
        if !path.exists() {
            return Err(Error::Other(format!("File not found: {}", path.display())));
        }

        let metadata = path.metadata()?;
        let hash = Self::compute_hash(path)?;
        let content_fingerprint = Self::compute_fingerprint(path)?;

        let entry = FileEntry {
            path: path.to_path_buf(),
            hash,
            size: metadata.len(),
            content_fingerprint,
        };

        self.files.push(entry.clone());
        debug!("Added file: {} (size: {})", path.display(), metadata.len());

        Ok(entry)
    }

    pub fn find_duplicates(&mut self) -> Result<Vec<DuplicateGroup>> {
        let threshold = self.sensitivity.threshold();
        let mut groups: Vec<DuplicateGroup> = Vec::new();
        let mut assigned: Vec<bool> = vec![false; self.files.len()];

        for i in 0..self.files.len() {
            if assigned[i] {
                continue;
            }

            let mut group_members: Vec<(usize, f64)> = Vec::new();

            for j in (i + 1)..self.files.len() {
                if assigned[j] {
                    continue;
                }

                let similarity = self.compute_similarity(&self.files[i], &self.files[j]);

                if similarity >= threshold {
                    group_members.push((j, similarity));
                }
            }

            if !group_members.is_empty() {
                let representative = self.files[i].clone();
                let avg_similarity = group_members.iter().map(|(_, s)| s).sum::<f64>()
                    / group_members.len() as f64;

                let duplicates: Vec<(FileEntry, f64)> = group_members
                    .iter()
                    .map(|&(idx, sim)| {
                        assigned[idx] = true;
                        (self.files[idx].clone(), sim)
                    })
                    .collect();

                assigned[i] = true;

                groups.push(DuplicateGroup {
                    representative,
                    duplicates,
                    similarity_score: avg_similarity,
                });
            }
        }

        groups.sort_by(|a, b| {
            b.duplicates.len().cmp(&a.duplicates.len())
                .then(b.similarity_score.partial_cmp(&a.similarity_score).unwrap_or(std::cmp::Ordering::Equal))
        });

        self.groups = groups.clone();
        Ok(groups)
    }

    pub fn get_groups(&self) -> &[DuplicateGroup] {
        &self.groups
    }

    pub fn remove_duplicates(&self, dry_run: bool) -> Result<RemovalReport> {
        let mut report = RemovalReport {
            files_to_remove: Vec::new(),
            space_saved: 0,
            dry_run,
        };

        for group in &self.groups {
            for (dup_entry, _similarity) in &group.duplicates {
                report.files_to_remove.push(dup_entry.path.clone());
                report.space_saved += dup_entry.size;
            }
        }

        if !dry_run {
            for path in &report.files_to_remove {
                if path.exists() {
                    std::fs::remove_file(path)?;
                    debug!("Removed duplicate: {}", path.display());
                }
            }
        }

        Ok(report)
    }

    pub fn clear(&mut self) {
        self.files.clear();
        self.groups.clear();
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    fn compute_similarity(&self, a: &FileEntry, b: &FileEntry) -> f64 {
        if a.hash == b.hash {
            return 1.0;
        }

        match (&a.content_fingerprint, &b.content_fingerprint) {
            (ContentFingerprint::Text { .. }, ContentFingerprint::Text { .. }) => {
                self.text_similarity(a, b)
            }
            (ContentFingerprint::Image { .. }, ContentFingerprint::Image { .. }) => {
                self.image_similarity(a, b)
            }
            (ContentFingerprint::Binary { .. }, ContentFingerprint::Binary { .. }) => {
                self.binary_similarity(a, b)
            }
            _ => 0.0,
        }
    }

    fn text_similarity(&self, a: &FileEntry, b: &FileEntry) -> f64 {
        let (a_lines, a_words, a_dist) = match &a.content_fingerprint {
            ContentFingerprint::Text { line_count, word_hashes, char_distribution } => {
                (*line_count, word_hashes, char_distribution)
            }
            _ => return 0.0,
        };

        let (b_lines, b_words, b_dist) = match &b.content_fingerprint {
            ContentFingerprint::Text { line_count, word_hashes, char_distribution } => {
                (*line_count, word_hashes, char_distribution)
            }
            _ => return 0.0,
        };

        let size_ratio = if a.size == 0 && b.size == 0 {
            1.0
        } else if a.size == 0 || b.size == 0 {
            0.0
        } else {
            let min = std::cmp::min(a.size, b.size) as f64;
            let max = std::cmp::max(a.size, b.size) as f64;
            min / max
        };

        let line_ratio = if a_lines == 0 && b_lines == 0 {
            1.0
        } else if a_lines == 0 || b_lines == 0 {
            0.0
        } else {
            let min = std::cmp::min(a_lines, b_lines) as f64;
            let max = std::cmp::max(a_lines, b_lines) as f64;
            min / max
        };

        let char_dist_similarity = self.distribution_similarity(a_dist, b_dist);

        let word_overlap = self.word_set_overlap(a_words, b_words);

        let combined = (size_ratio * 0.2)
            + (line_ratio * 0.15)
            + (char_dist_similarity * 0.25)
            + (word_overlap * 0.4);

        combined
    }
    fn image_similarity(&self, a: &FileEntry, b: &FileEntry) -> f64 {
        let a_hash = match &a.content_fingerprint {
            ContentFingerprint::Image { perceptual_hash, .. } => *perceptual_hash,
            _ => return 0.0,
        };

        let b_hash = match &b.content_fingerprint {
            ContentFingerprint::Image { perceptual_hash, .. } => *perceptual_hash,
            _ => return 0.0,
        };

        let hamming_distance = (a_hash ^ b_hash).count_ones() as f64;
        let max_bits = 64.0;
        let similarity = 1.0 - (hamming_distance / max_bits);

        let size_factor = if a.size == 0 && b.size == 0 {
            1.0
        } else if a.size == 0 || b.size == 0 {
            0.0
        } else {
            let min = std::cmp::min(a.size, b.size) as f64;
            let max = std::cmp::max(a.size, b.size) as f64;
            min / max
        };

        similarity * 0.85 + size_factor * 0.15
    }

    fn binary_similarity(&self, a: &FileEntry, b: &FileEntry) -> f64 {
        let (a_blocks, a_dist) = match &a.content_fingerprint {
            ContentFingerprint::Binary { block_hashes, byte_distribution } => {
                (block_hashes, byte_distribution)
            }
            _ => return 0.0,
        };

        let (b_blocks, b_dist) = match &b.content_fingerprint {
            ContentFingerprint::Binary { block_hashes, byte_distribution } => {
                (block_hashes, byte_distribution)
            }
            _ => return 0.0,
        };

        let block_overlap = self.block_set_overlap(a_blocks, b_blocks);
        let dist_similarity = self.distribution_similarity(a_dist, b_dist);

        let size_ratio = if a.size == 0 && b.size == 0 {
            1.0
        } else if a.size == 0 || b.size == 0 {
            0.0
        } else {
            let min = std::cmp::min(a.size, b.size) as f64;
            let max = std::cmp::max(a.size, b.size) as f64;
            min / max
        };

        block_overlap * 0.5 + dist_similarity * 0.3 + size_ratio * 0.2
    }

    fn distribution_similarity(&self, a: &[u32], b: &[u32]) -> f64 {
        let a_total: f64 = a.iter().sum::<u32>() as f64;
        let b_total: f64 = b.iter().sum::<u32>() as f64;

        if a_total == 0.0 && b_total == 0.0 {
            return 1.0;
        }
        if a_total == 0.0 || b_total == 0.0 {
            return 0.0;
        }

        let mut dot_product = 0.0f64;
        let mut a_magnitude = 0.0f64;
        let mut b_magnitude = 0.0f64;

        for i in 0..256 {
            let a_norm = a[i] as f64 / a_total;
            let b_norm = b[i] as f64 / b_total;
            dot_product += a_norm * b_norm;
            a_magnitude += a_norm * a_norm;
            b_magnitude += b_norm * b_norm;
        }

        let denominator = a_magnitude.sqrt() * b_magnitude.sqrt();
        if denominator == 0.0 {
            return 0.0;
        }

        dot_product / denominator
    }

    fn word_set_overlap(&self, a: &[u64], b: &[u64]) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 1.0;
        }
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }

        let set_a: HashSet<u64> = a.iter().copied().collect();
        let set_b: HashSet<u64> = b.iter().copied().collect();

        let intersection = set_a.intersection(&set_b).count() as f64;
        let union = set_a.union(&set_b).count() as f64;

        if union == 0.0 {
            return 1.0;
        }

        intersection / union
    }

    fn block_set_overlap(&self, a: &[String], b: &[String]) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 1.0;
        }
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }

        let set_a: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
        let set_b: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();

        let intersection = set_a.intersection(&set_b).count() as f64;
        let union = set_a.union(&set_b).count() as f64;

        if union == 0.0 {
            return 1.0;
        }

        intersection / union
    }

    fn compute_hash(path: &Path) -> Result<String> {
        let mut file = File::open(path)?;
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

    fn compute_fingerprint(path: &Path) -> Result<ContentFingerprint> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if TEXT_EXTENSIONS.contains(&ext.as_str()) {
            Self::compute_text_fingerprint(path)
        } else if IMAGE_EXTENSIONS.contains(&ext.as_str()) {
            Self::compute_image_fingerprint(path)
        } else {
            Self::compute_binary_fingerprint(path)
        }
    }

    fn compute_text_fingerprint(path: &Path) -> Result<ContentFingerprint> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let line_count = content.lines().count();

        let word_hashes: Vec<u64> = content
            .split_whitespace()
            .map(|word| {
                let mut hasher = Sha256::new();
                hasher.update(word.to_lowercase().as_bytes());
                let result = hasher.finalize();
                u64::from_le_bytes(result[0..8].try_into().unwrap_or([0; 8]))
            })
            .collect();

        let mut char_distribution = vec![0u32; 256];
        for byte in content.bytes() {
            char_distribution[byte as usize] += 1;
        }

        Ok(ContentFingerprint::Text {
            line_count,
            word_hashes,
            char_distribution,
        })
    }

    fn compute_image_fingerprint(path: &Path) -> Result<ContentFingerprint> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let perceptual_hash = Self::compute_average_hash(&buffer);

        Ok(ContentFingerprint::Image {
            perceptual_hash,
            dimensions: None,
        })
    }

    fn compute_average_hash(data: &[u8]) -> u64 {
        let size = 8;
        let total_pixels = size * size;
        let mut pixels = vec![0u8; total_pixels];

        let chunk_size = if data.len() >= total_pixels {
            data.len() / total_pixels
        } else {
            1
        };

        for i in 0..total_pixels {
            let start = i * chunk_size;
            if start < data.len() {
                let end = std::cmp::min(start + chunk_size, data.len());
                let sum: u32 = data[start..end].iter().map(|&b| b as u32).sum();
                pixels[i] = (sum / (end - start) as u32) as u8;
            }
        }

        let avg: u32 = pixels.iter().map(|&p| p as u32).sum::<u32>() / total_pixels as u32;

        let mut hash: u64 = 0;
        for (i, &pixel) in pixels.iter().enumerate() {
            if pixel as u32 > avg {
                hash |= 1 << i;
            }
        }

        hash
    }

    fn compute_binary_fingerprint(path: &Path) -> Result<ContentFingerprint> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let block_size = 4096;
        let block_count = std::cmp::min((file_size / block_size) + 1, 64);

        let mut block_hashes = Vec::with_capacity(block_count);
        let mut byte_distribution = vec![0u32; 256];
        let mut buffer = vec![0u8; block_size];

        for i in 0..block_count {
            let offset = if file_size <= block_count * block_size {
                i * block_size
            } else {
                (i * (file_size - block_size)) / (block_count - 1).max(1)
            };

            use std::io::Seek;
            file.seek(std::io::SeekFrom::Start(offset as u64))?;
            let bytes_read = file.read(&mut buffer)?;

            if bytes_read > 0 {
                let mut hasher = Sha256::new();
                hasher.update(&buffer[..bytes_read]);
                block_hashes.push(hex::encode(hasher.finalize()));

                for &byte in &buffer[..bytes_read] {
                    byte_distribution[byte as usize] += 1;
                }
            }
        }

        Ok(ContentFingerprint::Binary {
            block_hashes,
            byte_distribution,
        })
    }
}

impl Default for SmartDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalReport {
    pub files_to_remove: Vec<PathBuf>,
    pub space_saved: u64,
    pub dry_run: bool,
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
    fn test_deduplicator_creation() {
        let dedup = SmartDeduplicator::new();
        assert_eq!(dedup.file_count(), 0);
        assert_eq!(dedup.group_count(), 0);
    }

    #[test]
    fn test_with_sensitivity() {
        let dedup = SmartDeduplicator::new().with_sensitivity(Sensitivity::High);
        assert_eq!(dedup.sensitivity.threshold(), 0.60);
    }

    #[test]
    fn test_sensitivity_thresholds() {
        assert_eq!(Sensitivity::Low.threshold(), 0.95);
        assert_eq!(Sensitivity::Medium.threshold(), 0.80);
        assert_eq!(Sensitivity::High.threshold(), 0.60);
        assert_eq!(Sensitivity::Custom(0.75).threshold(), 0.75);
    }

    #[test]
    fn test_add_file() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "test.txt", b"hello world");

        let mut dedup = SmartDeduplicator::new();
        let entry = dedup.add_file(&path).unwrap();

        assert_eq!(entry.path, path);
        assert_eq!(entry.size, 11);
        assert_eq!(dedup.file_count(), 1);
    }

    #[test]
    fn test_add_nonexistent_file() {
        let mut dedup = SmartDeduplicator::new();
        let result = dedup.add_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_identical_text_files() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"identical content");
        let path2 = write_test_file(dir.path(), "file2.txt", b"identical content");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].duplicates.len(), 1);
        assert_eq!(groups[0].similarity_score, 1.0);
    }

    #[test]
    fn test_similar_text_files() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(
            dir.path(),
            "file1.txt",
            b"The quick brown fox jumps over the lazy dog",
        );
        let path2 = write_test_file(
            dir.path(),
            "file2.txt",
            b"The quick brown fox jumps over the lazy cat",
        );

        let mut dedup = SmartDeduplicator::new().with_sensitivity(Sensitivity::High);
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert!(!groups.is_empty());
        assert!(groups[0].similarity_score > 0.6);
    }

    #[test]
    fn test_different_text_files() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"Completely different");
        let path2 = write_test_file(dir.path(), "file2.txt", b"Another unique file");

        let mut dedup = SmartDeduplicator::new().with_sensitivity(Sensitivity::High);
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn test_identical_binary_files() {
        let dir = TempDir::new().unwrap();
        let content: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let path1 = write_test_file(dir.path(), "file1.bin", &content);
        let path2 = write_test_file(dir.path(), "file2.bin", &content);

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].similarity_score, 1.0);
    }

    #[test]
    fn test_multiple_groups() {
        let dir = TempDir::new().unwrap();
        let p1 = write_test_file(dir.path(), "a1.txt", b"Group A content");
        let p2 = write_test_file(dir.path(), "a2.txt", b"Group A content");
        let p3 = write_test_file(dir.path(), "b1.txt", b"Group B content");
        let p4 = write_test_file(dir.path(), "b2.txt", b"Group B content");
        let p5 = write_test_file(dir.path(), "unique.txt", b"Unique content here");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&p1).unwrap();
        dedup.add_file(&p2).unwrap();
        dedup.add_file(&p3).unwrap();
        dedup.add_file(&p4).unwrap();
        dedup.add_file(&p5).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(dedup.group_count(), 2);
    }

    #[test]
    fn test_removal_report_dry_run() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "original.txt", b"duplicate content");
        let path2 = write_test_file(dir.path(), "copy.txt", b"duplicate content");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();
        dedup.find_duplicates().unwrap();

        let report = dedup.remove_duplicates(true).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.files_to_remove.len(), 1);
        assert!(path1.exists());
        assert!(path2.exists());
    }

    #[test]
    fn test_removal_report_actual() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "original.txt", b"duplicate content");
        let path2 = write_test_file(dir.path(), "copy.txt", b"duplicate content");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();
        dedup.find_duplicates().unwrap();

        let report = dedup.remove_duplicates(false).unwrap();
        assert!(!report.dry_run);
        assert_eq!(report.files_to_remove.len(), 1);
        assert!(path1.exists());
        assert!(!path2.exists());
    }

    #[test]
    fn test_clear() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "test.txt", b"content");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path).unwrap();
        assert_eq!(dedup.file_count(), 1);

        dedup.clear();
        assert_eq!(dedup.file_count(), 0);
        assert_eq!(dedup.group_count(), 0);
    }

    #[test]
    fn test_text_fingerprint() {
        let dir = TempDir::new().unwrap();
        let path = write_test_file(dir.path(), "test.txt", b"line1\nline2\nline3");

        let mut dedup = SmartDeduplicator::new();
        let entry = dedup.add_file(&path).unwrap();

        match &entry.content_fingerprint {
            ContentFingerprint::Text { line_count, word_hashes, .. } => {
                assert_eq!(*line_count, 3);
                assert!(!word_hashes.is_empty());
            }
            _ => panic!("Expected Text fingerprint"),
        }
    }

    #[test]
    fn test_binary_fingerprint() {
        let dir = TempDir::new().unwrap();
        let content: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let path = write_test_file(dir.path(), "test.bin", &content);

        let mut dedup = SmartDeduplicator::new();
        let entry = dedup.add_file(&path).unwrap();

        match &entry.content_fingerprint {
            ContentFingerprint::Binary { block_hashes, byte_distribution } => {
                assert!(!block_hashes.is_empty());
                assert!(byte_distribution.iter().any(|&c| c > 0));
            }
            _ => panic!("Expected Binary fingerprint"),
        }
    }

    #[test]
    fn test_image_fingerprint() {
        let dir = TempDir::new().unwrap();
        let fake_image: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let path = write_test_file(dir.path(), "test.png", &fake_image);

        let mut dedup = SmartDeduplicator::new();
        let entry = dedup.add_file(&path).unwrap();

        match &entry.content_fingerprint {
            ContentFingerprint::Image { perceptual_hash, .. } => {
                assert_ne!(*perceptual_hash, 0);
            }
            _ => panic!("Expected Image fingerprint"),
        }
    }

    #[test]
    fn test_distribution_similarity_identical() {
        let dedup = SmartDeduplicator::new();
        let dist = vec![10u32; 256];
        let similarity = dedup.distribution_similarity(&dist, &dist);
        assert!((similarity - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_distribution_similarity_different() {
        let dedup = SmartDeduplicator::new();
        let dist_a = vec![10u32; 256];
        let mut dist_b = vec![0u32; 256];
        dist_b[0] = 2560;
        let similarity = dedup.distribution_similarity(&dist_a, &dist_b);
        assert!(similarity < 0.5);
    }

    #[test]
    fn test_word_set_overlap_identical() {
        let dedup = SmartDeduplicator::new();
        let words = vec![1u64, 2, 3, 4, 5];
        let overlap = dedup.word_set_overlap(&words, &words);
        assert!((overlap - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_word_set_overlap_disjoint() {
        let dedup = SmartDeduplicator::new();
        let words_a = vec![1u64, 2, 3];
        let words_b = vec![4u64, 5, 6];
        let overlap = dedup.word_set_overlap(&words_a, &words_b);
        assert!(overlap < 0.001);
    }

    #[test]
    fn test_average_hash_consistency() {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let hash1 = SmartDeduplicator::compute_average_hash(&data);
        let hash2 = SmartDeduplicator::compute_average_hash(&data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sensitivity_affects_grouping() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(
            dir.path(),
            "file1.txt",
            b"The quick brown fox jumps over the lazy dog and runs away",
        );
        let path2 = write_test_file(
            dir.path(),
            "file2.txt",
            b"The quick brown fox jumps over the lazy cat and runs away quickly",
        );

        let mut dedup_low = SmartDeduplicator::new().with_sensitivity(Sensitivity::Low);
        dedup_low.add_file(&path1).unwrap();
        dedup_low.add_file(&path2).unwrap();
        let groups_low = dedup_low.find_duplicates().unwrap();

        let mut dedup_high = SmartDeduplicator::new().with_sensitivity(Sensitivity::High);
        dedup_high.add_file(&path1).unwrap();
        dedup_high.add_file(&path2).unwrap();
        let groups_high = dedup_high.find_duplicates().unwrap();

        assert!(groups_high.len() >= groups_low.len());
    }

    #[test]
    fn test_empty_files() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "empty1.txt", b"");
        let path2 = write_test_file(dir.path(), "empty2.txt", b"");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].similarity_score, 1.0);
    }

    #[test]
    fn test_large_file() {
        let dir = TempDir::new().unwrap();
        let content: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let path1 = write_test_file(dir.path(), "large1.bin", &content);
        let path2 = write_test_file(dir.path(), "large2.bin", &content);

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        let groups = dedup.find_duplicates().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].similarity_score, 1.0);
    }

    #[test]
    fn test_get_groups() {
        let dir = TempDir::new().unwrap();
        let path1 = write_test_file(dir.path(), "file1.txt", b"same content");
        let path2 = write_test_file(dir.path(), "file2.txt", b"same content");

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();

        assert!(dedup.get_groups().is_empty());

        dedup.find_duplicates().unwrap();

        assert_eq!(dedup.get_groups().len(), 1);
    }

    #[test]
    fn test_space_saved_calculation() {
        let dir = TempDir::new().unwrap();
        let content = b"some content for size calculation";
        let path1 = write_test_file(dir.path(), "file1.txt", content);
        let path2 = write_test_file(dir.path(), "file2.txt", content);

        let mut dedup = SmartDeduplicator::new();
        dedup.add_file(&path1).unwrap();
        dedup.add_file(&path2).unwrap();
        dedup.find_duplicates().unwrap();

        let report = dedup.remove_duplicates(true).unwrap();
        assert_eq!(report.space_saved, content.len() as u64);
    }
}
