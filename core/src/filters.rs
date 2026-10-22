use crate::{RecoveredFile, FileSignature};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFilter {
    pub file_types: Vec<String>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub name_pattern: Option<String>,
    pub categories: Vec<String>,
    pub exclude_extensions: Vec<String>,
    pub exclude_paths: Vec<String>,
}

impl RecoveryFilter {
    pub fn new() -> Self {
        Self {
            file_types: Vec::new(),
            min_size: None,
            max_size: None,
            date_range: None,
            name_pattern: None,
            categories: Vec::new(),
            exclude_extensions: Vec::new(),
            exclude_paths: Vec::new(),
        }
    }

    pub fn builder() -> RecoveryFilterBuilder {
        RecoveryFilterBuilder::new()
    }

    pub fn file_type(mut self, ext: &str) -> Self {
        self.file_types.push(ext.to_lowercase());
        self
    }

    pub fn file_types(mut self, exts: &[&str]) -> Self {
        self.file_types.extend(exts.iter().map(|e| e.to_lowercase()));
        self
    }

    pub fn category(mut self, cat: &str) -> Self {
        self.categories.push(cat.to_string());
        self
    }

    pub fn categories(mut self, cats: &[&str]) -> Self {
        self.categories.extend(cats.iter().map(|c| c.to_string()));
        self
    }

    pub fn min_size(mut self, size: u64) -> Self {
        self.min_size = Some(size);
        self
    }

    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }

    pub fn size_range(mut self, min: u64, max: u64) -> Self {
        self.min_size = Some(min);
        self.max_size = Some(max);
        self
    }

    pub fn date_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.date_range = Some((start, end));
        self
    }

    pub fn name_pattern(mut self, pattern: &str) -> Self {
        self.name_pattern = Some(pattern.to_string());
        self
    }

    pub fn exclude_extension(mut self, ext: &str) -> Self {
        self.exclude_extensions.push(ext.to_lowercase());
        self
    }

    pub fn exclude_extensions(mut self, exts: &[&str]) -> Self {
        self.exclude_extensions.extend(exts.iter().map(|e| e.to_lowercase()));
        self
    }

    pub fn exclude_path(mut self, path: &str) -> Self {
        self.exclude_paths.push(path.to_string());
        self
    }

    pub fn exclude_paths(mut self, paths: &[&str]) -> Self {
        self.exclude_paths.extend(paths.iter().map(|p| p.to_string()));
        self
    }

    pub fn matches_file(&self, file: &RecoveredFile) -> bool {
        if !self.file_types.is_empty() {
            let ext_lower = file.extension.to_lowercase();
            if !self.file_types.iter().any(|ft| *ft == ext_lower) {
                return false;
            }
        }

        if !self.categories.is_empty() {
            let cat_lower = file.file_type.to_lowercase();
            if !self.categories.iter().any(|c| c.to_lowercase() == cat_lower) {
                return false;
            }
        }

        if let Some(min) = self.min_size {
            if file.file_size < min {
                return false;
            }
        }

        if let Some(max) = self.max_size {
            if file.file_size > max {
                return false;
            }
        }

        if let Some((start, end)) = &self.date_range {
            if let Some(ref meta) = file.metadata {
                if let Some(modified) = meta.modified {
                    if modified < *start || modified > *end {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref pattern) = self.name_pattern {
            let name = file.original_name.as_deref().unwrap_or("");
            if !glob_match(pattern, name) {
                return false;
            }
        }

        let ext_lower = file.extension.to_lowercase();
        if self.exclude_extensions.iter().any(|e| *e == ext_lower) {
            return false;
        }

        let path = &file.recovered_path;
        if self.exclude_paths.iter().any(|p| path.contains(p.as_str())) {
            return false;
        }

        true
    }

    pub fn matches_signature(&self, sig: &FileSignature) -> bool {
        if !self.file_types.is_empty() {
            let ext_lower = sig.extension.to_lowercase();
            if !self.file_types.iter().any(|ft| *ft == ext_lower) {
                return false;
            }
        }

        if !self.categories.is_empty() {
            let cat_lower = sig.category.to_lowercase();
            if !self.categories.iter().any(|c| c.to_lowercase() == cat_lower) {
                return false;
            }
        }

        true
    }

    pub fn is_empty(&self) -> bool {
        self.file_types.is_empty()
            && self.min_size.is_none()
            && self.max_size.is_none()
            && self.date_range.is_none()
            && self.name_pattern.is_none()
            && self.categories.is_empty()
            && self.exclude_extensions.is_empty()
            && self.exclude_paths.is_empty()
    }

    pub fn filter_files<'a>(&self, files: &'a [RecoveredFile]) -> Vec<&'a RecoveredFile> {
        files.iter().filter(|f| self.matches_file(f)).collect()
    }

    pub fn filter_signatures<'a>(&self, sigs: &'a [FileSignature]) -> Vec<&'a FileSignature> {
        sigs.iter().filter(|s| self.matches_signature(s)).collect()
    }
}

impl Default for RecoveryFilter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RecoveryFilterBuilder {
    filter: RecoveryFilter,
}

impl RecoveryFilterBuilder {
    pub fn new() -> Self {
        Self {
            filter: RecoveryFilter::new(),
        }
    }

    pub fn file_type(mut self, ext: &str) -> Self {
        self.filter.file_types.push(ext.to_lowercase());
        self
    }

    pub fn file_types(mut self, exts: &[&str]) -> Self {
        self.filter.file_types.extend(exts.iter().map(|e| e.to_lowercase()));
        self
    }

    pub fn category(mut self, cat: &str) -> Self {
        self.filter.categories.push(cat.to_string());
        self
    }

    pub fn categories(mut self, cats: &[&str]) -> Self {
        self.filter.categories.extend(cats.iter().map(|c| c.to_string()));
        self
    }

    pub fn min_size(mut self, size: u64) -> Self {
        self.filter.min_size = Some(size);
        self
    }

    pub fn max_size(mut self, size: u64) -> Self {
        self.filter.max_size = Some(size);
        self
    }

    pub fn size_range(mut self, min: u64, max: u64) -> Self {
        self.filter.min_size = Some(min);
        self.filter.max_size = Some(max);
        self
    }

    pub fn date_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.filter.date_range = Some((start, end));
        self
    }

    pub fn name_pattern(mut self, pattern: &str) -> Self {
        self.filter.name_pattern = Some(pattern.to_string());
        self
    }

    pub fn exclude_extension(mut self, ext: &str) -> Self {
        self.filter.exclude_extensions.push(ext.to_lowercase());
        self
    }

    pub fn exclude_extensions(mut self, exts: &[&str]) -> Self {
        self.filter.exclude_extensions.extend(exts.iter().map(|e| e.to_lowercase()));
        self
    }

    pub fn exclude_path(mut self, path: &str) -> Self {
        self.filter.exclude_paths.push(path.to_string());
        self
    }

    pub fn exclude_paths(mut self, paths: &[&str]) -> Self {
        self.filter.exclude_paths.extend(paths.iter().map(|p| p.to_string()));
        self
    }

    pub fn build(self) -> RecoveryFilter {
        self.filter
    }
}

impl Default for RecoveryFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    let text_bytes = text.as_bytes();
    glob_match_impl(pattern_bytes, text_bytes)
}

fn glob_match_impl(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_p = None;
    let mut star_t = None;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_p = Some(pi);
            star_t = Some(ti);
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            let st = star_t.unwrap() + 1;
            star_t = Some(st);
            ti = st;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RecoveryStatus, IntegrityStatus, ThreatStatus};

    fn make_file(ext: &str, size: u64, name: Option<&str>) -> RecoveredFile {
        let mut f = RecoveredFile::new("sess-1", "/tmp/test");
        f.extension = ext.to_string();
        f.file_size = size;
        f.file_type = "Test".to_string();
        f.original_name = name.map(|n| n.to_string());
        f.status = RecoveryStatus::Completed;
        f.integrity_check = IntegrityStatus::Verified;
        f.threat_scan = ThreatStatus::Clean;
        f
    }

    fn make_sig(ext: &str, category: &str) -> FileSignature {
        FileSignature {
            extension: ext.to_string(),
            magic_bytes: vec![0x00],
            offset: 0,
            description: "Test".to_string(),
            category: category.to_string(),
        }
    }

    #[test]
    fn test_empty_filter_matches_all() {
        let filter = RecoveryFilter::new();
        let file = make_file("jpg", 1000, Some("photo.jpg"));
        assert!(filter.matches_file(&file));
    }

    #[test]
    fn test_file_type_filter() {
        let filter = RecoveryFilter::new().file_type("jpg");
        let jpg = make_file("jpg", 1000, Some("photo.jpg"));
        let png = make_file("png", 1000, Some("image.png"));
        assert!(filter.matches_file(&jpg));
        assert!(!filter.matches_file(&png));
    }

    #[test]
    fn test_multiple_file_types() {
        let filter = RecoveryFilter::new().file_types(&["jpg", "png", "gif"]);
        let jpg = make_file("jpg", 1000, None);
        let png = make_file("png", 1000, None);
        let gif = make_file("gif", 1000, None);
        let txt = make_file("txt", 1000, None);
        assert!(filter.matches_file(&jpg));
        assert!(filter.matches_file(&png));
        assert!(filter.matches_file(&gif));
        assert!(!filter.matches_file(&txt));
    }

    #[test]
    fn test_min_size_filter() {
        let filter = RecoveryFilter::new().min_size(500);
        let big = make_file("jpg", 1000, None);
        let small = make_file("jpg", 100, None);
        assert!(filter.matches_file(&big));
        assert!(!filter.matches_file(&small));
    }

    #[test]
    fn test_max_size_filter() {
        let filter = RecoveryFilter::new().max_size(500);
        let big = make_file("jpg", 1000, None);
        let small = make_file("jpg", 100, None);
        assert!(!filter.matches_file(&big));
        assert!(filter.matches_file(&small));
    }

    #[test]
    fn test_size_range_filter() {
        let filter = RecoveryFilter::new().size_range(100, 500);
        let in_range = make_file("jpg", 300, None);
        let too_small = make_file("jpg", 50, None);
        let too_big = make_file("jpg", 1000, None);
        assert!(filter.matches_file(&in_range));
        assert!(!filter.matches_file(&too_small));
        assert!(!filter.matches_file(&too_big));
    }

    #[test]
    fn test_name_pattern_filter() {
        let filter = RecoveryFilter::new().name_pattern("*.jpg");
        let match1 = make_file("jpg", 1000, Some("photo.jpg"));
        let match2 = make_file("jpg", 1000, Some("vacation.jpg"));
        let no_match = make_file("png", 1000, Some("image.png"));
        assert!(filter.matches_file(&match1));
        assert!(filter.matches_file(&match2));
        assert!(!filter.matches_file(&no_match));
    }

    #[test]
    fn test_name_pattern_wildcard() {
        let filter = RecoveryFilter::new().name_pattern("report_*");
        let match1 = make_file("pdf", 1000, Some("report_2024.pdf"));
        let no_match = make_file("pdf", 1000, Some("invoice.pdf"));
        assert!(filter.matches_file(&match1));
        assert!(!filter.matches_file(&no_match));
    }

    #[test]
    fn test_name_pattern_no_name() {
        let filter = RecoveryFilter::new().name_pattern("*.jpg");
        let file = make_file("jpg", 1000, None);
        assert!(!filter.matches_file(&file));
    }

    #[test]
    fn test_exclude_extension() {
        let filter = RecoveryFilter::new().exclude_extension("exe");
        let jpg = make_file("jpg", 1000, None);
        let exe = make_file("exe", 1000, None);
        assert!(filter.matches_file(&jpg));
        assert!(!filter.matches_file(&exe));
    }

    #[test]
    fn test_exclude_paths() {
        let filter = RecoveryFilter::new().exclude_path("/tmp/quarantine");
        let mut ok_file = make_file("jpg", 1000, None);
        ok_file.recovered_path = "/output/photo.jpg".to_string();
        let mut bad_file = make_file("jpg", 1000, None);
        bad_file.recovered_path = "/tmp/quarantine/bad.exe".to_string();
        assert!(filter.matches_file(&ok_file));
        assert!(!filter.matches_file(&bad_file));
    }

    #[test]
    fn test_combined_filters() {
        let filter = RecoveryFilter::new()
            .file_types(&["jpg", "png"])
            .min_size(100)
            .max_size(10000)
            .exclude_extension("exe");

        let match1 = make_file("jpg", 500, None);
        let too_big = make_file("jpg", 20000, None);
        let wrong_type = make_file("txt", 500, None);
        assert!(filter.matches_file(&match1));
        assert!(!filter.matches_file(&too_big));
        assert!(!filter.matches_file(&wrong_type));
    }

    #[test]
    fn test_matches_signature() {
        let filter = RecoveryFilter::new().file_type("jpg").category("Image");
        let jpg_sig = make_sig("jpg", "Image");
        let png_sig = make_sig("png", "Image");
        let pdf_sig = make_sig("pdf", "Document");
        assert!(filter.matches_signature(&jpg_sig));
        assert!(!filter.matches_signature(&png_sig));
        assert!(!filter.matches_signature(&pdf_sig));
    }

    #[test]
    fn test_matches_signature_category_only() {
        let filter = RecoveryFilter::new().category("Image");
        let jpg_sig = make_sig("jpg", "Image");
        let png_sig = make_sig("png", "Image");
        let pdf_sig = make_sig("pdf", "Document");
        assert!(filter.matches_signature(&jpg_sig));
        assert!(filter.matches_signature(&png_sig));
        assert!(!filter.matches_signature(&pdf_sig));
    }

    #[test]
    fn test_builder_pattern() {
        let filter = RecoveryFilter::builder()
            .file_type("jpg")
            .file_type("png")
            .min_size(100)
            .max_size(5000)
            .category("Image")
            .exclude_extension("exe")
            .name_pattern("*.jpg")
            .build();

        assert_eq!(filter.file_types, vec!["jpg", "png"]);
        assert_eq!(filter.min_size, Some(100));
        assert_eq!(filter.max_size, Some(5000));
        assert_eq!(filter.categories, vec!["Image"]);
        assert_eq!(filter.exclude_extensions, vec!["exe"]);
        assert_eq!(filter.name_pattern, Some("*.jpg".to_string()));
    }

    #[test]
    fn test_builder_with_multiple() {
        let filter = RecoveryFilter::builder()
            .file_types(&["jpg", "png", "gif"])
            .categories(&["Image", "Video"])
            .exclude_extensions(&["exe", "bat", "cmd"])
            .exclude_paths(&["/tmp/quarantine", "/tmp/virus"])
            .build();

        assert_eq!(filter.file_types.len(), 3);
        assert_eq!(filter.categories.len(), 2);
        assert_eq!(filter.exclude_extensions.len(), 3);
        assert_eq!(filter.exclude_paths.len(), 2);
    }

    #[test]
    fn test_is_empty() {
        assert!(RecoveryFilter::new().is_empty());
        assert!(!RecoveryFilter::new().file_type("jpg").is_empty());
        assert!(!RecoveryFilter::new().min_size(100).is_empty());
        assert!(!RecoveryFilter::new().max_size(100).is_empty());
        assert!(!RecoveryFilter::new().category("Image").is_empty());
        assert!(!RecoveryFilter::new().exclude_extension("exe").is_empty());
        assert!(!RecoveryFilter::new().name_pattern("*").is_empty());
    }

    #[test]
    fn test_filter_files() {
        let files = vec![
            make_file("jpg", 500, None),
            make_file("png", 1500, None),
            make_file("txt", 200, None),
            make_file("jpg", 100, None),
        ];

        let filter = RecoveryFilter::new().file_type("jpg").min_size(200);
        let result = filter.filter_files(&files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_size, 500);
    }

    #[test]
    fn test_filter_signatures() {
        let sigs = vec![
            make_sig("jpg", "Image"),
            make_sig("png", "Image"),
            make_sig("pdf", "Document"),
        ];

        let filter = RecoveryFilter::new().category("Image");
        let result = filter.filter_signatures(&sigs);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_glob_match_basic() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.jpg", "photo.jpg"));
        assert!(!glob_match("*.jpg", "photo.png"));
        assert!(glob_match("report_*", "report_2024"));
        assert!(glob_match("*.*", "file.txt"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("file?.txt", "file1.txt"));
        assert!(glob_match("file?.txt", "fileA.txt"));
        assert!(!glob_match("file?.txt", "file12.txt"));
    }

    #[test]
    fn test_glob_match_combined() {
        assert!(glob_match("*photo*", "my_photo_2024.jpg"));
        assert!(glob_match("*.????.jpg", "file.2024.jpg"));
        assert!(!glob_match("*.????.jpg", "file.24.jpg"));
    }

    #[test]
    fn test_glob_match_empty() {
        assert!(glob_match("", ""));
        assert!(glob_match("*", ""));
        assert!(!glob_match("?", ""));
    }

    #[test]
    fn test_default() {
        let filter = RecoveryFilter::default();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_builder_default() {
        let filter = RecoveryFilterBuilder::default().build();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_case_insensitive_file_types() {
        let filter = RecoveryFilter::new().file_type("JPG");
        let file = make_file("jpg", 1000, None);
        assert!(filter.matches_file(&file));
    }
}
