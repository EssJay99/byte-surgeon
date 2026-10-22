use crate::error::{SdkError, SdkResult};
use datadoctor_core::{
    SignatureDatabase, SignatureEntry, SignatureCategory,
    FileSignature,
    scanner::MmapScanner,
};

pub struct SignatureScanner {
    db: SignatureDatabase,
    categories: Vec<SignatureCategory>,
    extensions: Vec<String>,
}

impl SignatureScanner {
    pub fn new() -> Self {
        Self {
            db: SignatureDatabase::new(),
            categories: Vec::new(),
            extensions: Vec::new(),
        }
    }

    pub fn category(mut self, cat: SignatureCategory) -> Self {
        self.categories.push(cat);
        self
    }

    pub fn categories(mut self, cats: &[SignatureCategory]) -> Self {
        self.categories.extend(cats.iter().cloned());
        self
    }

    pub fn extension(mut self, ext: &str) -> Self {
        self.extensions.push(ext.to_lowercase());
        self
    }

    pub fn extensions(mut self, exts: &[&str]) -> Self {
        self.extensions.extend(exts.iter().map(|e| e.to_lowercase()));
        self
    }

    pub fn images_only(self) -> Self {
        self.category(SignatureCategory::Image)
    }

    pub fn documents_only(self) -> Self {
        self.category(SignatureCategory::Document)
    }

    pub fn videos_only(self) -> Self {
        self.category(SignatureCategory::Video)
    }

    pub fn audio_only(self) -> Self {
        self.category(SignatureCategory::Audio)
    }

    pub fn archives_only(self) -> Self {
        self.category(SignatureCategory::Archive)
    }

    pub fn signatures(&self) -> Vec<FileSignature> {
        let all_entries = self.filtered_entries();
        all_entries
            .iter()
            .map(|e| FileSignature {
                extension: e.extension.clone(),
                magic_bytes: e.magic_bytes.clone(),
                offset: e.offset,
                description: e.description.clone(),
                category: e.category.as_str().to_string(),
            })
            .collect()
    }

    pub fn scan_path(&self, path: &str) -> SdkResult<Vec<ScanHit>> {
        let sigs = self.signatures();
        if sigs.is_empty() {
            return Err(SdkError::InvalidArgument(
                "No signatures selected for scanning".into(),
            ));
        }

        let scanner = MmapScanner::with_signatures(sigs);
        let results = scanner.scan_file(path)
            .map_err(|e| SdkError::Core(e))?;

        let hits = results
            .into_iter()
            .map(|r| ScanHit {
                offset: r.offset,
                extension: r.signature.extension,
                description: r.signature.description,
                category: r.signature.category,
            })
            .collect();

        Ok(hits)
    }

    pub fn identify_bytes(&self, data: &[u8]) -> Option<FileSignature> {
        self.db.identify(data).map(|e| FileSignature {
            extension: e.extension.clone(),
            magic_bytes: e.magic_bytes.clone(),
            offset: e.offset,
            description: e.description.clone(),
            category: e.category.as_str().to_string(),
        })
    }

    pub fn total_signatures(&self) -> usize {
        self.filtered_entries().len()
    }

    fn filtered_entries(&self) -> Vec<&SignatureEntry> {
        if self.categories.is_empty() && self.extensions.is_empty() {
            return self.db.entries().iter().collect();
        }

        self.db.entries()
            .iter()
            .filter(|e| {
                let cat_match = self.categories.is_empty() || self.categories.contains(&e.category);
                let ext_match = self.extensions.is_empty()
                    || self.extensions.contains(&e.extension.to_lowercase());
                cat_match && ext_match
            })
            .collect()
    }
}

impl Default for SignatureScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub offset: u64,
    pub extension: String,
    pub description: String,
    pub category: String,
}
