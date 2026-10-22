//! Training utilities for ML models

use crate::classifier::{FileClassifier, FileCategory};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Training data container
pub struct TrainingData {
    pub samples: Vec<(Vec<u8>, FileCategory)>,
    pub metadata: TrainingMetadata,
}

impl TrainingData {
    /// Create new training data
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            metadata: TrainingMetadata::new(),
        }
    }

    /// Add a sample
    pub fn add_sample(&mut self, data: Vec<u8>, category: FileCategory) {
        self.metadata.update(&data, category);
        self.samples.push((data, category));
    }

    /// Load training data from directory
    pub fn load_from_directory(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut training_data = Self::new();

        if !dir.exists() {
            return Err(format!("Directory {:?} does not exist", dir).into());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                let category = Self::infer_category_from_path(&path)?;
                let data = std::fs::read(&path)?;
                training_data.add_sample(data, category);
            }
        }

        info!("Loaded {} training samples", training_data.samples.len());
        Ok(training_data)
    }

    /// Infer category from file path/extension
    fn infer_category_from_path(path: &Path) -> Result<FileCategory, Box<dyn std::error::Error>> {
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let category = match extension.as_str() {
            // Images
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "webp" | "svg" => FileCategory::Image,

            // Videos
            "mp4" | "avi" | "mov" | "mkv" | "wmv" | "flv" | "webm" | "m4v" => FileCategory::Video,

            // Audio
            "mp3" | "wav" | "flac" | "aac" | "ogg" | "wma" | "m4a" => FileCategory::Audio,

            // Documents
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "txt" | "rtf" => FileCategory::Document,

            // Archives
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" => FileCategory::Archive,

            // Executables
            "exe" | "dll" | "so" | "dylib" | "app" | "msi" | "dmg" => FileCategory::Executable,

            // Database
            "db" | "sqlite" | "sql" | "mdb" | "accdb" => FileCategory::Database,

            // Source code
            "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "java" | "go" | "rb" | "php" => FileCategory::SourceCode,

            // Configuration
            "json" | "yaml" | "yml" | "toml" | "xml" | "ini" | "conf" | "cfg" => FileCategory::Configuration,

            // Default
            _ => FileCategory::Other,
        };

        Ok(category)
    }

    /// Get category distribution
    pub fn category_distribution(&self) -> HashMap<FileCategory, usize> {
        let mut dist = HashMap::new();
        for (_, category) in &self.samples {
            *dist.entry(*category).or_insert(0) += 1;
        }
        dist
    }

    /// Get sample count
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

impl Default for TrainingData {
    fn default() -> Self {
        Self::new()
    }
}

/// Training metadata
#[derive(Debug, Clone)]
pub struct TrainingMetadata {
    pub total_samples: usize,
    pub total_bytes: u64,
    pub category_counts: HashMap<FileCategory, usize>,
    pub avg_sample_size: f64,
}

impl TrainingMetadata {
    pub fn new() -> Self {
        Self {
            total_samples: 0,
            total_bytes: 0,
            category_counts: HashMap::new(),
            avg_sample_size: 0.0,
        }
    }

    pub fn update(&mut self, data: &[u8], category: FileCategory) {
        self.total_samples += 1;
        self.total_bytes += data.len() as u64;
        *self.category_counts.entry(category).or_insert(0) += 1;
        self.avg_sample_size = self.total_bytes as f64 / self.total_samples as f64;
    }
}

impl Default for TrainingMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Training configuration
#[derive(Debug, Clone)]
pub struct TrainingConfig {
    pub max_depth: Option<usize>,
    pub min_samples_split: usize,
    pub validation_split: f64,
    pub random_seed: Option<u64>,
}

impl TrainingConfig {
    pub fn new() -> Self {
        Self {
            max_depth: Some(10),
            min_samples_split: 2,
            validation_split: 0.2,
            random_seed: Some(42),
        }
    }
}

impl Default for TrainingConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Model trainer
pub struct ModelTrainer {
    config: TrainingConfig,
}

impl ModelTrainer {
    /// Create a new model trainer
    pub fn new(config: TrainingConfig) -> Self {
        Self { config }
    }

    /// Train a model
    pub fn train(&self, training_data: &TrainingData) -> Result<FileClassifier, Box<dyn std::error::Error>> {
        info!("Starting model training with {} samples", training_data.len());

        let mut classifier = FileClassifier::new();
        classifier.train(&training_data.samples)?;

        info!("Model training completed");
        Ok(classifier)
    }

    /// Train with cross-validation
    pub fn train_with_cv(&self, training_data: &TrainingData, folds: usize) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
        info!("Starting {}-fold cross-validation", folds);

        let mut scores = Vec::with_capacity(folds);
        let fold_size = training_data.len() / folds;

        for fold in 0..folds {
            let start = fold * fold_size;
            let end = if fold == folds - 1 {
                training_data.len()
            } else {
                start + fold_size
            };

            // Create training and validation sets
            let mut train_samples = Vec::new();
            let mut val_samples = Vec::new();

            for (i, sample) in training_data.samples.iter().enumerate() {
                if i >= start && i < end {
                    val_samples.push(sample.clone());
                } else {
                    train_samples.push(sample.clone());
                }
            }

            // Train on training set
            let mut classifier = FileClassifier::new();
            classifier.train(&train_samples)?;

            // Evaluate on validation set
            let mut correct = 0;
            for (data, category) in &val_samples {
                if let Ok(result) = classifier.classify(data) {
                    if result.category == *category {
                        correct += 1;
                    }
                }
            }

            let accuracy = correct as f64 / val_samples.len() as f64;
            scores.push(accuracy);
            info!("Fold {}: accuracy = {:.2}%", fold + 1, accuracy * 100.0);
        }

        let avg_accuracy = scores.iter().sum::<f64>() / scores.len() as f64;
        info!("Cross-validation completed: average accuracy = {:.2}%", avg_accuracy * 100.0);

        Ok(scores)
    }
}

impl Default for ModelTrainer {
    fn default() -> Self {
        Self::new(TrainingConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_training_data_creation() {
        let data = TrainingData::new();
        assert!(data.is_empty());
    }

    #[test]
    fn test_add_sample() {
        let mut data = TrainingData::new();
        data.add_sample(vec![0u8, 1, 2, 3], FileCategory::Image);
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn test_category_distribution() {
        let mut data = TrainingData::new();
        data.add_sample(vec![0u8], FileCategory::Image);
        data.add_sample(vec![1u8], FileCategory::Image);
        data.add_sample(vec![2u8], FileCategory::Video);

        let dist = data.category_distribution();
        assert_eq!(dist[&FileCategory::Image], 2);
        assert_eq!(dist[&FileCategory::Video], 1);
    }

    #[test]
    fn test_infer_category() {
        let img_path = PathBuf::from("test.jpg");
        let category = TrainingData::infer_category_from_path(&img_path).unwrap();
        assert_eq!(category, FileCategory::Image);

        let vid_path = PathBuf::from("test.mp4");
        let category = TrainingData::infer_category_from_path(&vid_path).unwrap();
        assert_eq!(category, FileCategory::Video);
    }
}
