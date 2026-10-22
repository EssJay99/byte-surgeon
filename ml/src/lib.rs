//! Machine Learning for Data Doctor
//!
//! This module provides ML-based file classification and analysis.

mod classifier;
mod features;
mod training;

pub use classifier::{FileClassifier, ClassificationResult, FileCategory};
pub use features::{FeatureExtractor, ByteFrequencyFeatures, EntropyFeatures};
pub use training::{TrainingData, ModelTrainer, TrainingConfig};

use thiserror::Error;

/// ML-specific errors
#[derive(Error, Debug)]
pub enum MlError {
    #[error("Training failed: {0}")]
    TrainingFailed(String),

    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Invalid features: {0}")]
    InvalidFeatures(String),

    #[error("Classification failed: {0}")]
    ClassificationFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// ML model manager
pub struct MlModelManager {
    classifiers: std::collections::HashMap<String, FileClassifier>,
}

impl MlModelManager {
    /// Create a new ML model manager
    pub fn new() -> Self {
        Self {
            classifiers: std::collections::HashMap::new(),
        }
    }

    /// Load a trained model
    pub fn load_model(&mut self, name: &str, path: &std::path::Path) -> std::result::Result<(), MlError> {
        let classifier = FileClassifier::load(path)
            .map_err(|e| MlError::ModelNotFound(format!("{}: {}", name, e)))?;
        self.classifiers.insert(name.to_string(), classifier);
        Ok(())
    }

    /// Save a trained model
    pub fn save_model(&self, name: &str, path: &std::path::Path) -> std::result::Result<(), MlError> {
        if let Some(classifier) = self.classifiers.get(name) {
            classifier.save(path)
                .map_err(|e| MlError::SerializationError(e.to_string()))?;
            Ok(())
        } else {
            Err(MlError::ModelNotFound(name.to_string()))
        }
    }

    /// Classify a file using a specific model
    pub fn classify(&self, model_name: &str, data: &[u8]) -> std::result::Result<ClassificationResult, MlError> {
        if let Some(classifier) = self.classifiers.get(model_name) {
            classifier.classify(data)
                .map_err(|e| MlError::ClassificationFailed(e.to_string()))
        } else {
            Err(MlError::ModelNotFound(model_name.to_string()))
        }
    }

    /// List available models
    pub fn list_models(&self) -> Vec<String> {
        self.classifiers.keys().cloned().collect()
    }

    /// Get model information
    pub fn get_model_info(&self, name: &str) -> Option<ModelInfo> {
        self.classifiers.get(name).map(|c| ModelInfo {
            name: name.to_string(),
            num_classes: c.num_classes(),
            feature_count: c.feature_count(),
        })
    }
}

/// Model information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub num_classes: usize,
    pub feature_count: usize,
}

impl Default for MlModelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_manager_creation() {
        let manager = MlModelManager::new();
        assert!(manager.list_models().is_empty());
    }
}
