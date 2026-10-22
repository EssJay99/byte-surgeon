//! File classification using ML models

use crate::features::{FeatureExtractor, ByteFrequencyFeatures, EntropyFeatures, CompositeFeatureExtractor};
use linfa::prelude::*;
use linfa_trees::DecisionTree;
use ndarray::{Array1, Array2};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// File categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileCategory {
    Image,
    Video,
    Audio,
    Document,
    Archive,
    Executable,
    Database,
    SourceCode,
    Configuration,
    Other,
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileCategory::Image => write!(f, "Image"),
            FileCategory::Video => write!(f, "Video"),
            FileCategory::Audio => write!(f, "Audio"),
            FileCategory::Document => write!(f, "Document"),
            FileCategory::Archive => write!(f, "Archive"),
            FileCategory::Executable => write!(f, "Executable"),
            FileCategory::Database => write!(f, "Database"),
            FileCategory::SourceCode => write!(f, "Source Code"),
            FileCategory::Configuration => write!(f, "Configuration"),
            FileCategory::Other => write!(f, "Other"),
        }
    }
}

/// Classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub category: FileCategory,
    pub confidence: f64,
    pub probabilities: HashMap<FileCategory, f64>,
}

impl ClassificationResult {
    pub fn new(category: FileCategory, confidence: f64, probabilities: HashMap<FileCategory, f64>) -> Self {
        Self {
            category,
            confidence,
            probabilities,
        }
    }
}

/// File classifier using ML
pub struct FileClassifier {
    feature_extractor: Box<dyn FeatureExtractor + Send + Sync>,
    model: Option<TrainedModel>,
    category_mapping: HashMap<usize, FileCategory>,
}

enum TrainedModel {
    DecisionTree(DecisionTree<f64, usize>),
}

impl FileClassifier {
    /// Create a new file classifier
    pub fn new() -> Self {
        let mut composite = CompositeFeatureExtractor::new();
        composite.add_extractor(Box::new(ByteFrequencyFeatures::new()));
        composite.add_extractor(Box::new(EntropyFeatures::new(1024)));

        Self {
            feature_extractor: Box::new(composite),
            model: None,
            category_mapping: HashMap::new(),
        }
    }

    /// Train the classifier
    pub fn train(&mut self, data: &[(Vec<u8>, FileCategory)]) -> Result<(), Box<dyn std::error::Error>> {
        info!("Training classifier with {} samples", data.len());

        // Extract features
        let features: Vec<Vec<f64>> = data.iter()
            .map(|(bytes, _)| self.feature_extractor.extract(bytes))
            .collect();

        if features.is_empty() {
            return Err("No training data provided".into());
        }

        let feature_dim = features[0].len();
        let num_samples = features.len();

        // Create feature matrix
        let mut x_data = Vec::with_capacity(num_samples * feature_dim);
        for feature_vec in &features {
            x_data.extend(feature_vec);
        }
        let x = Array2::from_shape_vec((num_samples, feature_dim), x_data)?;

        // Create labels
        let mut category_to_id = HashMap::new();
        let mut id_to_category = HashMap::new();
        let mut y_data = Vec::with_capacity(num_samples);

        for (_, category) in data {
            let id = if let Some(&id) = category_to_id.get(category) {
                id
            } else {
                let id = category_to_id.len();
                category_to_id.insert(*category, id);
                id_to_category.insert(id, *category);
                id
            };
            y_data.push(id);
        }

        let y = Array1::from_vec(y_data);

        // Create dataset
        let dataset = Dataset::new(x, y);

        // Train decision tree
        let model = DecisionTree::params()
            .max_depth(Some(10))
            .fit(&dataset)?;

        self.model = Some(TrainedModel::DecisionTree(model));
        self.category_mapping = id_to_category;

        info!("Classifier trained successfully");
        Ok(())
    }

    /// Classify data
    pub fn classify(&self, data: &[u8]) -> Result<ClassificationResult, Box<dyn std::error::Error>> {
        let model = self.model.as_ref()
            .ok_or("Model not trained")?;

        // Extract features
        let features = self.feature_extractor.extract(data);
        let x = Array2::from_shape_vec((1, features.len()), features)?;

        // Predict
        let prediction = match model {
            TrainedModel::DecisionTree(tree) => tree.predict(&x),
        };

        let predicted_id = prediction[0];
        let category = self.category_mapping.get(&predicted_id)
            .copied()
            .unwrap_or(FileCategory::Other);

        // Calculate confidence (simplified)
        let confidence = 0.85; // In a real implementation, use probability estimates

        let mut probabilities = HashMap::new();
        probabilities.insert(category, confidence);

        Ok(ClassificationResult::new(category, confidence, probabilities))
    }

    /// Save model to file
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let model_data = ModelData {
            category_mapping: self.category_mapping.clone(),
            // Note: In a real implementation, serialize the model here
        };

        let json = serde_json::to_string(&model_data)?;
        std::fs::write(path, json)?;

        info!("Model saved to {:?}", path);
        Ok(())
    }

    /// Load model from file
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let model_data: ModelData = serde_json::from_str(&json)?;

        let mut composite = CompositeFeatureExtractor::new();
        composite.add_extractor(Box::new(ByteFrequencyFeatures::new()));
        composite.add_extractor(Box::new(EntropyFeatures::new(1024)));

        Ok(Self {
            feature_extractor: Box::new(composite),
            model: None, // Note: In a real implementation, deserialize the model
            category_mapping: model_data.category_mapping,
        })
    }

    /// Get number of classes
    pub fn num_classes(&self) -> usize {
        self.category_mapping.len()
    }

    /// Get feature count
    pub fn feature_count(&self) -> usize {
        self.feature_extractor.feature_count()
    }
}

impl Default for FileClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize)]
struct ModelData {
    category_mapping: HashMap<usize, FileCategory>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_category_display() {
        assert_eq!(FileCategory::Image.to_string(), "Image");
        assert_eq!(FileCategory::Video.to_string(), "Video");
        assert_eq!(FileCategory::Audio.to_string(), "Audio");
    }

    #[test]
    fn test_classifier_creation() {
        let classifier = FileClassifier::new();
        assert!(classifier.model.is_none());
    }

    #[test]
    fn test_classification_result() {
        let mut probs = HashMap::new();
        probs.insert(FileCategory::Image, 0.9);
        let result = ClassificationResult::new(FileCategory::Image, 0.9, probs);
        assert_eq!(result.category, FileCategory::Image);
        assert_eq!(result.confidence, 0.9);
    }
}
