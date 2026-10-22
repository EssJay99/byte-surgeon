//! Feature extraction for ML classification

use ndarray::Array1;
use std::collections::HashMap;

/// Feature extractor trait
pub trait FeatureExtractor {
    /// Extract features from data
    fn extract(&self, data: &[u8]) -> Vec<f64>;

    /// Get feature names
    fn feature_names(&self) -> Vec<String>;

    /// Get feature count
    fn feature_count(&self) -> usize {
        self.feature_names().len()
    }
}

/// Byte frequency features
pub struct ByteFrequencyFeatures;

impl ByteFrequencyFeatures {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ByteFrequencyFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureExtractor for ByteFrequencyFeatures {
    fn extract(&self, data: &[u8]) -> Vec<f64> {
        if data.is_empty() {
            return vec![0.0; 256];
        }

        let mut counts = vec![0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        counts.iter()
            .map(|&c| c as f64 / data.len() as f64)
            .collect()
    }

    fn feature_names(&self) -> Vec<String> {
        (0..256).map(|i| format!("byte_freq_{}", i)).collect()
    }
}

/// Entropy features
pub struct EntropyFeatures {
    block_size: usize,
}

impl EntropyFeatures {
    pub fn new(block_size: usize) -> Self {
        Self { block_size }
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        counts.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

impl Default for EntropyFeatures {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl FeatureExtractor for EntropyFeatures {
    fn extract(&self, data: &[u8]) -> Vec<f64> {
        if data.len() < self.block_size {
            return vec![self.calculate_entropy(data)];
        }

        let num_blocks = (data.len() + self.block_size - 1) / self.block_size;
        let mut entropies = Vec::with_capacity(num_blocks);

        for i in 0..num_blocks {
            let start = i * self.block_size;
            let end = std::cmp::min(start + self.block_size, data.len());
            entropies.push(self.calculate_entropy(&data[start..end]));
        }

        entropies
    }

    fn feature_names(&self) -> Vec<String> {
        vec!["entropy_global".to_string()]
    }
}

/// Magic bytes features
pub struct MagicBytesFeatures;

impl MagicBytesFeatures {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MagicBytesFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureExtractor for MagicBytesFeatures {
    fn extract(&self, data: &[u8]) -> Vec<f64> {
        if data.len() < 16 {
            return vec![0.0; 16];
        }

        data[..16].iter().map(|&b| b as f64 / 255.0).collect()
    }

    fn feature_names(&self) -> Vec<String> {
        (0..16).map(|i| format!("magic_byte_{}", i)).collect()
    }
}

/// Composite feature extractor
pub struct CompositeFeatureExtractor {
    extractors: Vec<Box<dyn FeatureExtractor + Send + Sync>>,
}

impl CompositeFeatureExtractor {
    pub fn new() -> Self {
        Self {
            extractors: Vec::new(),
        }
    }

    pub fn add_extractor(&mut self, extractor: Box<dyn FeatureExtractor + Send + Sync>) {
        self.extractors.push(extractor);
    }
}

impl Default for CompositeFeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureExtractor for CompositeFeatureExtractor {
    fn extract(&self, data: &[u8]) -> Vec<f64> {
        self.extractors
            .iter()
            .flat_map(|e| e.extract(data))
            .collect()
    }

    fn feature_names(&self) -> Vec<String> {
        self.extractors
            .iter()
            .flat_map(|e| e.feature_names())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_frequency_features() {
        let extractor = ByteFrequencyFeatures::new();
        let data = vec![0u8, 1, 2, 3, 0, 1];
        let features = extractor.extract(&data);

        assert_eq!(features.len(), 256);
        assert_eq!(features[0], 2.0 / 6.0); // byte 0 appears twice
        assert_eq!(features[1], 2.0 / 6.0); // byte 1 appears twice
    }

    #[test]
    fn test_entropy_features() {
        let extractor = EntropyFeatures::new(4);
        let data = vec![0u8, 1, 2, 3];
        let features = extractor.extract(&data);

        assert_eq!(features.len(), 1);
        assert!(features[0] > 0.0);
    }

    #[test]
    fn test_magic_bytes_features() {
        let extractor = MagicBytesFeatures::new();
        let data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                       0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52];
        let features = extractor.extract(&data);

        assert_eq!(features.len(), 16);
        assert_eq!(features[0], 0x89 as f64 / 255.0);
    }
}
