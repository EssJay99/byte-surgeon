//! Media Recovery for Data Doctor
//!
//! This module provides specialized recovery for media files including:
//! - Video frame-by-frame recovery
//! - Audio waveform reconstruction
//! - Image recovery and repair

mod video;
mod audio;
mod image;

pub use video::{VideoRecoverer, VideoFrame, VideoMetadata};
pub use audio::{AudioRecoverer, AudioSegment, AudioMetadata};
pub use image::{ImageRecoverer, ImageMetadata};

use thiserror::Error;

/// Media recovery errors
#[derive(Error, Debug)]
pub enum MediaError {
    #[error("Invalid media format: {0}")]
    InvalidFormat(String),

    #[error("Corrupted data: {0}")]
    CorruptedData(String),

    #[error("Unsupported codec: {0}")]
    UnsupportedCodec(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MediaError::InvalidFormat("test".to_string());
        assert_eq!(err.to_string(), "Invalid media format: test");
    }
}
