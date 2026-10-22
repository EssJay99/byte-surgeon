use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClassificationResult {
    File(FileType),
    Encrypted(EncryptionIndicator),
    Compressed(CompressionIndicator),
    Unknown(UnknownIndicator),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FileType {
    Text,
    Image(ImageFormat),
    Audio(AudioFormat),
    Video(VideoFormat),
    Archive(ArchiveFormat),
    Document(DocumentFormat),
    Executable(ExecutableFormat),
    Database(DatabaseFormat),
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Gif,
    Bmp,
    Tiff,
    Webp,
    Svg,
    Raw(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AudioFormat {
    Mp3,
    Wav,
    Flac,
    Aac,
    Ogg,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VideoFormat {
    Mp4,
    Avi,
    Mkv,
    Mov,
    Webm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    Gzip,
    Rar,
    SevenZ,
    Bzip2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DocumentFormat {
    Pdf,
    Docx,
    Xlsx,
    Pptx,
    Odt,
    Rtf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExecutableFormat {
    Elf,
    MachO,
    PE,
    Java,
    Python,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DatabaseFormat {
    Sqlite,
    BerkeleyDb,
    LevelDb,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptionIndicator {
    pub confidence: f64,
    pub method_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompressionIndicator {
    pub confidence: f64,
    pub algorithm_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownIndicator {
    pub confidence: f64,
    pub features: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassificationReport {
    pub result: ClassificationResult,
    pub confidence: f64,
    pub entropy: f64,
    pub byte_distribution: HashMap<u8, f64>,
    pub magic_bytes: Option<Vec<u8>>,
    pub method: String,
}

impl ClassificationResult {
    pub fn is_encrypted(&self) -> bool {
        matches!(self, ClassificationResult::Encrypted(_))
    }

    pub fn is_compressed(&self) -> bool {
        matches!(self, ClassificationResult::Compressed(_))
    }

    pub fn file_type_name(&self) -> &str {
        match self {
            ClassificationResult::File(ft) => match ft {
                FileType::Text => "text",
                FileType::Image(_) => "image",
                FileType::Audio(_) => "audio",
                FileType::Video(_) => "video",
                FileType::Archive(_) => "archive",
                FileType::Document(_) => "document",
                FileType::Executable(_) => "executable",
                FileType::Database(_) => "database",
                FileType::Custom(name) => name,
            },
            ClassificationResult::Encrypted(_) => "encrypted",
            ClassificationResult::Compressed(_) => "compressed",
            ClassificationResult::Unknown(_) => "unknown",
        }
    }

    pub fn confidence(&self) -> f64 {
        match self {
            ClassificationResult::File(_) => 0.8,
            ClassificationResult::Encrypted(ind) => ind.confidence,
            ClassificationResult::Compressed(ind) => ind.confidence,
            ClassificationResult::Unknown(ind) => ind.confidence,
        }
    }
}

impl fmt::Display for ClassificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file_type_name())
    }
}

impl ClassificationReport {
    pub fn new(result: ClassificationResult, entropy: f64, method: &str) -> Self {
        Self {
            result,
            confidence: 0.0,
            entropy,
            byte_distribution: HashMap::new(),
            magic_bytes: None,
            method: method.to_string(),
        }
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_byte_distribution(mut self, dist: HashMap<u8, f64>) -> Self {
        self.byte_distribution = dist;
        self
    }

    pub fn with_magic_bytes(mut self, magic: Vec<u8>) -> Self {
        self.magic_bytes = Some(magic);
        self
    }
}
