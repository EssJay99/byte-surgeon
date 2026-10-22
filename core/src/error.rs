use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Date parse error: {0}")]
    DateParse(#[from] chrono::ParseError),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("Invalid device: {0}")]
    InvalidDevice(String),

    #[error("File system not supported: {0}")]
    UnsupportedFileSystem(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Threat detected: {0}")]
    ThreatDetected(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("{0}")]
    Other(String),

    #[error("Partition parse error: {0}")]
    PartitionParse(String),

    #[error("Invalid partition table: {0}")]
    InvalidPartitionTable(String),
}

pub type Result<T> = std::result::Result<T, Error>;
