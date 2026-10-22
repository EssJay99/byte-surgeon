use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Fragment not found: {0}")]
    FragmentNotFound(String),

    #[error("Reassembly failed: {0}")]
    ReassemblyFailed(String),

    #[error("Repair failed: {0}")]
    RepairFailed(String),

    #[error("Registry error: {0}")]
    RegistryError(String),

    #[error("Shadow copy error: {0}")]
    ShadowCopyError(String),

    #[error("USN journal error: {0}")]
    UsnJournalError(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
