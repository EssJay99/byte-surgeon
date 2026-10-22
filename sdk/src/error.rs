use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Error, Debug)]
pub enum SdkError {
    #[error("Core engine error: {0}")]
    Core(#[from] datadoctor_core::Error),

    #[error("Device error: {0}")]
    Device(String),

    #[error("Filesystem error: {0}")]
    FileSystem(String),

    #[error("Forensic error: {0}")]
    Forensic(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("{0}")]
    Other(String),
}

pub type SdkResult<T> = std::result::Result<T, SdkError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub session_id: String,
    pub device_path: String,
    pub scan_type: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub files_found: u64,
    pub files_recovered: u64,
    pub total_bytes_recovered: u64,
    pub errors: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub path: String,
    pub name: String,
    pub device_type: String,
    pub file_system: String,
    pub total_size: u64,
    pub free_space: u64,
    pub mount_point: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
}

impl From<datadoctor_core::DeviceInfo> for DeviceSummary {
    fn from(d: datadoctor_core::DeviceInfo) -> Self {
        Self {
            path: d.path,
            name: d.name,
            device_type: format!("{:?}", d.device_type),
            file_system: format!("{:?}", d.file_system),
            total_size: d.total_size,
            free_space: d.free_space,
            mount_point: d.mount_point,
            vendor: d.vendor,
            model: d.model,
        }
    }
}
