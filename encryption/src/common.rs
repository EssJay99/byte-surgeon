use anyhow::Result;
use serde::{Deserialize, Serialize};

pub trait EncryptedVolume {
    fn detect(path: &str) -> Result<bool>;
    fn unlock(path: &str, password: &str) -> Result<UnlockedVolume>;
    fn volume_type(&self) -> VolumeType;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlockedVolume {
    pub device_path: String,
    pub volume_type: VolumeType,
    pub decrypted_data: Vec<u8>,
    pub metadata: VolumeMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeType {
    BitLocker,
    FileVault,
    LUKS,
    VeraCrypt,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VolumeMetadata {
    pub version: String,
    pub encryption_method: String,
    pub created: Option<String>,
}

impl VolumeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            VolumeType::BitLocker => "BitLocker",
            VolumeType::FileVault => "FileVault",
            VolumeType::LUKS => "LUKS",
            VolumeType::VeraCrypt => "VeraCrypt",
            VolumeType::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for VolumeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
