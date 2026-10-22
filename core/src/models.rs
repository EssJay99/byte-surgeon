use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub path: String,
    pub total_size: u64,
    pub free_space: u64,
    pub file_system: FileSystemType,
    pub is_network_device: bool,
    pub mount_point: Option<String>,
    pub serial_number: Option<String>,
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceType {
    HardDrive,
    SSD,
    USB,
    Network,
    Mobile,
    Optical,
    Memory,
    Virtual,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileSystemType {
    NTFS,
    FAT32,
    ExFAT,
    EXT4,
    EXT3,
    APFS,
    HFSPlus,
    ZFS,
    Btrfs,
    XFS,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    pub id: String,
    pub session_id: String,
    pub original_path: Option<String>,
    pub original_name: Option<String>,
    pub recovered_path: String,
    pub file_size: u64,
    pub file_type: String,
    pub extension: String,
    pub signature: String,
    pub status: RecoveryStatus,
    pub integrity_check: IntegrityStatus,
    pub threat_scan: ThreatStatus,
    pub recovered_at: DateTime<Utc>,
    pub metadata: Option<FileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryStatus {
    Pending,
    InProgress,
    Completed,
    PartiallyRecovered,
    Failed,
    Corrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityStatus {
    Verified,
    PartiallyIntact,
    Corrupted,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatStatus {
    Clean,
    Suspicious,
    ThreatDetected,
    NotScanned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    pub permissions: Option<u32>,
    pub owner: Option<String>,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    pub id: String,
    pub device_id: String,
    pub device_info: DeviceInfo,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: SessionStatus,
    pub scan_type: ScanType,
    pub files_found: u64,
    pub files_recovered: u64,
    pub total_size_recovered: u64,
    pub output_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Active,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Quick,
    Deep,
    Signature,
    FileSystem,
    Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSignature {
    pub extension: String,
    pub magic_bytes: Vec<u8>,
    pub offset: usize,
    pub description: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub session_id: String,
    pub current_position: u64,
    pub total_size: u64,
    pub percentage: f32,
    pub files_found: u64,
    pub files_recovered: u64,
    pub speed_bytes_per_sec: u64,
    pub estimated_time_remaining: u64,
    pub current_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PartitionType {
    Empty,
    Fat12,
    Fat16,
    Fat32,
    Fat32Lba,
    Ntfs,
    Ext,
    LinuxSwap,
    HfsPlus,
    Apfs,
    EfiSystem,
    Other(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub index: u32,
    pub start_sector: u64,
    pub end_sector: u64,
    pub partition_type: PartitionType,
    pub filesystem: FileSystemType,
    pub is_active: bool,
    pub is_gpt: bool,
    pub guid: Option<String>,
}

impl DeviceInfo {
    pub fn new(path: &str, name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            device_type: DeviceType::Unknown,
            path: path.to_string(),
            total_size: 0,
            free_space: 0,
            file_system: FileSystemType::Unknown,
            is_network_device: false,
            mount_point: None,
            serial_number: None,
            model: None,
            vendor: None,
            connected_at: Utc::now(),
        }
    }
}

impl RecoveredFile {
    pub fn new(session_id: &str, recovered_path: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            original_path: None,
            original_name: None,
            recovered_path: recovered_path.to_string(),
            file_size: 0,
            file_type: String::new(),
            extension: String::new(),
            signature: String::new(),
            status: RecoveryStatus::Pending,
            integrity_check: IntegrityStatus::Unknown,
            threat_scan: ThreatStatus::NotScanned,
            recovered_at: Utc::now(),
            metadata: None,
        }
    }
}

impl RecoverySession {
    pub fn new(device_info: DeviceInfo, scan_type: ScanType, output_path: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            device_id: device_info.id.clone(),
            device_info,
            started_at: Utc::now(),
            completed_at: None,
            status: SessionStatus::Active,
            scan_type,
            files_found: 0,
            files_recovered: 0,
            total_size_recovered: 0,
            output_path: output_path.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_info_defaults() {
        let device = DeviceInfo::new("/dev/sda", "TestDisk");
        assert_eq!(device.name, "TestDisk");
        assert_eq!(device.path, "/dev/sda");
        assert_eq!(device.device_type, DeviceType::Unknown);
        assert_eq!(device.file_system, FileSystemType::Unknown);
        assert_eq!(device.total_size, 0);
        assert_eq!(device.free_space, 0);
        assert!(!device.is_network_device);
        assert!(device.mount_point.is_none());
        assert!(device.serial_number.is_none());
        assert!(device.model.is_none());
        assert!(device.vendor.is_none());
        assert!(!device.id.is_empty());
    }

    #[test]
    fn test_recovered_file_defaults() {
        let file = RecoveredFile::new("sess-1", "/tmp/recovered.jpg");
        assert_eq!(file.session_id, "sess-1");
        assert_eq!(file.recovered_path, "/tmp/recovered.jpg");
        assert_eq!(file.file_size, 0);
        assert!(file.original_path.is_none());
        assert!(file.original_name.is_none());
        assert_eq!(file.status, RecoveryStatus::Pending);
        assert_eq!(file.integrity_check, IntegrityStatus::Unknown);
        assert_eq!(file.threat_scan, ThreatStatus::NotScanned);
        assert!(file.metadata.is_none());
    }

    #[test]
    fn test_recovery_session_defaults() {
        let device = DeviceInfo::new("/dev/sda", "Disk");
        let session = RecoverySession::new(device.clone(), ScanType::Deep, "/output");
        assert_eq!(session.device_id, device.id);
        assert_eq!(session.status, SessionStatus::Active);
        assert_eq!(session.scan_type, ScanType::Deep);
        assert_eq!(session.files_found, 0);
        assert_eq!(session.files_recovered, 0);
        assert_eq!(session.total_size_recovered, 0);
        assert!(session.completed_at.is_none());
        assert_eq!(session.output_path, "/output");
    }

    #[test]
    fn test_device_info_serialization_roundtrip() {
        let device = DeviceInfo::new("/dev/sda", "TestDisk");
        let json = serde_json::to_string(&device).unwrap();
        let deserialized: DeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "TestDisk");
        assert_eq!(deserialized.path, "/dev/sda");
        assert_eq!(deserialized.id, device.id);
    }

    #[test]
    fn test_recovered_file_serialization_roundtrip() {
        let file = RecoveredFile::new("sess-1", "/tmp/file.jpg");
        let json = serde_json::to_string(&file).unwrap();
        let deserialized: RecoveredFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_id, "sess-1");
        assert_eq!(deserialized.recovered_path, "/tmp/file.jpg");
        assert_eq!(deserialized.id, file.id);
    }

    #[test]
    fn test_recovery_session_serialization_roundtrip() {
        let device = DeviceInfo::new("/dev/sda", "Disk");
        let session = RecoverySession::new(device, ScanType::Quick, "/out");
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: RecoverySession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, session.id);
        assert_eq!(deserialized.output_path, "/out");
        assert_eq!(deserialized.scan_type, ScanType::Quick);
    }

    #[test]
    fn test_enum_variants_serialize() {
        assert_eq!(serde_json::to_string(&DeviceType::SSD).unwrap(), "\"SSD\"");
        assert_eq!(serde_json::to_string(&DeviceType::USB).unwrap(), "\"USB\"");
        assert_eq!(serde_json::to_string(&DeviceType::Network).unwrap(), "\"Network\"");
        assert_eq!(serde_json::to_string(&FileSystemType::NTFS).unwrap(), "\"NTFS\"");
        assert_eq!(serde_json::to_string(&FileSystemType::APFS).unwrap(), "\"APFS\"");
        assert_eq!(serde_json::to_string(&RecoveryStatus::Completed).unwrap(), "\"Completed\"");
        assert_eq!(serde_json::to_string(&IntegrityStatus::Corrupted).unwrap(), "\"Corrupted\"");
        assert_eq!(serde_json::to_string(&ThreatStatus::Clean).unwrap(), "\"Clean\"");
        assert_eq!(serde_json::to_string(&SessionStatus::Active).unwrap(), "\"Active\"");
        assert_eq!(serde_json::to_string(&ScanType::Deep).unwrap(), "\"Deep\"");
    }

    #[test]
    fn test_file_metadata_serialization() {
        let meta = FileMetadata {
            created: Some(Utc::now()),
            modified: None,
            accessed: Some(Utc::now()),
            permissions: Some(0o644),
            owner: Some("root".to_string()),
            attributes: vec!["readonly".to_string()],
        };
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: FileMetadata = serde_json::from_str(&json).unwrap();
        assert!(deserialized.created.is_some());
        assert!(deserialized.modified.is_none());
        assert_eq!(deserialized.owner, Some("root".to_string()));
        assert_eq!(deserialized.attributes.len(), 1);
    }

    #[test]
    fn test_scan_progress_serialization() {
        let progress = ScanProgress {
            session_id: "s1".to_string(),
            current_position: 1024,
            total_size: 2048,
            percentage: 50.0,
            files_found: 5,
            files_recovered: 3,
            speed_bytes_per_sec: 1000,
            estimated_time_remaining: 60,
            current_file: Some("test.jpg".to_string()),
        };
        let json = serde_json::to_string(&progress).unwrap();
        let deserialized: ScanProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.session_id, "s1");
        assert_eq!(deserialized.percentage, 50.0);
    }

    #[test]
    fn test_file_signature_serialization() {
        let sig = FileSignature {
            extension: "jpg".to_string(),
            magic_bytes: vec![0xFF, 0xD8, 0xFF],
            offset: 0,
            description: "JPEG".to_string(),
            category: "Image".to_string(),
        };
        let json = serde_json::to_string(&sig).unwrap();
        let deserialized: FileSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.extension, "jpg");
        assert_eq!(deserialized.magic_bytes, vec![0xFF, 0xD8, 0xFF]);
    }
}
