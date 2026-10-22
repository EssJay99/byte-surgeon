pub mod error;
pub mod recovery;
pub mod devices;
pub mod progress;
pub mod signatures;

pub use error::{SdkError, SdkResult};
pub use recovery::{RecoveryBuilder, RecoveryOperation, RecoveryReport};
pub use devices::DeviceScanner;
pub use progress::{ProgressReporter, ProgressSnapshot};
pub use signatures::{SignatureScanner, ScanHit};

pub use bytesurgeon_core::{
    DeviceInfo, DeviceType, FileSystemType,
    RecoveredFile, RecoveryStatus, IntegrityStatus, ThreatStatus,
    RecoverySession, SessionStatus, ScanType,
    FileSignature, PartitionInfo, PartitionType,
    ScanProgress, FileMetadata,
    SignatureDatabase, SignatureEntry, SignatureCategory,
    RecoveryFilter, RecoveryFilterBuilder,
    DiskScanner, FileCarver,
    scanner::{SignatureMatch, MmapScanner, MmapScanResult},
};

pub use bytesurgeon_devices::DeviceDetector;
pub use bytesurgeon_filesystem;
pub use bytesurgeon_forensic;
pub use bytesurgeon_encryption;
