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

pub use datadoctor_core::{
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

pub use datadoctor_devices::DeviceDetector;
pub use datadoctor_filesystem;
pub use datadoctor_forensic;
pub use datadoctor_encryption;
