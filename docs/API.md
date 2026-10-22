# Core Engine API Reference

## RecoveryEngine

The central orchestrator for all recovery operations.

```rust
use bytesurgeon_core::RecoveryEngine;
use std::path::Path;

let engine = RecoveryEngine::new(Path::new("./data"))?;
```

### Methods

#### `RecoveryEngine::new(data_dir: &Path) -> Result<Self>`

Creates a new recovery engine instance. Initializes the database, audit logger, threat scanner, and security policy.

```rust
let engine = RecoveryEngine::new(Path::new("/var/lib/bytesurgeon"))?;
```

**Errors:**
- `Error::Io` if `data_dir` cannot be created
- `Error::Database` if the SQLite database cannot be initialized

---

#### `engine.enumerate_devices() -> Result<Vec<DeviceInfo>>`

Scans the system for connected storage devices. Detects hard drives, SSDs, USB devices, and optical media across all supported platforms.

```rust
let devices = engine.enumerate_devices()?;
for device in &devices {
    println!("{}: {} ({:?})", device.name, device.path, device.device_type);
}
```

---

#### `engine.start_recovery(device: &DeviceInfo, scan_type: ScanType, output_dir: &Path) -> Result<String>`

Starts a recovery session on the given device. Returns a session ID for tracking progress and retrieving results.

```rust
let session_id = engine.start_recovery(
    &device,
    ScanType::Signature,
    Path::new("./recovered"),
)?;
```

**Scan Types:**

| Variant | Description |
|---------|-------------|
| `ScanType::Signature` | Fast magic-byte detection |
| `ScanType::Quick` | Quick file system scan |
| `ScanType::Deep` | Thorough sector analysis |
| `ScanType::FileSystem` | File system metadata scan |
| `ScanType::Raw` | Raw sector-by-sector recovery |

---

#### `engine.get_session(session_id: &str) -> Result<Option<RecoverySession>>`

Retrieves a recovery session by ID.

```rust
if let Some(session) = engine.get_session(&session_id)? {
    println!("Status: {:?}", session.status);
    println!("Files found: {}", session.files_found);
    println!("Files recovered: {}", session.files_recovered);
    println!("Size recovered: {} bytes", session.total_size_recovered);
}
```

---

#### `engine.get_recovered_files(session_id: &str) -> Result<Vec<RecoveredFile>>`

Returns all files recovered in a session.

```rust
let files = engine.get_recovered_files(&session_id)?;
for file in &files {
    println!("{}: {} bytes ({:?})", file.extension, file.file_size, file.status);
}
```

---

#### `engine.get_all_devices() -> Result<Vec<DeviceInfo>>`

Returns all devices from the database.

---

#### `engine.get_sessions_for_device(device_id: &str) -> Result<Vec<RecoverySession>>`

Returns all recovery sessions for a specific device.

---

#### `engine.cancel_session(session_id: &str) -> Result<()>`

Cancels an active recovery session.

---

## DiskScanner

Low-level disk scanning with signature detection.

```rust
use bytesurgeon_core::DiskScanner;

let scanner = DiskScanner::new("/dev/sda");
```

### Methods

#### `DiskScanner::new(device_path: &str) -> Self`

Creates a scanner for the given device path.

#### `scanner.with_block_size(size: usize) -> Self`

Sets the I/O block size (default: 4096).

#### `scanner.find_signatures() -> Result<Vec<SignatureMatch>>`

Scans the device for known file signatures.

```rust
let matches = scanner.find_signatures()?;
for m in &matches {
    println!("Found {} at offset {}", m.signature.extension, m.offset);
}
```

#### `scanner.scan_raw<F>(callback: F) -> Result<Vec<DiscoveredSector>>`

Performs a raw sector scan with a callback for each block.

```rust
let sectors = scanner.scan_raw(|data, offset| {
    // Return true to include this sector in results
    !data.iter().all(|&b| b == 0)
})?;
```

#### `scanner.cancel()`

Cancels an in-progress scan.

#### `scanner.is_cancelled() -> bool`

Returns whether the scan has been cancelled.

#### `scanner.get_progress() -> (u64, u64)`

Returns `(current_position, bytes_scanned)`.

---

## MmapScanner

Memory-mapped file scanner for high-performance scanning of large files.

```rust
use bytesurgeon_core::scanner::MmapScanner;

let scanner = MmapScanner::new();
let results = scanner.scan_file("/path/to/large/file.img")?;
```

### Methods

#### `MmapScanner::new() -> Self`

Creates a new memory-mapped scanner with default signatures.

#### `MmapScanner::with_signatures(signatures: Vec<FileSignature>) -> Self`

Creates a scanner with custom signatures.

#### `scanner.scan_file(path: &str) -> Result<Vec<MmapScanResult>>`

Scans a file using memory-mapped I/O. Automatically falls back to regular I/O for files below 64KB or when mmap fails.

For files > 1GB, uses chunked mapping with overlap to handle signatures at chunk boundaries.

---

## FileCarver

Extracts files from raw disk data based on signature matches.

```rust
use bytesurgeon_core::FileCarver;
use std::path::Path;

let carver = FileCarver::new(Path::new("./output"), "session-1");
```

### Methods

#### `FileCarver::new(output_dir: &Path, session_id: &str) -> Self`

Creates a carver that writes recovered files to `output_dir`.

#### `carver.with_max_file_size(size: u64) -> Self`

Sets the maximum file size to recover (default: 10GB).

#### `carver.carve_files<F>(device_path: &str, signatures: &[SignatureMatch], callback: F) -> Result<Vec<RecoveredFile>>`

Carves files sequentially from the device.

```rust
let recovered = carver.carve_files("/dev/sda", &matches, |current, total| {
    println!("Carving file {}/{}", current, total);
})?;
```

#### `carver.carve_files_parallel<F>(device_path: &str, signatures: &[SignatureMatch], callback: F) -> Result<Vec<RecoveredFile>>`

Carves files in parallel using Rayon. Uses memory-mapped I/O for the source device.

```rust
let recovered = carver.carve_files_parallel("/dev/sda", &matches, |completed, total| {
    println!("Completed: {}/{}", completed, total);
})?;
```

### Supported File End Detection

| Type | Method |
|------|--------|
| JPEG | Scans for `FF D9` end marker |
| PNG | Reads IHDR chunk length |
| PDF | Scans for `%%EOF` marker |
| ZIP/DOCX/XLSX/PPTX | Scans for end-of-central-directory record |
| Other | Uses remaining device size (max 1MB) |

---

## ThreatScanner

Pattern-based malware and threat detection.

```rust
use bytesurgeon_core::ThreatScanner;
use std::path::Path;

let scanner = ThreatScanner::new();
```

### Methods

#### `scanner.scan_file(file_path: &Path) -> Result<ThreatStatus>`

Scans a file for suspicious patterns and executable headers.

```rust
let status = scanner.scan_file(Path::new("/recovered/file.exe"))?;
match status {
    ThreatStatus::Clean => println!("File is clean"),
    ThreatStatus::Suspicious => println!("File contains suspicious patterns"),
    ThreatStatus::ThreatDetected => println!("Threat detected!"),
    ThreatStatus::NotScanned => println!("File was not scanned (too large)"),
}
```

#### `scanner.calculate_file_hash(file_path: &Path) -> Result<String>`

Computes SHA-256 hash of a file.

```rust
let hash = scanner.calculate_file_hash(Path::new("/path/to/file"))?;
println!("SHA-256: {}", hash);
```

#### `scanner.verify_file_integrity(file_path: &Path, expected_hash: &str) -> Result<bool>`

Verifies a file matches an expected SHA-256 hash.

---

## AuditLogger

Append-only audit log for all operations.

```rust
use bytesurgeon_core::AuditLogger;
use std::path::Path;

let logger = AuditLogger::new(Path::new("/var/log/bytesurgeon/audit.log"));
```

### Methods

#### `logger.log_operation(operation: &str, details: &str) -> Result<()>`

Logs a general operation.

```rust
logger.log_operation("RECOVERY_START", "Device: /dev/sda, Type: Signature")?;
```

#### `logger.log_security_event(event_type: &str, details: &str) -> Result<()>`

Logs a security-specific event.

```rust
logger.log_security_event("BREACH", "Unauthorized access attempt")?;
```

#### `logger.log_threat_detection(file_path: &Path, threat_type: &str) -> Result<()>`

Logs a threat detection event.

```rust
logger.log_threat_detection(Path::new("/tmp/suspicious.exe"), "malware")?;
```

---

## SecurityPolicy

Configurable security policy for recovery operations.

```rust
use bytesurgeon_core::SecurityPolicy;

let policy = SecurityPolicy {
    allow_network_recovery: true,
    allow_mobile_recovery: true,
    require_threat_scan: true,
    max_concurrent_operations: 4,
    audit_logging: true,
};
```

---

## Database

SQLite-backed persistent storage for sessions, devices, and recovered files.

```rust
use bytesurgeon_core::Database;

let db = Database::new(Path::new("./data/bytesurgeon.db"))?;
```

### Methods

| Method | Description |
|--------|-------------|
| `save_device(device: &DeviceInfo) -> Result<()>` | Persist device info |
| `save_session(session: &RecoverySession) -> Result<()>` | Persist session state |
| `save_recovered_file(file: &RecoveredFile) -> Result<()>` | Persist recovered file |
| `get_session(id: &str) -> Result<Option<RecoverySession>>` | Retrieve session |
| `get_recovered_files(session_id: &str) -> Result<Vec<RecoveredFile>>` | Get session files |
| `get_all_devices() -> Result<Vec<DeviceInfo>>` | Get all devices |
| `get_sessions_for_device(device_id: &str) -> Result<Vec<RecoverySession>>` | Get device sessions |

---

## Type Definitions

### DeviceInfo

```rust
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
```

### DeviceType

```rust
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
```

### FileSystemType

```rust
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
```

### RecoveredFile

```rust
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
```

### RecoveryStatus

```rust
pub enum RecoveryStatus {
    Pending,
    InProgress,
    Completed,
    PartiallyRecovered,
    Failed,
    Corrupted,
}
```

### IntegrityStatus

```rust
pub enum IntegrityStatus {
    Verified,
    PartiallyIntact,
    Corrupted,
    Unknown,
}
```

### ThreatStatus

```rust
pub enum ThreatStatus {
    Clean,
    Suspicious,
    ThreatDetected,
    NotScanned,
}
```

### RecoverySession

```rust
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
```

### SessionStatus

```rust
pub enum SessionStatus {
    Active,
    Paused,
    Completed,
    Failed,
    Cancelled,
}
```

### FileSignature

```rust
pub struct FileSignature {
    pub extension: String,
    pub magic_bytes: Vec<u8>,
    pub offset: usize,
    pub description: String,
    pub category: String,
}
```

### ScanProgress

```rust
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
```

---

## Additional Modules

### WriteProtector

```rust
use bytesurgeon_core::{WriteProtector, WriteProtectionStatus};

let protector = WriteProtector::new("/dev/sda");
let status = protector.status();
```

### DeduplicationEngine

```rust
use bytesurgeon_core::DeduplicationEngine;

let engine = DeduplicationEngine::new();
```

### SmartDeduplicator

```rust
use bytesurgeon_core::{SmartDeduplicator, DuplicateGroup, Sensitivity};

let dedup = SmartDeduplicator::new();
```

### RecoveryFilter

```rust
use bytesurgeon_core::{RecoveryFilter, RecoveryFilterBuilder};

let filter = RecoveryFilterBuilder::new()
    .with_extensions(&["jpg", "png"])
    .with_min_size(1024)
    .build();
```

### CheckpointManager

```rust
use bytesurgeon_core::{CheckpointManager, CheckpointConfig};

let manager = CheckpointManager::new(CheckpointConfig::default());
```

### StreamProcessor

```rust
use bytesurgeon_core::{StreamProcessor, StreamChunk};

let processor = StreamProcessor::new();
```

### SectorCache

```rust
use bytesurgeon_core::SectorCache;

let cache = SectorCache::new();
```

### UndoManager

```rust
use bytesurgeon_core::{UndoManager, UndoAction};

let manager = UndoManager::new();
```

### BackupManager

```rust
use bytesurgeon_core::{BackupManager, BackupPolicy};

let manager = BackupManager::new(BackupPolicy::default());
```

### ErrorRecovery

```rust
use bytesurgeon_core::{ErrorRecovery, ErrorRecoveryStrategy};

let recovery = ErrorRecovery::new(ErrorRecoveryStrategy::default());
```

### EvidenceHasher

```rust
use bytesurgeon_core::{EvidenceHasher, EvidenceChain};

let hasher = EvidenceHasher::new();
```

### Examiner / ExaminerManager

```rust
use bytesurgeon_core::{ExaminerManager, Role};

let manager = ExaminerManager::new();
```

### CourtReportGenerator

```rust
use bytesurgeon_core::{CourtReportGenerator, CaseInfo, ExaminerInfo};

let generator = CourtReportGenerator::new();
```

### DryRunExecutor

```rust
use bytesurgeon_core::{DryRunExecutor, DryRunContext};

let executor = DryRunExecutor::new();
```

### MetadataPreserver

```rust
use bytesurgeon_core::{MetadataPreserver, MetadataSnapshot};

let preserver = MetadataPreserver::new();
```

### FilePreviewer

```rust
use bytesurgeon_core::{FilePreviewer, PreviewData};

let previewer = FilePreviewer::new();
```

### HexViewer

```rust
use bytesurgeon_core::{HexViewer, HexDump};

let viewer = HexViewer::new();
```

### ReportGenerator

```rust
use bytesurgeon_core::{ReportGenerator, ReportData};

let generator = ReportGenerator::new();
```

---

## Filesystem Module

### Detect File System

```rust
use bytesurgeon_filesystem::detect_filesystem;

let fs_type = bytesurgeon_filesystem::detect_filesystem("/dev/sda1")?;
```

### Create Parser

```rust
use bytesurgeon_filesystem::create_parser;
use bytesurgeon_core::FileSystemType;

let parser = create_parser(FileSystemType::NTFS, "/dev/sda1")?;
```

### FileSystem Trait

```rust
pub trait FileSystem {
    fn list_files(&self) -> Result<Vec<FileEntry>>;
    fn list_directories(&self) -> Result<Vec<DirectoryEntry>>;
    fn read_file(&self, path: &str) -> Result<Vec<u8>>;
}
```

---

## Encryption Module

### Volume Types

```rust
use bytesurgeon_encryption::{VolumeType, EncryptedVolume, UnlockedVolume};
```

| Type | Description |
|------|-------------|
| `VolumeType::BitLocker` | Windows BitLocker |
| `VolumeType::FileVault` | macOS FileVault |
| `VolumeType::LUKS` | Linux LUKS |
| `VolumeType::VeraCrypt` | VeraCrypt volumes |

---

## Enterprise Module

### CaseManager

```rust
use bytesurgeon_enterprise::CaseManager;

let case_mgr = CaseManager::new();
let case_id = case_mgr.create_case("CASE-001", "John Doe")?;
let evidence_id = case_mgr.add_evidence(&case_id, "/dev/sda")?;
let report = case_mgr.generate_report(&case_id)?;
```

### BatchProcessor

```rust
use bytesurgeon_enterprise::BatchProcessor;

let processor = BatchProcessor::new();
let job_id = processor.add_job("/dev/sda", "./output", "signature")?;
processor.start()?;
let status = processor.status()?;
```

### ScanManager

```rust
use bytesurgeon_enterprise::ScanManager;

let manager = ScanManager::new();
let interrupted = manager.list_interrupted_scans()?;
let state = manager.resume_scan("/dev/sda")?;
```

### ApiServer

```rust
use bytesurgeon_enterprise::ApiServer;

let server = ApiServer::new();
server.start(8080)?;
```

---

## Compliance Module

```rust
use bytesurgeon_security::compliance::ComplianceChecker;

let checker = ComplianceChecker::new();
let report = checker.check_nist_compliance()?;
println!("Passed: {}", report.passed);
println!("Standard: {}", report.standard);
```
