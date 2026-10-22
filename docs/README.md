# Byte Surgeon API Documentation

## Overview

Welcome to the Byte Surgeon API documentation. This guide provides comprehensive reference material for developers integrating with or extending the Byte Surgeon data recovery platform.

Byte Surgeon is a cross-platform data recovery solution built with Rust, offering high-performance scanning, multiple recovery modes, security compliance, and an extensible plugin architecture.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           CLI / GUI / API Server         │
                    └────────────────┬────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
    ┌─────────▼──────────┐ ┌────────▼────────┐  ┌──────────▼──────────┐
    │   RecoveryEngine   │ │  PluginManager   │  │   Enterprise APIs   │
    └─────────┬──────────┘ └─────────────────┘  └─────────────────────┘
              │
    ┌─────────┼─────────────────────────────────────────┐
    │         │                                         │
    │  ┌──────▼──────┐  ┌──────────┐  ┌──────────────┐  │
    │  │ DiskScanner │  │FileCarver│  │ThreatScanner │  │
    │  └─────────────┘  └──────────┘  └──────────────┘  │
    │                                                    │
    │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
    │  │ Database │  │AuditLog  │  │SecurityPolicy    │  │
    │  └──────────┘  └──────────┘  └──────────────────┘  │
    │                                                    │
    │              Core Engine (bytesurgeon-core)        │
    └────────────────────────────────────────────────────┘
              │
    ┌─────────┼─────────────────────────────────────────┐
    │         │                                         │
    │  ┌──────▼──────┐  ┌──────────┐  ┌──────────────┐  │
    │  │ Filesystem  │  │Encryption│  │   Devices    │  │
    │  │   Parsers   │  │  Engines  │  │  Detection   │  │
    │  └─────────────┘  └──────────┘  └──────────────┘  │
    │                                                    │
    │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
    │  │  Network  │  │  Mobile  │  │   Forensic     │  │
    │  │  Scanner  │  │ Recovery │  │   Analysis      │  │
    │  └──────────┘  └──────────┘  └──────────────────┘  │
    └────────────────────────────────────────────────────┘
```

### Workspace Crates

| Crate | Description |
|-------|-------------|
| `bytesurgeon-core` | Core recovery engine, models, scanning, carving |
| `bytesurgeon-filesystem` | NTFS, FAT32, ext4, APFS parsers |
| `bytesurgeon-devices` | Device detection and abstraction |
| `bytesurgeon-network` | Network discovery (SMB, NFS) |
| `bytesurgeon-mobile` | Android and iOS recovery |
| `bytesurgeon-security` | Threat detection and compliance |
| `bytesurgeon-crypto` | Password decryption engine |
| `bytesurgeon-encryption` | Volume encryption (BitLocker, FileVault, LUKS, VeraCrypt) |
| `bytesurgeon-enterprise` | Case management, batch processing, API server |
| `bytesurgeon-forensic` | Shadow copies, USN journal, registry, fragments |
| `bytesurgeon-raid` | RAID 0/1/5/6 reconstruction |
| `bytesurgeon-chat` | Chat message extraction (iMessage, WhatsApp, Signal, Slack) |
| `bytesurgeon-ml` | Machine learning classification |
| `tle-plugins` | Plugin system with dynamic loading |
| `bytesurgeon-cli` | Command-line interface |
| `bytesurgeon-gui` | Tauri-based GUI application |

---

## Quick Start

### Prerequisites

- Rust 1.70+
- Node.js 18+ (for GUI)
- Platform-specific dependencies:
  - **Linux**: `libudev-dev`, `libusb-1.0-0-dev`
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Visual Studio Build Tools

### Installation

#### From Source

```bash
git clone https://github.com/yourorg/bytesurgeon.git
cd bytesurgeon
cargo build --release
cargo install --path cli
```

#### Platform-Specific

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install libudev-dev libusb-1.0-0-dev
cargo build --release
```

**macOS:**
```bash
xcode-select --install
cargo build --release
```

**Windows:**
```powershell
# Install Visual Studio Build Tools with C++ workload
cargo build --release
```

### Basic Usage

```rust
use bytesurgeon_core::{RecoveryEngine, ScanType};
use std::path::Path;

fn main() -> bytesurgeon_core::Result<()> {
    let engine = RecoveryEngine::new(Path::new("./data"))?;

    // Enumerate devices
    let devices = engine.enumerate_devices()?;

    // Start recovery
    if let Some(device) = devices.first() {
        let session_id = engine.start_recovery(
            device,
            ScanType::Signature,
            Path::new("./recovered"),
        )?;

        // Get results
        let session = engine.get_session(&session_id)?;
        let files = engine.get_recovered_files(&session_id)?;

        println!("Recovered {} files", files.len());
    }

    Ok(())
}
```

---

## Feature List

### Core Recovery

| Feature | Module | Description |
|---------|--------|-------------|
| Signature Scanning | `core::scanner` | Magic-byte based file identification (15+ types) |
| File Carving | `core::carver` | Extract files from raw sectors with size estimation |
| Parallel Carving | `core::carver` | Multi-threaded carving via Rayon |
| Memory-Mapped Scanning | `core::scanner` | Zero-copy scanning for large files |
| Deep Scan | `core::recovery` | Thorough sector-by-sector analysis |
| Quick Scan | `core::recovery` | Fast signature-based recovery |
| Raw Recovery | `core::recovery` | Sector-by-sector extraction |

### File System Support

| File System | Module | Parser |
|-------------|--------|--------|
| NTFS | `filesystem::ntfs` | `NTFSParser` |
| FAT32 | `filesystem::fat32` | `FAT32Parser` |
| ext4/ext3 | `filesystem::ext4` | `EXT4Parser` |
| APFS | `filesystem::apfs` | `APFSParser` |

### Security

| Feature | Module | Description |
|---------|--------|-------------|
| Threat Detection | `core::security` | Pattern-based malware scanning |
| Integrity Verification | `core::security` | SHA-256 hash verification |
| Audit Logging | `core::security` | Complete operation tracking |
| Compliance Checking | `security::compliance` | NIST SP 800-53 validation |
| Write Protection | `core::writeprotect` | Evidence write-blocking |
| Tamper-Proof Audit | `core::tamper_proof_audit` | Hashed audit chain |
| Evidence Hashing | `core::evidence_hash` | Chain-of-custody hash verification |

### Encryption

| Engine | Module | Description |
|--------|--------|-------------|
| BitLocker | `encryption::bitlocker` | Windows full-disk encryption |
| FileVault | `encryption::filevault` | macOS full-disk encryption |
| LUKS | `encryption::luks` | Linux unified key setup |
| VeraCrypt | `encryption::veracrypt` | Cross-platform volume encryption |
| AES-GCM | `crypto` | Symmetric file decryption |
| Argon2 | `crypto` | Password hashing |

### Enterprise

| Feature | Module | Description |
|---------|--------|-------------|
| Case Management | `enterprise` | Multi-case tracking with evidence custody |
| Batch Processing | `enterprise` | Concurrent multi-device recovery |
| Incremental Scanning | `enterprise` | Resume interrupted scans |
| API Server | `enterprise` | REST API interface |
| Court Reports | `core::court_report` | Forensic report generation |

### Forensic Analysis

| Feature | Module | Description |
|---------|--------|-------------|
| Shadow Copies | `forensic::shadow_copy` | VSS recovery |
| USN Journal | `forensic::usn_journal` | NTFS change journal analysis |
| Registry Parsing | `forensic::registry` | Windows registry extraction |
| Fragment Recovery | `forensic::fragments` | File fragment reassembly |
| Timeline Analysis | `core::timeline` | Event timeline construction |

---

## Code Examples

### File System Detection

```rust
use bytesurgeon_filesystem::detect_filesystem;

let fs_type = detect_filesystem("/dev/sda1")?;
println!("Detected: {:?}", fs_type);
```

### Threat Scanning

```rust
use bytesurgeon_core::ThreatScanner;
use std::path::Path;

let scanner = ThreatScanner::new();
let status = scanner.scan_file(Path::new("/path/to/file"))?;
let hash = scanner.calculate_file_hash(Path::new("/path/to/file"))?;
let valid = scanner.verify_file_integrity(Path::new("/path/to/file"), &hash)?;
```

### Parallel File Carving

```rust
use bytesurgeon_core::{FileCarver, DiskScanner};
use std::path::Path;

let scanner = DiskScanner::new("/dev/sda");
let signatures = scanner.find_signatures()?;

let carver = FileCarver::new(Path::new("./output"), "session-1");
let recovered = carver.carve_files_parallel(
    "/dev/sda",
    &signatures,
    |completed, total| {
        println!("Progress: {}/{}", completed, total);
    },
)?;
```

### Deduplication

```rust
use bytesurgeon_core::{DeduplicationEngine, SmartDeduplicator};

let engine = DeduplicationEngine::new();
let dedup = SmartDeduplicator::new();
```

### Enterprise Case Management

```rust
use bytesurgeon_enterprise::CaseManager;

let case_mgr = CaseManager::new();
let case_id = case_mgr.create_case("CASE-2026-001", "Examiner Name")?;
let evidence_id = case_mgr.add_evidence(&case_id, "/dev/sda")?;
let report_path = case_mgr.generate_report(&case_id)?;
```

### Encryption Detection

```rust
use bytesurgeon_encryption::{EncryptedVolume, VolumeType};

// Detect and unlock encrypted volumes
```

### Recovery Filters

```rust
use bytesurgeon_core::{RecoveryFilter, RecoveryFilterBuilder};

let filter = RecoveryFilterBuilder::new()
    .with_extensions(&["jpg", "png", "pdf"])
    .with_min_size(1024)
    .with_max_size(100 * 1024 * 1024)
    .build();
```

### Dry Run

```rust
use bytesurgeon_core::{DryRunExecutor, DryRunContext};

let executor = DryRunExecutor::new();
```

### Stream Processing

```rust
use bytesurgeon_core::{StreamProcessor, StreamChunk};

let processor = StreamProcessor::new();
```

---

## Error Handling

All core operations return `bytesurgeon_core::Result<T>`:

```rust
pub type Result<T> = std::result::Result<T, Error>;
```

### Error Variants

| Variant | Description |
|---------|-------------|
| `Error::Io` | I/O operation failed |
| `Error::Database` | SQLite database error |
| `Error::Serialization` | JSON serialization error |
| `Error::InvalidDevice` | Device path invalid or inaccessible |
| `Error::UnsupportedFileSystem` | File system not recognized |
| `Error::RecoveryFailed` | Recovery operation failed |
| `Error::SecurityViolation` | Security policy violation |
| `Error::ThreatDetected` | Malware detected in file |
| `Error::DecryptionFailed` | Decryption operation failed |
| `Error::PermissionDenied` | Insufficient permissions |
| `Error::Cancelled` | Operation cancelled by user |
| `Error::ResourceExhausted` | System resources depleted |
| `Error::PartitionParse` | Partition table parse error |
| `Error::InvalidPartitionTable` | Invalid partition table |

### Error Handling Example

```rust
use bytesurgeon_core::{RecoveryEngine, Error};
use std::path::Path;

match RecoveryEngine::new(Path::new("./data")) {
    Ok(engine) => { /* use engine */ },
    Err(Error::PermissionDenied(msg)) => {
        eprintln!("Permission denied: {}", msg);
        eprintln!("Try running with elevated privileges");
    },
    Err(Error::Io(e)) => {
        eprintln!("I/O error: {}", e);
    },
    Err(e) => {
        eprintln!("Unexpected error: {}", e);
    }
}
```

---

## Cargo Dependencies

```toml
[workspace.dependencies]
tokio = { version = "1.36", features = ["full"] }
async-trait = "0.1"
thiserror = "1.0"
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tracing = "0.1"
uuid = { version = "1.7", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
hex = "0.4"
sha2 = "0.10"
aes-gcm = "0.10"
argon2 = "0.5"
rand = "0.8"
rayon = "1.8"
crossbeam = "0.8"
parking_lot = "0.12"
memmap2 = "0.9"
rusqlite = { version = "0.31", features = ["bundled"] }
nom = "7.1"
regex = "1.10"
dashmap = "5.5"
```

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux x86_64 | Full | Requires libudev, libusb |
| macOS x86_64/arm64 | Full | Requires Xcode CLT |
| Windows x86_64 | Full | Requires VS Build Tools |
| Linux aarch64 | Partial | Community supported |

---

## Performance

Typical benchmarks on modern hardware (NVMe SSD):

| Operation | Throughput |
|-----------|-----------|
| Signature Scan | ~500 MB/s |
| Deep Scan | ~200 MB/s |
| File Carving (serial) | ~300 MB/s |
| File Carving (parallel) | ~800 MB/s |
| Memory-mapped Scan | ~1.2 GB/s |
| Threat Scan | ~100 MB/s per thread |
| Memory Usage (typical) | < 500 MB |

---

## Versioning

Byte Surgeon follows semantic versioning: `MAJOR.MINOR.PATCH`

- **1.0.0**: Initial release
- **1.1.0** (Q1 2026): RAID reconstruction, cloud recovery
- **1.2.0** (Q2 2026): ML classification, distributed recovery
- **2.0.0** (Q4 2026): Blockchain integrity, quantum-resistant encryption
