# Byte Surgeon SDK

High-level Rust SDK for building custom data recovery and forensic tools on top of the Byte Surgeon engine.

## Quick Start

Add the SDK to your `Cargo.toml`:

```toml
[dependencies]
bytesurgeon-sdk = { path = "../sdk" }
```

## Core Components

### RecoveryBuilder

Fluent API for configuring and executing recovery operations:

```rust
use bytesurgeon_sdk::{RecoveryBuilder, ScanType};

let report = RecoveryBuilder::new()
    .device("/dev/sda")
    .output_dir("./recovered")
    .data_dir("./metadata")
    .deep_scan()
    .on_file_recovered(|file| {
        println!("Recovered: {} ({} bytes)", file.extension, file.file_size);
    })
    .on_complete(|report| {
        println!("Done: {} files recovered", report.files_recovered);
    })
    .build()?
    .execute()?;
```

Scan types: `.quick_scan()`, `.deep_scan()`, `.signature_scan()`, `.filesystem_scan()`, `.raw_scan()`.

### DeviceScanner

Enumerate and filter connected devices:

```rust
use bytesurgeon_sdk::{DeviceScanner, DeviceType};

let devices = DeviceScanner::new()
    .usb_only()
    .scan()?;

for dev in &devices {
    println!("{}: {} ({})", dev.path, dev.name, dev.device_type);
}
```

Filter methods: `.filter_by_type()`, `.filter_by_filesystem()`, `.min_size()`, `.max_size()`, `.usb_only()`, `.hard_drives_only()`, `.ssd_only()`.

### SignatureScanner

Scan for file signatures by category or extension:

```rust
use bytesurgeon_sdk::{SignatureScanner, SignatureCategory};

let scanner = SignatureScanner::new()
    .images_only()
    .documents_only();

let hits = scanner.scan_path("/dev/sda")?;
for hit in &hits {
    println!("0x{:010X}: .{} - {}", hit.offset, hit.extension, hit.description);
}
```

Category filters: `.images_only()`, `.documents_only()`, `.videos_only()`, `.audio_only()`, `.archives_only()`, `.category()`, `.extension()`.

### ProgressReporter

Track recovery progress with callbacks:

```rust
use bytesurgeon_sdk::ProgressReporter;

let reporter = ProgressReporter::new(total_bytes)
    .on_update(|snap| {
        println!("{:.1}% - {:.1} MB/s - ETA: {:?}",
            snap.percentage,
            snap.bytes_per_second / (1024.0 * 1024.0),
            snap.estimated_remaining_secs,
        );
    });
```

### Error Handling

All SDK operations return `SdkResult<T>` with rich error context:

```rust
use bytesurgeon_sdk::{SdkError, SdkResult};

match RecoveryBuilder::new().device("/dev/sda").build() {
    Ok(op) => { /* ... */ }
    Err(SdkError::Config(msg)) => eprintln!("Configuration error: {}", msg),
    Err(SdkError::Device(msg)) => eprintln!("Device error: {}", msg),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Examples

Build and run the included examples:

```bash
cargo run --example simple_recovery
cargo run --example batch_processing
cargo run --example custom_scanner -- /path/to/device
cargo run --example forensic_workflow -- /path/to/device ./output
```

### simple_recovery

Basic single-device file recovery with callbacks.

### batch_processing

Iterates over all detected devices and runs recovery on each.

### custom_scanner

Demonstrates custom signature scanning with category and extension filters.

### forensic_workflow

Complete forensic workflow: device enumeration, signature pre-scan, fragment analysis, shadow copy detection, USN journal parsing, and full recovery.

## Re-exports

The SDK re-exports all public types from the core crates for convenience:

- `bytesurgeon_core` - Engine, models, scanner, carver, filters, signatures
- `bytesurgeon_devices` - Device detector
- `bytesurgeon_filesystem` - File system parsers (NTFS, FAT32, ext4, APFS)
- `bytesurgeon_forensic` - Fragment scanner, shadow copies, USN journal, registry
- `bytesurgeon_encryption` - Encrypted volume support
