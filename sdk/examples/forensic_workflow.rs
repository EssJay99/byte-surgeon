use bytesurgeon_sdk::{
    DeviceScanner, RecoveryBuilder, SignatureScanner,
    ProgressReporter,
    SignatureCategory,
};
use bytesurgeon_forensic;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let args: Vec<String> = std::env::args().collect();
    let device_path = args.get(1).map(|s| s.as_str()).unwrap_or("/dev/sda");
    let output_dir = args.get(2).map(|s| s.as_str()).unwrap_or("./forensic_output");

    println!("=== Byte Surgeon Forensic Workflow ===");
    println!("Device:  {}", device_path);
    println!("Output:  {}", output_dir);

    println!("\n[Step 1] Device enumeration and validation");
    let devices = DeviceScanner::new()
        .scan()
        .expect("Failed to enumerate devices");

    let target = devices.iter().find(|d| d.path == device_path);
    match target {
        Some(dev) => {
            println!("  Device:  {}", dev.name);
            println!("  Type:    {}", dev.device_type);
            println!("  FS:      {}", dev.file_system);
            println!("  Size:    {} bytes", dev.total_size);
            if let Some(ref vendor) = dev.vendor {
                println!("  Vendor:  {}", vendor);
            }
            if let Some(ref model) = dev.model {
                println!("  Model:   {}", model);
            }
        }
        None => {
            println!("  Device not in enumeration list, proceeding with raw path");
        }
    }

    println!("\n[Step 2] Signature pre-scan");
    let sig_scanner = SignatureScanner::new()
        .categories(&[
            SignatureCategory::Image,
            SignatureCategory::Document,
            SignatureCategory::Video,
            SignatureCategory::Audio,
            SignatureCategory::Archive,
            SignatureCategory::Database,
            SignatureCategory::Email,
        ]);

    println!("  Loaded {} signatures", sig_scanner.total_signatures());

    match sig_scanner.scan_path(device_path) {
        Ok(hits) => {
            println!("  Found {} signature hits", hits.len());
            let mut by_ext = std::collections::HashMap::new();
            for hit in &hits {
                *by_ext.entry(hit.extension.clone()).or_insert(0u64) += 1;
            }
            let mut sorted: Vec<_> = by_ext.into_iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1));
            for (ext, count) in sorted.iter().take(10) {
                println!("    .{}: {} hits", ext, count);
            }
        }
        Err(e) => {
            println!("  Pre-scan failed (non-fatal): {}", e);
        }
    }

    println!("\n[Step 3] Forensic analysis");

    let fragment_scanner = bytesurgeon_forensic::FragmentScanner::new();
    match fragment_scanner.scan(device_path) {
        Ok(fragments) => {
            println!("  Found {} file fragments", fragments.len());
            for frag in fragments.iter().take(5) {
                println!(
                    "    offset=0x{:010X} size={} sig={} confidence={:.2}",
                    frag.offset, frag.size, frag.signature, frag.confidence
                );
            }
        }
        Err(e) => {
            println!("  Fragment scan failed (non-fatal): {}", e);
        }
    }

    let shadow_copy_detector = bytesurgeon_forensic::ShadowCopyDetector::new();
    match shadow_copy_detector.detect(device_path) {
        Ok(copies) => {
            println!("  Found {} shadow copies", copies.len());
            for copy in &copies {
                println!("    ID: {} Volume: {} Size: {}", copy.id, copy.volume, copy.size);
            }
        }
        Err(e) => {
            println!("  Shadow copy detection failed (non-fatal): {}", e);
        }
    }

    let usn_parser = bytesurgeon_forensic::UsnJournalParser::new();
    match usn_parser.parse(device_path) {
        Ok(entries) => {
            println!("  Found {} USN journal entries", entries.len());
            for entry in entries.iter().take(5) {
                println!("    {} - {} ({})", entry.timestamp, entry.filename, entry.reason);
            }
        }
        Err(e) => {
            println!("  USN journal parse failed (non-fatal): {}", e);
        }
    }

    println!("\n[Step 4] Data recovery");

    let reporter = ProgressReporter::new(100)
        .on_update(|snap| {
            if snap.percentage >= 0.0 {
                print!(
                    "\r  Progress: {:.1}% | Speed: {:.1} MB/s | Files: {}",
                    snap.percentage,
                    snap.bytes_per_second / (1024.0 * 1024.0),
                    snap.files_recovered,
                );
            }
        });

    let report = RecoveryBuilder::new()
        .device(device_path)
        .output_dir(output_dir)
        .data_dir(format!("{}/.metadata", output_dir))
        .deep_scan()
        .on_progress(move |current, _total, files| {
            reporter.update(current);
            reporter.set_files_recovered(files);
        })
        .on_file_recovered(|file| {
            tracing::info!(
                "Recovered: .{} ({} bytes) integrity={:?}",
                file.extension,
                file.file_size,
                file.integrity_check,
            );
        })
        .build()
        .expect("Failed to build recovery operation")
        .execute()
        .expect("Recovery execution failed");

    println!("\n\n[Step 5] Final report");
    println!("  Session ID:      {}", report.session_id);
    println!("  Files found:     {}", report.files_found);
    println!("  Files recovered: {}", report.files_recovered);
    println!("  Total bytes:     {}", report.total_bytes_recovered);
    println!("\n=== Forensic workflow complete ===");
}
