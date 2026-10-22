use bytesurgeon_sdk::{
    RecoveryBuilder, DeviceScanner,
    RecoveryReport,
};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    println!("Scanning for devices...");

    let devices = DeviceScanner::new()
        .scan()
        .expect("Failed to scan devices");

    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    println!("Found {} device(s):", devices.len());
    for (i, dev) in devices.iter().enumerate() {
        println!(
            "  [{}] {} ({}) - {} [{}]",
            i, dev.name, dev.device_type, dev.file_system, dev.path
        );
    }

    let mut all_reports: Vec<RecoveryReport> = Vec::new();

    for dev in &devices {
        println!("\n--- Recovering from {} ---", dev.path);

        match RecoveryBuilder::new()
            .device(&dev.path)
            .output_dir(format!("./recovered/{}", dev.name))
            .data_dir(format!("./data/{}", dev.name))
            .signature_scan()
            .build()
        {
            Ok(op) => match op.execute() {
                Ok(report) => {
                    println!(
                        "  Found: {}, Recovered: {}, Size: {} bytes",
                        report.files_found, report.files_recovered, report.total_bytes_recovered
                    );
                    all_reports.push(report);
                }
                Err(e) => {
                    eprintln!("  Recovery failed: {}", e);
                }
            },
            Err(e) => {
                eprintln!("  Build failed: {}", e);
            }
        }
    }

    println!("\n=== Batch Summary ===");
    let total_found: u64 = all_reports.iter().map(|r| r.files_found).sum();
    let total_recovered: u64 = all_reports.iter().map(|r| r.files_recovered).sum();
    let total_bytes: u64 = all_reports.iter().map(|r| r.total_bytes_recovered).sum();
    println!("Devices processed: {}", all_reports.len());
    println!("Total files found: {}", total_found);
    println!("Total recovered:   {}", total_recovered);
    println!("Total bytes:       {}", total_bytes);
}
