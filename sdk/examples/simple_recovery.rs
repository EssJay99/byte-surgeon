use bytesurgeon_sdk::RecoveryBuilder;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let report = RecoveryBuilder::new()
        .device("/dev/sda")
        .output_dir("./recovered_files")
        .data_dir("./recovery_data")
        .deep_scan()
        .on_file_recovered(|file| {
            println!(
                "Recovered: {} ({} bytes) -> {}",
                file.extension, file.file_size, file.recovered_path
            );
        })
        .on_complete(|report| {
            println!("--- Recovery Report ---");
            println!("Session:    {}", report.session_id);
            println!("Found:      {}", report.files_found);
            println!("Recovered:  {}", report.files_recovered);
            println!("Total size: {} bytes", report.total_bytes_recovered);
        })
        .build()
        .expect("Failed to build recovery operation")
        .execute()
        .expect("Recovery failed");

    println!("\nRecovery finished. Session ID: {}", report.session_id);
}
