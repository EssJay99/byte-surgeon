use bytesurgeon_sdk::{
    SignatureScanner, SignatureCategory,
};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let args: Vec<String> = std::env::args().collect();
    let target_path = args.get(1).map(|s| s.as_str()).unwrap_or("/dev/sda");

    println!("Custom signature scan on: {}", target_path);

    let image_scanner = SignatureScanner::new()
        .images_only()
        .videos_only();

    println!(
        "Loaded {} image/video signatures",
        image_scanner.total_signatures()
    );

    let doc_scanner = SignatureScanner::new()
        .documents_only()
        .extension("sqlite");

    println!(
        "Loaded {} document/database signatures",
        doc_scanner.total_signatures()
    );

    let media_scanner = SignatureScanner::new()
        .categories(&[
            SignatureCategory::Image,
            SignatureCategory::Video,
            SignatureCategory::Audio,
        ]);

    println!(
        "Loaded {} media signatures",
        media_scanner.total_signatures()
    );

    match media_scanner.scan_path(target_path) {
        Ok(hits) => {
            println!("\nFound {} signature hits:", hits.len());
            for hit in &hits {
                println!(
                    "  offset=0x{:010X}  .{}  {}  [{}]",
                    hit.offset, hit.extension, hit.description, hit.category
                );
            }

            let mut by_category = std::collections::HashMap::new();
            for hit in &hits {
                *by_category.entry(hit.category.clone()).or_insert(0u64) += 1;
            }

            println!("\nHits by category:");
            for (cat, count) in &by_category {
                println!("  {}: {}", cat, count);
            }
        }
        Err(e) => {
            eprintln!("Scan failed: {}", e);
        }
    }
}
