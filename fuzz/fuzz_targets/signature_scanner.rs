#![no_main]

use datadoctor_core::SignatureDatabase;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let db = SignatureDatabase::new();

    let _ = std::panic::catch_unwind(|| {
        let _ = db.identify(data);
        let _ = db.identify_all(data);
    });

    for offset in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
        if data.len() > offset {
            let _ = std::panic::catch_unwind(|| {
                let _ = db.identify(&data[offset..]);
            });
        }
    }

    let _ = std::panic::catch_unwind(|| {
        for cat_name in &["image", "document", "audio", "video", "archive", "database", "executable", "email", "diskimage", "compressed", "certificate", "unknown"] {
            let _ = db.by_category_name(cat_name);
        }
    });
});
