#![no_main]

use bytesurgeon_chat::{WhatsAppRecoverer, IMessageRecoverer, SqliteCarver};
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    fuzz_whatsapp(data);
    fuzz_imessage(data);
    fuzz_sqlite_carver(data);
    fuzz_imessage_date_parsing(data);
});

fn fuzz_whatsapp(data: &[u8]) {
    let tmp = match tempfile::Builder::new().suffix(".db").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(data).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        let recoverer = WhatsAppRecoverer::new();
        let _ = recoverer.recover(&path);
    });
}

fn fuzz_imessage(data: &[u8]) {
    let tmp = match tempfile::Builder::new().suffix(".db").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(data).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        let recoverer = IMessageRecoverer::new();
        let _ = recoverer.recover(&path);
    });
}

fn fuzz_sqlite_carver(data: &[u8]) {
    let tmp = match tempfile::Builder::new().suffix(".bin").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(data).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let out_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };

    let _ = std::panic::catch_unwind(|| {
        let carver = SqliteCarver::new();
        let _ = carver.carve(&path, out_dir.path());
    });
}

fn fuzz_imessage_date_parsing(data: &[u8]) {
    if data.len() < 8 {
        return;
    }

    let _ = std::panic::catch_unwind(|| {
        let recoverer = IMessageRecoverer::new();

        for window in data.windows(8) {
            let raw = i64::from_le_bytes([
                window[0], window[1], window[2], window[3],
                window[4], window[5], window[6], window[7],
            ]);
            let _ = parse_imessage_date_public(raw);
        }
        let _ = recoverer;
    });
}

fn parse_imessage_date_public(date_raw: i64) -> String {
    let epoch_offset: i64 = 978_307_200;

    let normalized = if date_raw > 1_000_000_000_000_000_000 {
        date_raw / 1_000_000_000
    } else if date_raw > 1_000_000_000_000 {
        date_raw / 1_000_000
    } else {
        date_raw
    };

    let unix_ts = normalized + epoch_offset;

    chrono::DateTime::from_timestamp(unix_ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "unknown".to_string())
}
