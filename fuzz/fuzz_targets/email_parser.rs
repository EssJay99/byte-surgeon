#![no_main]

use bytesurgeon_chat::EmailRecoverer;
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    fuzz_pst(data);
    fuzz_mbox(data);
    fuzz_eml(data);
    fuzz_raw_email_bytes(data);
});

fn fuzz_pst(data: &[u8]) {
    let mut pst_data = Vec::with_capacity(data.len() + 68);
    pst_data.extend_from_slice(&[0x21, 0x42, 0x44, 0x4E]);
    pst_data.extend_from_slice(data);

    let tmp = match tempfile::Builder::new().suffix(".pst").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(&pst_data).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        let recoverer = EmailRecoverer::new();
        let _ = recoverer.recover(&path);
    });
}

fn fuzz_mbox(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mbox_content = format!("From test@example.com Mon Jan 01 00:00:00 2024\n{}\n", text);

    let tmp = match tempfile::Builder::new().suffix(".mbox").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(mbox_content.as_bytes()).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        let recoverer = EmailRecoverer::new();
        let _ = recoverer.recover(&path);
    });
}

fn fuzz_eml(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let eml_content = format!(
        "From: sender@test.com\r\nTo: recv@test.com\r\nSubject: Test\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n{}",
        text
    );

    let tmp = match tempfile::Builder::new().suffix(".eml").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(eml_content.as_bytes()).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        let recoverer = EmailRecoverer::new();
        let _ = recoverer.recover(&path);
    });
}

fn fuzz_raw_email_bytes(data: &[u8]) {
    let tmp = match tempfile::Builder::new().suffix(".dat").tempfile() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(data).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        let recoverer = EmailRecoverer::new();
        let _ = recoverer.recover(&path);
    });
}
