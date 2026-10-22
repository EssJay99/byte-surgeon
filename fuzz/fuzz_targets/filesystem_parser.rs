#![no_main]

use bytesurgeon_filesystem::FileSystem;
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    fuzz_ntfs(data);
    fuzz_fat32(data);
    fuzz_ext4(data);
    fuzz_apfs(data);
});

fn fuzz_ntfs(data: &[u8]) {
    let mut padded = Vec::with_capacity(8192);
    padded.extend_from_slice(data);
    padded.resize(8192, 0);

    let tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(&padded).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        if let Ok(parser) = bytesurgeon_filesystem::NTFSParser::new(&path) {
            let _ = parser.read_superblock();
            let _ = parser.list_root_directory();
        }
    });
}

fn fuzz_fat32(data: &[u8]) {
    let mut padded = Vec::with_capacity(8192);
    padded.extend_from_slice(data);
    padded.resize(8192, 0);

    let tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(&padded).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        if let Ok(parser) = bytesurgeon_filesystem::FAT32Parser::new(&path) {
            let _ = parser.read_superblock();
            let _ = parser.list_root_directory();
        }
    });
}

fn fuzz_ext4(data: &[u8]) {
    let mut padded = Vec::with_capacity(8192);
    padded.extend_from_slice(data);
    padded.resize(8192, 0);

    let tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(&padded).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        if let Ok(parser) = bytesurgeon_filesystem::EXT4Parser::new(&path) {
            let _ = parser.read_superblock();
            let _ = parser.list_root_directory();
        }
    });
}

fn fuzz_apfs(data: &[u8]) {
    let mut padded = Vec::with_capacity(8192);
    padded.extend_from_slice(data);
    padded.resize(8192, 0);

    let tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return,
    };
    if tmp.as_file().write_all(&padded).is_err() {
        return;
    }
    let path = tmp.path().to_string_lossy().to_string();

    let _ = std::panic::catch_unwind(|| {
        if let Ok(parser) = bytesurgeon_filesystem::APFSParser::new(&path) {
            let _ = parser.read_superblock();
            let _ = parser.list_root_directory();
        }
    });
}
