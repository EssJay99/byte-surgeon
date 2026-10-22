use crate::{Result, Error, FileSignature};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use tracing::{info, debug, warn};

const MMAP_THRESHOLD: u64 = 64 * 1024;
const CHUNK_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_SIGNATURE_LEN: usize = 16;

pub struct DiskScanner {
    device_path: String,
    block_size: usize,
    file_signatures: Vec<FileSignature>,
    cancelled: Arc<AtomicBool>,
    position: Arc<AtomicU64>,
    bytes_scanned: Arc<AtomicU64>,
}

impl DiskScanner {
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: device_path.to_string(),
            block_size: 4096,
            file_signatures: Self::load_signatures(),
            cancelled: Arc::new(AtomicBool::new(false)),
            position: Arc::new(AtomicU64::new(0)),
            bytes_scanned: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    fn load_signatures() -> Vec<FileSignature> {
        vec![
            FileSignature {
                extension: "jpg".to_string(),
                magic_bytes: vec![0xFF, 0xD8, 0xFF],
                offset: 0,
                description: "JPEG Image".to_string(),
                category: "Image".to_string(),
            },
            FileSignature {
                extension: "png".to_string(),
                magic_bytes: vec![0x89, 0x50, 0x4E, 0x47],
                offset: 0,
                description: "PNG Image".to_string(),
                category: "Image".to_string(),
            },
            FileSignature {
                extension: "pdf".to_string(),
                magic_bytes: vec![0x25, 0x50, 0x44, 0x46],
                offset: 0,
                description: "PDF Document".to_string(),
                category: "Document".to_string(),
            },
            FileSignature {
                extension: "zip".to_string(),
                magic_bytes: vec![0x50, 0x4B, 0x03, 0x04],
                offset: 0,
                description: "ZIP Archive".to_string(),
                category: "Archive".to_string(),
            },
            FileSignature {
                extension: "docx".to_string(),
                magic_bytes: vec![0x50, 0x4B, 0x03, 0x04],
                offset: 0,
                description: "Word Document".to_string(),
                category: "Document".to_string(),
            },
            FileSignature {
                extension: "mp4".to_string(),
                magic_bytes: vec![0x00, 0x00, 0x00],
                offset: 0,
                description: "MP4 Video".to_string(),
                category: "Video".to_string(),
            },
            FileSignature {
                extension: "mp3".to_string(),
                magic_bytes: vec![0xFF, 0xFB],
                offset: 0,
                description: "MP3 Audio".to_string(),
                category: "Audio".to_string(),
            },
            FileSignature {
                extension: "gif".to_string(),
                magic_bytes: vec![0x47, 0x49, 0x46, 0x38],
                offset: 0,
                description: "GIF Image".to_string(),
                category: "Image".to_string(),
            },
            FileSignature {
                extension: "exe".to_string(),
                magic_bytes: vec![0x4D, 0x5A],
                offset: 0,
                description: "Windows Executable".to_string(),
                category: "Executable".to_string(),
            },
            FileSignature {
                extension: "elf".to_string(),
                magic_bytes: vec![0x7F, 0x45, 0x4C, 0x46],
                offset: 0,
                description: "Linux Executable".to_string(),
                category: "Executable".to_string(),
            },
            FileSignature {
                extension: "sqlite".to_string(),
                magic_bytes: vec![0x53, 0x51, 0x4C, 0x69],
                offset: 0,
                description: "SQLite Database".to_string(),
                category: "Database".to_string(),
            },
            FileSignature {
                extension: "rar".to_string(),
                magic_bytes: vec![0x52, 0x61, 0x72, 0x21],
                offset: 0,
                description: "RAR Archive".to_string(),
                category: "Archive".to_string(),
            },
            FileSignature {
                extension: "7z".to_string(),
                magic_bytes: vec![0x37, 0x7A, 0xBC, 0xAF],
                offset: 0,
                description: "7-Zip Archive".to_string(),
                category: "Archive".to_string(),
            },
            FileSignature {
                extension: "psd".to_string(),
                magic_bytes: vec![0x38, 0x42, 0x50, 0x53],
                offset: 0,
                description: "Photoshop Document".to_string(),
                category: "Image".to_string(),
            },
            FileSignature {
                extension: "mov".to_string(),
                magic_bytes: vec![0x00, 0x00, 0x00],
                offset: 0,
                description: "QuickTime Video".to_string(),
                category: "Video".to_string(),
            },
        ]
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn get_progress(&self) -> (u64, u64) {
        (self.position.load(Ordering::SeqCst), self.bytes_scanned.load(Ordering::SeqCst))
    }

    pub fn scan_raw<F>(&self, mut callback: F) -> Result<Vec<DiscoveredSector>>
    where
        F: FnMut(&[u8], u64) -> bool,
    {
        info!("Starting raw scan of device: {}", self.device_path);
        
        let mut file = File::open(&self.device_path)
            .map_err(Error::Io)?;

        let total_size = file.metadata()?.len();
        let mut buffer = vec![0u8; self.block_size];
        let mut position = 0u64;
        let mut discovered = Vec::new();

        loop {
            if self.is_cancelled() {
                info!("Scan cancelled by user");
                return Err(Error::Cancelled);
            }

            file.seek(SeekFrom::Start(position))?;
            let bytes_read = file.read(&mut buffer)?;

            if bytes_read == 0 {
                break;
            }

            self.position.store(position, Ordering::SeqCst);
            self.bytes_scanned.fetch_add(bytes_read as u64, Ordering::SeqCst);

            if callback(&buffer[..bytes_read], position) {
                discovered.push(DiscoveredSector {
                    offset: position,
                    data: buffer[..bytes_read].to_vec(),
                });
            }

            position += bytes_read as u64;

            if position.is_multiple_of(100 * 1024 * 1024) {
                debug!("Scan progress: {} / {} bytes", position, total_size);
            }
        }

        info!("Raw scan completed. Found {} sectors", discovered.len());
        Ok(discovered)
    }

    pub fn find_signatures(&self) -> Result<Vec<SignatureMatch>> {
        info!("Scanning for file signatures in: {}", self.device_path);
        
        let mut file = File::open(&self.device_path)?;
        let _total_size = file.metadata()?.len();
        let mut buffer = vec![0u8; self.block_size];
        let mut position = 0u64;
        let mut matches = Vec::new();

        loop {
            if self.is_cancelled() {
                info!("Signature scan cancelled");
                return Err(Error::Cancelled);
            }

            file.seek(SeekFrom::Start(position))?;
            let bytes_read = file.read(&mut buffer)?;

            if bytes_read == 0 {
                break;
            }

            self.position.store(position, Ordering::SeqCst);
            self.bytes_scanned.fetch_add(bytes_read as u64, Ordering::SeqCst);

            for sig in &self.file_signatures {
                if bytes_read >= sig.offset + sig.magic_bytes.len() {
                    let slice = &buffer[sig.offset..sig.offset + sig.magic_bytes.len()];
                    if slice == sig.magic_bytes.as_slice() {
                        matches.push(SignatureMatch {
                            offset: position + sig.offset as u64,
                            signature: sig.clone(),
                        });
                        debug!("Found {} at offset {}", sig.extension, position + sig.offset as u64);
                    }
                }
            }

            position += bytes_read as u64;
        }

        info!("Signature scan completed. Found {} matches", matches.len());
        Ok(matches)
    }

    pub fn get_file_signatures(&self) -> &[FileSignature] {
        &self.file_signatures
    }
}

pub struct MmapScanner {
    file_signatures: Vec<FileSignature>,
    cancelled: Arc<AtomicBool>,
    bytes_scanned: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct MmapScanResult {
    pub offset: u64,
    pub signature: FileSignature,
}

impl MmapScanner {
    pub fn new() -> Self {
        Self {
            file_signatures: DiskScanner::load_signatures(),
            cancelled: Arc::new(AtomicBool::new(false)),
            bytes_scanned: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_signatures(signatures: Vec<FileSignature>) -> Self {
        Self {
            file_signatures: signatures,
            cancelled: Arc::new(AtomicBool::new(false)),
            bytes_scanned: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned.load(Ordering::SeqCst)
    }

    pub fn scan_file(&self, path: &str) -> Result<Vec<MmapScanResult>> {
        let file = File::open(path).map_err(Error::Io)?;
        let file_size = file.metadata()?.len();

        if file_size < MMAP_THRESHOLD {
            debug!("File {} bytes < threshold, using regular I/O", file_size);
            return self.scan_regular_io(path);
        }

        match self.try_mmap_scan(&file, file_size) {
            Ok(results) => Ok(results),
            Err(e) => {
                warn!("mmap failed ({}), falling back to regular I/O", e);
                self.scan_regular_io(path)
            }
        }
    }

    fn try_mmap_scan(&self, file: &File, file_size: u64) -> Result<Vec<MmapScanResult>> {
        if file_size <= CHUNK_SIZE {
            self.scan_mmap_full(file, file_size)
        } else {
            self.scan_mmap_chunked(file, file_size)
        }
    }

    fn scan_mmap_full(&self, file: &File, file_size: u64) -> Result<Vec<MmapScanResult>> {
        use memmap2::Mmap;

        info!("Memory-mapping file ({} bytes)", file_size);
        let mmap = unsafe { Mmap::map(file) }.map_err(|e| Error::Io(e))?;

        let mut matches = Vec::new();
        self.bytes_scanned.store(0, Ordering::SeqCst);

        let max_sig_len = self.max_signature_len();
        let scan_end = file_size.saturating_sub(max_sig_len as u64 - 1);

        for offset in 0..=scan_end as usize {
            if self.cancelled.load(Ordering::SeqCst) {
                info!("mmap scan cancelled");
                return Err(Error::Cancelled);
            }

            for sig in &self.file_signatures {
                let end = offset + sig.offset + sig.magic_bytes.len();
                if end > mmap.len() {
                    continue;
                }
                if &mmap[offset + sig.offset..end] == sig.magic_bytes.as_slice() {
                    matches.push(MmapScanResult {
                        offset: offset as u64 + sig.offset as u64,
                        signature: sig.clone(),
                    });
                    debug!("mmap: found {} at offset {}", sig.extension, offset as u64 + sig.offset as u64);
                }
            }

            self.bytes_scanned.store(offset as u64, Ordering::SeqCst);
        }

        info!("mmap full scan complete: {} matches in {} bytes", matches.len(), file_size);
        Ok(matches)
    }

    fn scan_mmap_chunked(&self, file: &File, file_size: u64) -> Result<Vec<MmapScanResult>> {
        use memmap2::MmapOptions;

        info!("Chunked mmap scan: {} bytes in {}-byte chunks", file_size, CHUNK_SIZE);
        let mut matches = Vec::new();
        self.bytes_scanned.store(0, Ordering::SeqCst);

        let max_sig_len = self.max_signature_len() as u64;
        let overlap = max_sig_len - 1;
        let mut chunk_start: u64 = 0;

        while chunk_start < file_size {
            if self.cancelled.load(Ordering::SeqCst) {
                info!("Chunked mmap scan cancelled");
                return Err(Error::Cancelled);
            }

            let remaining = file_size - chunk_start;
            let map_len = std::cmp::min(remaining, CHUNK_SIZE + if chunk_start > 0 { overlap } else { 0 });
            let map_offset = if chunk_start > 0 && chunk_start >= overlap {
                chunk_start - overlap
            } else {
                chunk_start
            };
            let actual_len = std::cmp::min(file_size - map_offset, map_len + overlap);

            debug!("Mapping chunk: offset={}, len={}", map_offset, actual_len);

            let mmap = unsafe {
                MmapOptions::new()
                    .offset(map_offset)
                    .len(actual_len as usize)
                    .map(file)
            }.map_err(|e| Error::Io(e))?;

            let local_start = (chunk_start - map_offset) as usize;
            let local_end = if remaining <= CHUNK_SIZE {
                mmap.len()
            } else {
                std::cmp::min(mmap.len(), local_start + CHUNK_SIZE as usize + overlap as usize)
            };

            let scan_limit = if local_end > max_sig_len as usize {
                local_end - max_sig_len as usize + 1
            } else {
                0
            };

            for local_offset in local_start..scan_limit {
                for sig in &self.file_signatures {
                    let end = local_offset + sig.offset + sig.magic_bytes.len();
                    if end > mmap.len() {
                        continue;
                    }
                    if &mmap[local_offset + sig.offset..end] == sig.magic_bytes.as_slice() {
                        let absolute_offset = map_offset + local_offset as u64 + sig.offset as u64;
                        if absolute_offset >= chunk_start {
                            matches.push(MmapScanResult {
                                offset: absolute_offset,
                                signature: sig.clone(),
                            });
                            debug!("mmap chunk: found {} at offset {}", sig.extension, absolute_offset);
                        }
                    }
                }
            }

            let chunk_bytes = if remaining <= CHUNK_SIZE { remaining } else { CHUNK_SIZE };
            self.bytes_scanned.fetch_add(chunk_bytes, Ordering::SeqCst);
            chunk_start += chunk_bytes;
        }

        info!("Chunked mmap scan complete: {} matches in {} bytes", matches.len(), file_size);
        Ok(matches)
    }

    fn scan_regular_io(&self, path: &str) -> Result<Vec<MmapScanResult>> {
        info!("Regular I/O scan: {}", path);

        let mut file = File::open(path).map_err(Error::Io)?;
        let block_size = 1024 * 1024;
        let mut buffer = vec![0u8; block_size];
        let mut position = 0u64;
        let mut matches = Vec::new();

        self.bytes_scanned.store(0, Ordering::SeqCst);

        loop {
            if self.cancelled.load(Ordering::SeqCst) {
                return Err(Error::Cancelled);
            }

            file.seek(SeekFrom::Start(position)).map_err(Error::Io)?;
            let bytes_read = file.read(&mut buffer).map_err(Error::Io)?;
            if bytes_read == 0 {
                break;
            }

            let max_sig_len = self.max_signature_len();
            let scan_limit = if bytes_read >= max_sig_len {
                bytes_read - max_sig_len + 1
            } else {
                0
            };

            for offset in 0..scan_limit {
                for sig in &self.file_signatures {
                    let end = offset + sig.offset + sig.magic_bytes.len();
                    if end > bytes_read {
                        continue;
                    }
                    if &buffer[offset + sig.offset..end] == sig.magic_bytes.as_slice() {
                        matches.push(MmapScanResult {
                            offset: position + offset as u64 + sig.offset as u64,
                            signature: sig.clone(),
                        });
                    }
                }
            }

            self.bytes_scanned.fetch_add(bytes_read as u64, Ordering::SeqCst);
            position += bytes_read as u64;
        }

        info!("Regular I/O scan complete: {} matches", matches.len());
        Ok(matches)
    }

    fn max_signature_len(&self) -> usize {
        self.file_signatures
            .iter()
            .map(|s| s.offset + s.magic_bytes.len())
            .max()
            .unwrap_or(MAX_SIGNATURE_LEN)
    }
}

impl Default for MmapScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredSector {
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub offset: u64,
    pub signature: FileSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_disk_scanner_creation() {
        let scanner = DiskScanner::new("/dev/null");
        assert!(!scanner.is_cancelled());
        let (pos, scanned) = scanner.get_progress();
        assert_eq!(pos, 0);
        assert_eq!(scanned, 0);
    }

    #[test]
    fn test_signature_database_loading() {
        let scanner = DiskScanner::new("/dev/null");
        let sigs = scanner.get_file_signatures();
        let extensions: Vec<&str> = sigs.iter().map(|s| s.extension.as_str()).collect();
        assert!(extensions.contains(&"jpg"));
        assert!(extensions.contains(&"png"));
        assert!(extensions.contains(&"pdf"));
        assert!(extensions.contains(&"zip"));
        assert!(extensions.contains(&"mp3"));
        assert!(extensions.contains(&"gif"));
        assert!(extensions.contains(&"exe"));
        assert!(extensions.contains(&"elf"));
        assert!(extensions.contains(&"sqlite"));
        assert!(extensions.contains(&"rar"));
        assert!(extensions.contains(&"7z"));
        assert!(extensions.contains(&"docx"));
        assert!(extensions.contains(&"psd"));
        assert!(sigs.len() >= 14);
    }

    #[test]
    fn test_file_signature_matching_jpeg() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]).unwrap();
        tmp.flush().unwrap();

        let scanner = DiskScanner::new(tmp.path().to_str().unwrap());
        let matches = scanner.find_signatures().unwrap();
        assert!(!matches.is_empty());
        let jpg_match = matches.iter().find(|m| m.signature.extension == "jpg");
        assert!(jpg_match.is_some());
        assert_eq!(jpg_match.unwrap().offset, 0);
    }

    #[test]
    fn test_file_signature_matching_png() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
        tmp.flush().unwrap();

        let scanner = DiskScanner::new(tmp.path().to_str().unwrap());
        let matches = scanner.find_signatures().unwrap();
        let png_match = matches.iter().find(|m| m.signature.extension == "png");
        assert!(png_match.is_some());
    }

    #[test]
    fn test_cancellation_mechanism() {
        let scanner = DiskScanner::new("/dev/null");
        assert!(!scanner.is_cancelled());
        scanner.cancel();
        assert!(scanner.is_cancelled());
    }

    #[test]
    fn test_progress_tracking() {
        let mut tmp = NamedTempFile::new().unwrap();
        let data = vec![0u8; 8192];
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let scanner = DiskScanner::new(tmp.path().to_str().unwrap());
        let _ = scanner.find_signatures().unwrap();
        let (_pos, scanned) = scanner.get_progress();
        assert!(scanned > 0);
    }

    #[test]
    fn test_with_block_size() {
        let scanner = DiskScanner::new("/dev/null").with_block_size(8192);
        assert_eq!(scanner.block_size, 8192);
    }

    #[test]
    fn test_load_signatures() {
        let scanner = DiskScanner::new("/dev/null");
        let signatures = scanner.get_file_signatures();
        assert!(!signatures.is_empty());
    }

    #[test]
    fn test_mmap_scanner_creation() {
        let scanner = MmapScanner::new();
        assert_eq!(scanner.bytes_scanned(), 0);
    }

    #[test]
    fn test_mmap_scan_jpeg_signature() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 128 * 1024];
        data[0] = 0xFF;
        data[1] = 0xD8;
        data[2] = 0xFF;
        data[64 * 1024] = 0xFF;
        data[64 * 1024 + 1] = 0xD8;
        data[64 * 1024 + 2] = 0xFF;
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let scanner = MmapScanner::new();
        let matches = scanner.scan_file(tmp.path().to_str().unwrap()).unwrap();
        let jpg_matches: Vec<_> = matches.iter().filter(|m| m.signature.extension == "jpg").collect();
        assert_eq!(jpg_matches.len(), 2);
        assert_eq!(jpg_matches[0].offset, 0);
        assert_eq!(jpg_matches[1].offset, 64 * 1024);
    }

    #[test]
    fn test_mmap_scan_small_file_falls_back() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();
        tmp.flush().unwrap();

        let scanner = MmapScanner::new();
        let matches = scanner.scan_file(tmp.path().to_str().unwrap()).unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_mmap_scan_multiple_signatures() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 256 * 1024];
        data[0] = 0xFF;
        data[1] = 0xD8;
        data[2] = 0xFF;
        data[128 * 1024] = 0x89;
        data[128 * 1024 + 1] = 0x50;
        data[128 * 1024 + 2] = 0x4E;
        data[128 * 1024 + 3] = 0x47;
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let scanner = MmapScanner::new();
        let matches = scanner.scan_file(tmp.path().to_str().unwrap()).unwrap();
        assert!(matches.iter().any(|m| m.signature.extension == "jpg"));
        assert!(matches.iter().any(|m| m.signature.extension == "png"));
    }

    #[test]
    fn test_mmap_cancellation() {
        let mut tmp = NamedTempFile::new().unwrap();
        let data = vec![0u8; 128 * 1024];
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let scanner = MmapScanner::new();
        scanner.cancel();
        let result = scanner.scan_file(tmp.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_mmap_vs_regular_io_consistency() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 256 * 1024];
        data[0] = 0xFF;
        data[1] = 0xD8;
        data[2] = 0xFF;
        data[4096] = 0x89;
        data[4096 + 1] = 0x50;
        data[4096 + 2] = 0x4E;
        data[4096 + 3] = 0x47;
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_str().unwrap();

        let mmap_scanner = MmapScanner::new();
        let mmap_matches = mmap_scanner.scan_file(path).unwrap();

        let disk_scanner = DiskScanner::new(path);
        let disk_matches = disk_scanner.find_signatures().unwrap();

        let mmap_jpg = mmap_matches.iter().filter(|m| m.signature.extension == "jpg").count();
        let disk_jpg = disk_matches.iter().filter(|m| m.signature.extension == "jpg").count();
        assert_eq!(mmap_jpg, disk_jpg);

        let mmap_png = mmap_matches.iter().filter(|m| m.signature.extension == "png").count();
        let disk_png = disk_matches.iter().filter(|m| m.signature.extension == "png").count();
        assert_eq!(mmap_png, disk_png);
    }

    #[test]
    fn test_benchmark_mmap_vs_regular_io() {
        use std::time::Instant;

        let mut tmp = NamedTempFile::new().unwrap();
        let size = 16 * 1024 * 1024;
        let mut data = vec![0u8; size];
        let step = 4096;
        for i in (0..size).step_by(step) {
            if i + 3 < size {
                data[i] = 0xFF;
                data[i + 1] = 0xD8;
                data[i + 2] = 0xFF;
            }
        }
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_str().unwrap();

        let regular_start = Instant::now();
        let disk_scanner = DiskScanner::new(path);
        let regular_matches = disk_scanner.find_signatures().unwrap();
        let regular_duration = regular_start.elapsed();

        let mmap_scanner = MmapScanner::new();
        let mmap_start = Instant::now();
        let mmap_matches = mmap_scanner.scan_file(path).unwrap();
        let mmap_duration = mmap_start.elapsed();

        assert_eq!(
            regular_matches.iter().filter(|m| m.signature.extension == "jpg").count(),
            mmap_matches.iter().filter(|m| m.signature.extension == "jpg").count()
        );

        eprintln!("Regular I/O: {:?} ({} matches)", regular_duration, regular_matches.len());
        eprintln!("mmap I/O:    {:?} ({} matches)", mmap_duration, mmap_matches.len());
    }
}
