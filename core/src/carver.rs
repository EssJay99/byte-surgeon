use crate::{Result, RecoveredFile, RecoveryStatus, IntegrityStatus, ThreatStatus, FileSignature};
use crate::scanner::SignatureMatch;
use std::fs::{self, File};
use std::io::{Read, Write, Seek, SeekFrom, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{info, debug, warn};
use sha2::{Sha256, Digest};
use rayon::prelude::*;
use memmap2::Mmap;

pub struct FileCarver {
    output_dir: PathBuf,
    session_id: String,
    max_file_size: u64,
}

impl FileCarver {
    pub fn new(output_dir: &Path, session_id: &str) -> Self {
        Self {
            output_dir: output_dir.to_path_buf(),
            session_id: session_id.to_string(),
            max_file_size: 10 * 1024 * 1024 * 1024,
        }
    }

    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    pub fn carve_files<F>(
        &self,
        device_path: &str,
        signatures: &[SignatureMatch],
        mut progress_callback: F,
    ) -> Result<Vec<RecoveredFile>>
    where
        F: FnMut(usize, usize),
    {
        info!("Starting file carving for {} signatures", signatures.len());
        
        fs::create_dir_all(&self.output_dir)?;

        let mut device = File::open(device_path)?;
        let mut recovered_files = Vec::new();

        for (idx, sig_match) in signatures.iter().enumerate() {
            progress_callback(idx, signatures.len());

            match self.carve_single_file(&mut device, sig_match) {
                Ok(file) => {
                    if let Some(file) = file {
                        recovered_files.push(file);
                    }
                }
                Err(e) => {
                    warn!("Failed to carve file at offset {}: {}", sig_match.offset, e);
                }
            }
        }

        info!("File carving completed. Recovered {} files", recovered_files.len());
        Ok(recovered_files)
    }

    pub fn carve_files_parallel<F>(
        &self,
        device_path: &str,
        signatures: &[SignatureMatch],
        progress_callback: F,
    ) -> Result<Vec<RecoveredFile>>
    where
        F: Fn(usize, usize) + Send + Sync,
    {
        info!("Starting parallel file carving for {} signatures across {} threads",
            signatures.len(), rayon::current_num_threads());

        fs::create_dir_all(&self.output_dir)?;

        let device_file = File::open(device_path)?;
        let file_size = device_file.metadata()?.len();
        let mmap = unsafe { Mmap::map(&device_file)? };
        let data: &[u8] = &mmap;

        let progress = Arc::new(AtomicUsize::new(0));
        let total = signatures.len();
        let output_dir = self.output_dir.clone();
        let session_id = self.session_id.clone();
        let max_file_size = self.max_file_size;

        let results: Vec<Option<RecoveredFile>> = signatures
            .par_iter()
            .enumerate()
            .map(|(idx, sig_match)| {
                let result = Self::carve_from_data(
                    data,
                    file_size,
                    sig_match,
                    &output_dir,
                    &session_id,
                    max_file_size,
                    idx,
                );

                let completed = progress.fetch_add(1, Ordering::Relaxed) + 1;
                progress_callback(completed, total);

                match result {
                    Ok(file) => file,
                    Err(e) => {
                        warn!("Failed to carve file at offset {}: {}", sig_match.offset, e);
                        None
                    }
                }
            })
            .collect();

        let recovered_files: Vec<RecoveredFile> = results.into_iter().flatten().collect();

        info!("Parallel file carving completed. Recovered {} files", recovered_files.len());
        Ok(recovered_files)
    }

    fn carve_from_data(
        data: &[u8],
        device_size: u64,
        sig_match: &SignatureMatch,
        output_dir: &Path,
        session_id: &str,
        max_file_size: u64,
        index: usize,
    ) -> Result<Option<RecoveredFile>> {
        let offset = sig_match.offset as usize;

        if offset >= data.len() {
            return Ok(None);
        }

        let extension = &sig_match.signature.extension;
        let output_path = Self::generate_output_path_indexed(output_dir, session_id, extension, index);

        let slice = &data[offset..];
        let file_size = Self::estimate_file_size_from_slice(slice, device_size - sig_match.offset, &sig_match.signature, max_file_size)?;

        if file_size == 0 || file_size > max_file_size {
            debug!("Skipping file at {} (invalid size: {})", sig_match.offset, file_size);
            return Ok(None);
        }

        let file_size_usize = file_size as usize;
        if file_size_usize > slice.len() {
            debug!("Skipping file at {} (requested {} but only {} bytes remain)",
                sig_match.offset, file_size, slice.len());
            return Ok(None);
        }

        let buffer = &slice[..file_size_usize];

        let mut output_file = BufWriter::new(File::create(&output_path)?);
        output_file.write_all(buffer)?;
        output_file.flush()?;

        let hash = Self::calculate_hash_static(buffer);

        let mut recovered_file = RecoveredFile::new(session_id, &output_path.to_string_lossy());
        recovered_file.file_size = file_size;
        recovered_file.extension = extension.clone();
        recovered_file.file_type = sig_match.signature.category.clone();
        recovered_file.signature = hash;
        recovered_file.status = RecoveryStatus::Completed;
        recovered_file.integrity_check = IntegrityStatus::Verified;
        recovered_file.threat_scan = ThreatStatus::NotScanned;

        debug!("Recovered file: {} ({} bytes)", output_path.display(), file_size);
        Ok(Some(recovered_file))
    }

    fn estimate_file_size_from_slice(
        data: &[u8],
        remaining_in_device: u64,
        signature: &FileSignature,
        max_file_size: u64,
    ) -> Result<u64> {
        let estimated_size = match signature.extension.as_str() {
            "jpg" | "jpeg" => Self::find_jpeg_end_in_slice(data, max_file_size),
            "png" => Self::find_png_end_in_slice(data),
            "pdf" => Self::find_pdf_end_in_slice(data, max_file_size),
            "zip" | "docx" | "xlsx" | "pptx" => Self::find_zip_end_in_slice(data, max_file_size),
            _ => Ok(std::cmp::min(remaining_in_device, 1024 * 1024)),
        };
        estimated_size
    }

    fn find_jpeg_end_in_slice(data: &[u8], max_file_size: u64) -> Result<u64> {
        let limit = std::cmp::min(data.len(), max_file_size as usize);
        for i in 0..limit.saturating_sub(1) {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                return Ok(i as u64 + 2);
            }
        }
        Ok(0)
    }

    fn find_png_end_in_slice(data: &[u8]) -> Result<u64> {
        if data.len() < 16 {
            return Ok(0);
        }
        let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as u64;
        let total_size = 8 + 4 + 4 + length + 4;
        Ok(total_size)
    }

    fn find_pdf_end_in_slice(data: &[u8], max_file_size: u64) -> Result<u64> {
        let limit = std::cmp::min(data.len(), max_file_size as usize);
        let mut last_eof: Option<usize> = None;
        let search_bytes = b"%%EOF";

        let searchable = &data[..limit];
        let mut pos = 0;
        while pos + search_bytes.len() <= searchable.len() {
            if let Some(idx) = searchable[pos..].windows(search_bytes.len())
                .position(|w| w == search_bytes)
            {
                let found_at = pos + idx;
                last_eof = Some(found_at + search_bytes.len());
                pos = found_at + 1;
            } else {
                break;
            }
        }

        Ok(last_eof.unwrap_or(0) as u64)
    }

    fn find_zip_end_in_slice(data: &[u8], max_file_size: u64) -> Result<u64> {
        let limit = std::cmp::min(data.len(), max_file_size as usize);
        let searchable = &data[..limit];

        for i in 0..searchable.len().saturating_sub(21) {
            if searchable[i] == 0x50 && searchable[i + 1] == 0x4B
                && searchable[i + 2] == 0x05 && searchable[i + 3] == 0x06
            {
                let comment_len = u16::from_le_bytes([searchable[i + 20], searchable[i + 21]]) as u64;
                return Ok(i as u64 + 22 + comment_len);
            }
        }
        Ok(0)
    }

    fn generate_output_path_indexed(output_dir: &Path, session_id: &str, extension: &str, index: usize) -> PathBuf {
        let filename = format!("recovered_{}_{:06}.{}", session_id, index, extension);
        output_dir.join(filename)
    }

    fn calculate_hash_static(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn carve_single_file(
        &self,
        device: &mut File,
        sig_match: &SignatureMatch,
    ) -> Result<Option<RecoveredFile>> {
        device.seek(SeekFrom::Start(sig_match.offset))?;

        let extension = &sig_match.signature.extension;
        let output_path = self.generate_output_path(extension);

        let file_size = self.estimate_file_size(device, &sig_match.signature)?;
        
        if file_size == 0 || file_size > self.max_file_size {
            debug!("Skipping file at {} (invalid size: {})", sig_match.offset, file_size);
            return Ok(None);
        }

        let mut buffer = vec![0u8; file_size as usize];
        device.seek(SeekFrom::Start(sig_match.offset))?;
        device.read_exact(&mut buffer)?;

        let mut output_file = BufWriter::new(File::create(&output_path)?);
        output_file.write_all(&buffer)?;
        output_file.flush()?;

        let hash = self.calculate_hash(&buffer);
        
        let mut recovered_file = RecoveredFile::new(&self.session_id, &output_path.to_string_lossy());
        recovered_file.file_size = file_size;
        recovered_file.extension = extension.clone();
        recovered_file.file_type = sig_match.signature.category.clone();
        recovered_file.signature = hash;
        recovered_file.status = RecoveryStatus::Completed;
        recovered_file.integrity_check = IntegrityStatus::Verified;
        recovered_file.threat_scan = ThreatStatus::NotScanned;

        debug!("Recovered file: {} ({} bytes)", output_path.display(), file_size);
        Ok(Some(recovered_file))
    }

    fn estimate_file_size(&self, device: &mut File, signature: &FileSignature) -> Result<u64> {
        let current_pos = device.stream_position()?;
        
        let estimated_size = match signature.extension.as_str() {
            "jpg" | "jpeg" => self.find_jpeg_end(device)?,
            "png" => self.find_png_end(device)?,
            "pdf" => self.find_pdf_end(device)?,
            "zip" | "docx" | "xlsx" | "pptx" => self.find_zip_end(device)?,
            _ => self.find_generic_end(device)?,
        };

        device.seek(SeekFrom::Start(current_pos))?;
        Ok(estimated_size)
    }

    fn find_jpeg_end(&self, device: &mut File) -> Result<u64> {
        let start_pos = device.stream_position()?;
        let mut buffer = vec![0u8; 4096];
        let mut position = start_pos;

        loop {
            device.seek(SeekFrom::Start(position))?;
            let bytes_read = device.read(&mut buffer)?;
            
            if bytes_read == 0 {
                break;
            }

            for i in 0..bytes_read.saturating_sub(1) {
                if buffer[i] == 0xFF && buffer[i + 1] == 0xD9 {
                    return Ok(position + i as u64 + 2 - start_pos);
                }
            }

            position += bytes_read as u64 - 1;

            if position - start_pos > self.max_file_size {
                return Ok(0);
            }
        }

        Ok(0)
    }

    fn find_png_end(&self, device: &mut File) -> Result<u64> {
        let start_pos = device.stream_position()?;
        let mut buffer = [0u8; 8];
        
        device.seek(SeekFrom::Start(start_pos + 8))?;
        device.read_exact(&mut buffer)?;
        
        let length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as u64;
        let total_size = 8 + 4 + 4 + length + 4;
        
        Ok(total_size)
    }

    fn find_pdf_end(&self, device: &mut File) -> Result<u64> {
        let start_pos = device.stream_position()?;
        let mut buffer = vec![0u8; 65536];
        let mut position = start_pos;
        let mut last_eof = None;

        loop {
            device.seek(SeekFrom::Start(position))?;
            let bytes_read = device.read(&mut buffer)?;
            
            if bytes_read == 0 {
                break;
            }

            let buffer_str = String::from_utf8_lossy(&buffer[..bytes_read]);
            if let Some(idx) = buffer_str.rfind("%%EOF") {
                last_eof = Some(position + idx as u64 + 5);
            }

            position += bytes_read as u64;

            if position - start_pos > self.max_file_size {
                break;
            }
        }

        Ok(last_eof.unwrap_or(0) - start_pos)
    }

    fn find_zip_end(&self, device: &mut File) -> Result<u64> {
        let start_pos = device.stream_position()?;
        let mut buffer = vec![0u8; 65536];
        let mut position = start_pos;

        loop {
            device.seek(SeekFrom::Start(position))?;
            let bytes_read = device.read(&mut buffer)?;
            
            if bytes_read == 0 {
                break;
            }

            for i in 0..bytes_read.saturating_sub(3) {
                if buffer[i] == 0x50 && buffer[i + 1] == 0x4B && 
                   buffer[i + 2] == 0x05 && buffer[i + 3] == 0x06
                    && i + 22 <= bytes_read {
                        let comment_len = u16::from_le_bytes([buffer[i + 20], buffer[i + 21]]) as u64;
                        return Ok(position + i as u64 + 22 + comment_len - start_pos);
                    }
            }

            position += bytes_read as u64 - 3;

            if position - start_pos > self.max_file_size {
                break;
            }
        }

        Ok(0)
    }

    fn find_generic_end(&self, device: &mut File) -> Result<u64> {
        let metadata = device.metadata()?;
        let current_pos = device.stream_position()?;
        let remaining = metadata.len() - current_pos;
        Ok(std::cmp::min(remaining, 1024 * 1024))
    }

    fn generate_output_path(&self, extension: &str) -> PathBuf {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("recovered_{}_{}.{}", self.session_id, timestamp, extension);
        self.output_dir.join(filename)
    }

    fn calculate_hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_file_carver_creation() {
        let temp_dir = TempDir::new().unwrap();
        let carver = FileCarver::new(temp_dir.path(), "test-session");
        assert_eq!(carver.session_id, "test-session");
        assert_eq!(carver.max_file_size, 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_with_max_file_size() {
        let temp_dir = TempDir::new().unwrap();
        let carver = FileCarver::new(temp_dir.path(), "s1").with_max_file_size(1024);
        assert_eq!(carver.max_file_size, 1024);
    }

    #[test]
    fn test_output_path_generation() {
        let temp_dir = TempDir::new().unwrap();
        let carver = FileCarver::new(temp_dir.path(), "test-session");
        let path = carver.generate_output_path("jpg");
        assert!(path.to_string_lossy().contains("test-session"));
        assert_eq!(path.extension().unwrap(), "jpg");
        assert!(path.starts_with(temp_dir.path()));
    }

    #[test]
    fn test_carve_jpeg() {
        let input_dir = TempDir::new().unwrap();
        let output_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("test.dat");

        let mut jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg_data.extend_from_slice(&[0x00; 100]);
        jpeg_data.extend_from_slice(&[0xFF, 0xD9]);
        std::fs::write(&input_path, &jpeg_data).unwrap();

        let carver = FileCarver::new(output_dir.path(), "jpeg-session");
        let sig = FileSignature {
            extension: "jpg".to_string(),
            magic_bytes: vec![0xFF, 0xD8, 0xFF],
            offset: 0,
            description: "JPEG".to_string(),
            category: "Image".to_string(),
        };
        let sig_matches = vec![SignatureMatch { offset: 0, signature: sig }];

        let mut callback_called = false;
        let recovered = carver.carve_files(
            input_path.to_str().unwrap(),
            &sig_matches,
            |_, _| { callback_called = true; },
        ).unwrap();

        assert!(callback_called);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].extension, "jpg");
        assert_eq!(recovered[0].status, RecoveryStatus::Completed);
        assert_eq!(recovered[0].integrity_check, IntegrityStatus::Verified);
        assert!(std::path::Path::new(&recovered[0].recovered_path).exists());
    }

    #[test]
    fn test_carve_png() {
        let input_dir = TempDir::new().unwrap();
        let output_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("test.dat");

        let mut png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let ihdr_length: u32 = 13;
        png_data.extend_from_slice(&ihdr_length.to_be_bytes());
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&[0u8; 13]);
        png_data.extend_from_slice(&[0u8; 4]);
        std::fs::write(&input_path, &png_data).unwrap();

        let carver = FileCarver::new(output_dir.path(), "png-session");
        let sig = FileSignature {
            extension: "png".to_string(),
            magic_bytes: vec![0x89, 0x50, 0x4E, 0x47],
            offset: 0,
            description: "PNG".to_string(),
            category: "Image".to_string(),
        };
        let sig_matches = vec![SignatureMatch { offset: 0, signature: sig }];

        let recovered = carver.carve_files(
            input_path.to_str().unwrap(),
            &sig_matches,
            |_, _| {},
        ).unwrap();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].extension, "png");
    }

    #[test]
    fn test_carve_pdf() {
        let input_dir = TempDir::new().unwrap();
        let output_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("test.dat");

        let mut pdf_data = b"%PDF-1.4\nsome content\n%%EOF".to_vec();
        pdf_data.extend_from_slice(&[0u8; 10]);
        std::fs::write(&input_path, &pdf_data).unwrap();

        let carver = FileCarver::new(output_dir.path(), "pdf-session");
        let sig = FileSignature {
            extension: "pdf".to_string(),
            magic_bytes: vec![0x25, 0x50, 0x44, 0x46],
            offset: 0,
            description: "PDF".to_string(),
            category: "Document".to_string(),
        };
        let sig_matches = vec![SignatureMatch { offset: 0, signature: sig }];

        let recovered = carver.carve_files(
            input_path.to_str().unwrap(),
            &sig_matches,
            |_, _| {},
        ).unwrap();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].extension, "pdf");
        assert_eq!(recovered[0].status, RecoveryStatus::Completed);
    }

    #[test]
    fn test_generate_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let carver = FileCarver::new(temp_dir.path(), "test-session");
        let path = carver.generate_output_path("jpg");
        assert!(path.to_string_lossy().contains("test-session"));
        assert!(path.extension().unwrap() == "jpg");
    }

    #[test]
    fn test_carve_parallel_jpeg() {
        let input_dir = TempDir::new().unwrap();
        let output_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("test.dat");

        let mut jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg_data.extend_from_slice(&[0x00; 100]);
        jpeg_data.extend_from_slice(&[0xFF, 0xD9]);
        std::fs::write(&input_path, &jpeg_data).unwrap();

        let carver = FileCarver::new(output_dir.path(), "jpeg-parallel");
        let sig = FileSignature {
            extension: "jpg".to_string(),
            magic_bytes: vec![0xFF, 0xD8, 0xFF],
            offset: 0,
            description: "JPEG".to_string(),
            category: "Image".to_string(),
        };
        let sig_matches = vec![SignatureMatch { offset: 0, signature: sig }];

        let progress_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let progress_clone = progress_count.clone();
        let recovered = carver.carve_files_parallel(
            input_path.to_str().unwrap(),
            &sig_matches,
            move |_, _| { progress_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed); },
        ).unwrap();

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].extension, "jpg");
        assert_eq!(recovered[0].status, RecoveryStatus::Completed);
        assert_eq!(recovered[0].integrity_check, IntegrityStatus::Verified);
        assert!(std::path::Path::new(&recovered[0].recovered_path).exists());
        assert_eq!(progress_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn test_carve_parallel_multiple_files() {
        let input_dir = TempDir::new().unwrap();
        let output_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("multi.dat");

        let mut data = Vec::new();
        
        let mut jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg_data.extend_from_slice(&[0x00; 100]);
        jpeg_data.extend_from_slice(&[0xFF, 0xD9]);
        let jpeg_offset = data.len() as u64;
        data.extend_from_slice(&jpeg_data);

        let pdf_data = b"%PDF-1.4\ncontent\n%%EOF".to_vec();
        let pdf_offset = data.len() as u64;
        data.extend_from_slice(&pdf_data);

        let mut png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        png_data.extend_from_slice(&13u32.to_be_bytes());
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&[0u8; 13]);
        png_data.extend_from_slice(&[0u8; 4]);
        let png_offset = data.len() as u64;
        data.extend_from_slice(&png_data);

        std::fs::write(&input_path, &data).unwrap();

        let carver = FileCarver::new(output_dir.path(), "multi-parallel");
        let sig_matches = vec![
            SignatureMatch {
                offset: jpeg_offset,
                signature: FileSignature {
                    extension: "jpg".to_string(),
                    magic_bytes: vec![0xFF, 0xD8, 0xFF],
                    offset: 0,
                    description: "JPEG".to_string(),
                    category: "Image".to_string(),
                },
            },
            SignatureMatch {
                offset: pdf_offset,
                signature: FileSignature {
                    extension: "pdf".to_string(),
                    magic_bytes: vec![0x25, 0x50, 0x44, 0x46],
                    offset: 0,
                    description: "PDF".to_string(),
                    category: "Document".to_string(),
                },
            },
            SignatureMatch {
                offset: png_offset,
                signature: FileSignature {
                    extension: "png".to_string(),
                    magic_bytes: vec![0x89, 0x50, 0x4E, 0x47],
                    offset: 0,
                    description: "PNG".to_string(),
                    category: "Image".to_string(),
                },
            },
        ];

        let recovered = carver.carve_files_parallel(
            input_path.to_str().unwrap(),
            &sig_matches,
            |_, _| {},
        ).unwrap();

        assert_eq!(recovered.len(), 3);
        let mut extensions: Vec<_> = recovered.iter().map(|f| f.extension.as_str()).collect();
        extensions.sort();
        assert_eq!(extensions, vec!["jpg", "pdf", "png"]);
    }

    #[test]
    fn test_benchmark_serial_vs_parallel() {
        use std::time::Instant;

        let input_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("benchmark.dat");
        
        let mut data = Vec::new();
        let file_size = 64 * 1024;
        let num_files = 20;

        let mut offsets = Vec::new();
        for _ in 0..num_files {
            offsets.push(data.len() as u64);
            let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
            jpeg.extend_from_slice(&vec![0x00; file_size]);
            jpeg.extend_from_slice(&[0xFF, 0xD9]);
            data.extend_from_slice(&jpeg);
        }

        std::fs::write(&input_path, &data).unwrap();

        let sig_matches: Vec<SignatureMatch> = offsets
            .into_iter()
            .map(|offset| SignatureMatch {
                offset,
                signature: FileSignature {
                    extension: "jpg".to_string(),
                    magic_bytes: vec![0xFF, 0xD8, 0xFF],
                    offset: 0,
                    description: "JPEG".to_string(),
                    category: "Image".to_string(),
                },
            })
            .collect();

        let serial_output = TempDir::new().unwrap();
        let carver_serial = FileCarver::new(serial_output.path(), "bench-serial");
        
        let start_serial = Instant::now();
        let recovered_serial = carver_serial.carve_files(
            input_path.to_str().unwrap(),
            &sig_matches,
            |_, _| {},
        ).unwrap();
        let serial_duration = start_serial.elapsed();

        let parallel_output = TempDir::new().unwrap();
        let carver_parallel = FileCarver::new(parallel_output.path(), "bench-parallel");

        let start_parallel = Instant::now();
        let recovered_parallel = carver_parallel.carve_files_parallel(
            input_path.to_str().unwrap(),
            &sig_matches,
            |_, _| {},
        ).unwrap();
        let parallel_duration = start_parallel.elapsed();

        assert_eq!(recovered_serial.len(), num_files);
        assert_eq!(recovered_parallel.len(), num_files);

        println!("Serial:   {:?}", serial_duration);
        println!("Parallel: {:?}", parallel_duration);
        println!("Files carved: {}", num_files);
        if parallel_duration.as_nanos() > 0 {
            let speedup = serial_duration.as_nanos() as f64 / parallel_duration.as_nanos() as f64;
            println!("Speedup:  {:.2}x", speedup);
        }
    }
}
