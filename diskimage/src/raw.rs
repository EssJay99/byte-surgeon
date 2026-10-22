use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};
use tracing::{info, debug};

use datadoctor_core::{Result, Error};
use crate::{DiskImage, ImageMetadata};

const DEFAULT_SECTOR_SIZE: u32 = 512;

pub struct RawImage {
    file: File,
    path: PathBuf,
    size_bytes: u64,
    sector_size: u32,
    sha256: Option<String>,
}

impl RawImage {
    pub fn verify_integrity(&mut self, expected_hash: &str) -> Result<bool> {
        info!("Verifying SHA-256 integrity for {:?}", self.path);
        self.file.seek(SeekFrom::Start(0))
            .map_err(|e| Error::Io(e))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];

        loop {
            let bytes_read = self.file.read(&mut buffer)
                .map_err(|e| Error::Io(e))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hex::encode(hasher.finalize());
        self.sha256 = Some(hash.clone());
        self.file.seek(SeekFrom::Start(0))
            .map_err(|e| Error::Io(e))?;

        debug!("Computed hash: {}, expected: {}", hash, expected_hash);
        Ok(hash == expected_hash.to_lowercase())
    }

    pub fn compute_sha256(&mut self) -> Result<String> {
        self.file.seek(SeekFrom::Start(0))
            .map_err(|e| Error::Io(e))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];

        loop {
            let bytes_read = self.file.read(&mut buffer)
                .map_err(|e| Error::Io(e))?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let hash = hex::encode(hasher.finalize());
        self.sha256 = Some(hash.clone());
        self.file.seek(SeekFrom::Start(0))
            .map_err(|e| Error::Io(e))?;

        Ok(hash)
    }

    pub fn create_from_device(device_path: &Path, output_path: &Path) -> Result<Self> {
        info!("Creating raw image from {:?} to {:?}", device_path, output_path);
        let mut src = File::open(device_path)
            .map_err(|e| Error::Io(e))?;
        let mut dst = File::create(output_path)
            .map_err(|e| Error::Io(e))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut total_written: u64 = 0;

        loop {
            let bytes_read = src.read(&mut buffer)
                .map_err(|e| Error::Io(e))?;
            if bytes_read == 0 {
                break;
            }
            dst.write_all(&buffer[..bytes_read])
                .map_err(|e| Error::Io(e))?;
            hasher.update(&buffer[..bytes_read]);
            total_written += bytes_read as u64;
        }

        let hash = hex::encode(hasher.finalize());
        info!("Image created: {} bytes, SHA-256: {}", total_written, hash);

        let file = File::open(output_path)
            .map_err(|e| Error::Io(e))?;
        let size_bytes = file.metadata()
            .map_err(|e| Error::Io(e))?
            .len();

        Ok(RawImage {
            file,
            path: output_path.to_path_buf(),
            size_bytes,
            sector_size: DEFAULT_SECTOR_SIZE,
            sha256: Some(hash),
        })
    }
}

impl DiskImage for RawImage {
    fn open(path: &Path) -> Result<Self> {
        info!("Opening raw disk image: {:?}", path);
        let file = File::open(path)
            .map_err(|e| Error::Io(e))?;
        let size_bytes = file.metadata()
            .map_err(|e| Error::Io(e))?
            .len();

        Ok(RawImage {
            file,
            path: path.to_path_buf(),
            size_bytes,
            sector_size: DEFAULT_SECTOR_SIZE,
            sha256: None,
        })
    }

    fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> Result<usize> {
        let offset = sector * self.sector_size as u64;
        if offset >= self.size_bytes {
            return Ok(0);
        }

        self.file.seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io(e))?;

        let to_read = std::cmp::min(
            buffer.len() as u64,
            self.size_bytes - offset,
        ) as usize;

        let bytes_read = self.file.read(&mut buffer[..to_read])
            .map_err(|e| Error::Io(e))?;

        Ok(bytes_read)
    }

    fn total_sectors(&self) -> u64 {
        self.size_bytes / self.sector_size as u64
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn metadata(&self) -> ImageMetadata {
        ImageMetadata {
            format: "raw".to_string(),
            size_bytes: self.size_bytes,
            sector_size: self.sector_size,
            total_sectors: self.total_sectors(),
            sha256: self.sha256.clone(),
            created: None,
            modified: None,
            examiner: None,
            case_number: None,
            evidence_number: None,
            description: None,
        }
    }
}

use std::io::Write;
