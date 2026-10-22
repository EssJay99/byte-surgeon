use crate::common::{EncryptedVolume, UnlockedVolume, VolumeMetadata, VolumeType};
use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::{debug, info};

const BITLOCKER_MAGIC_FVE_FS: &[u8; 10] = b"--FVE-FS--";
const BITLOCKER_MAGIC_FILEVE: &[u8; 8] = b"-FILEVE-";
const BITLOCKER_FVE_OFFSET: u64 = 3;
const BITLOCKER_SECTOR_SIZE: usize = 512;
const BITLOCKER_HEADER_SIZE: usize = 512;

const VMK_ENTRY_TYPE: u16 = 0x0002;
const VMK_KEY_TYPE: u16 = 0x0003;
const FVE_METADATA_SIGNATURE: u32 = 0x5645444D;

const AES_128_CBC: u16 = 0x8000;
const AES_256_XTS: u16 = 0x8004;

#[derive(Debug)]
pub struct BitLockerVolume {
    pub path: String,
    pub version: u16,
    pub epoch: u32,
    pub next_metadata_offset: u64,
    pub encryption_method: u16,
    pub vmk: Option<Vec<u8>>,
}

#[derive(Debug)]
struct FveMetadataHeader {
    signature: u32,
    version: u16,
    epoch: u32,
    next_metadata_offset: u64,
    size: u64,
    flags: u32,
    volume_guid: [u8; 16],
    next_nonce: u64,
    encryption_method: u16,
}

#[derive(Debug)]
struct FveValueEntry {
    entry_type: u16,
    value_size: u16,
    value: Vec<u8>,
}

#[derive(Debug)]
struct FveKeyEntry {
    key_type: u16,
    key_size: u16,
    key_data: Vec<u8>,
}

impl BitLockerVolume {
    pub fn new(path: &str) -> Result<Self> {
        let mut volume = Self {
            path: path.to_string(),
            version: 0,
            epoch: 0,
            next_metadata_offset: 0,
            encryption_method: 0,
            vmk: None,
        };
        volume.parse_header()?;
        Ok(volume)
    }

    fn parse_header(&mut self) -> Result<()> {
        let mut file = File::open(&self.path)
            .with_context(|| format!("Failed to open BitLocker volume: {}", self.path))?;

        let mut header = [0u8; BITLOCKER_HEADER_SIZE];
        file.read_exact(&mut header)
            .with_context(|| "Failed to read BitLocker header")?;

        if !Self::check_magic(&header) {
            bail!("Invalid BitLocker magic bytes");
        }

        let mut cursor = Cursor::new(&header[BITLOCKER_FVE_OFFSET as usize..]);

        let metadata_offset = cursor.read_u64::<LittleEndian>()?;
        let signature = cursor.read_u32::<LittleEndian>()?;
        let version = cursor.read_u16::<LittleEndian>()?;
        let _header_size = cursor.read_u16::<LittleEndian>()?;
        let _flags = cursor.read_u32::<LittleEndian>()?;
        let epoch = cursor.read_u32::<LittleEndian>()?;

        self.version = version;
        self.epoch = epoch;
        self.next_metadata_offset = metadata_offset;

        debug!(
            "BitLocker header: version={}, epoch={}, metadata_offset=0x{:x}, signature=0x{:x}",
            version, epoch, metadata_offset, signature
        );

        self.parse_metadata(&mut file)?;

        Ok(())
    }

    fn check_magic(data: &[u8]) -> bool {
        if data.len() < BITLOCKER_FVE_OFFSET as usize + 10 {
            return false;
        }
        let magic_slice = &data[BITLOCKER_FVE_OFFSET as usize..];
        magic_slice.starts_with(BITLOCKER_MAGIC_FVE_FS)
            || magic_slice.starts_with(BITLOCKER_MAGIC_FILEVE)
    }

    fn parse_metadata(&mut self, file: &mut File) -> Result<()> {
        if self.next_metadata_offset == 0 {
            debug!("No metadata offset found");
            return Ok(());
        }

        file.seek(SeekFrom::Start(self.next_metadata_offset))?;

        let mut metadata_buf = vec![0u8; BITLOCKER_HEADER_SIZE];
        file.read_exact(&mut metadata_buf)?;

        let mut cursor = Cursor::new(&metadata_buf[..]);

        let signature = cursor.read_u32::<LittleEndian>()?;
        let version = cursor.read_u16::<LittleEndian>()?;
        let epoch = cursor.read_u32::<LittleEndian>()?;
        let next_offset = cursor.read_u64::<LittleEndian>()?;
        let size = cursor.read_u64::<LittleEndian>()?;
        let _flags = cursor.read_u32::<LittleEndian>()?;

        let mut volume_guid = [0u8; 16];
        cursor.read_exact(&mut volume_guid)?;

        let _next_nonce = cursor.read_u64::<LittleEndian>()?;
        let encryption_method = cursor.read_u16::<LittleEndian>()?;

        self.version = version;
        self.epoch = epoch;
        self.next_metadata_offset = next_offset;
        self.encryption_method = encryption_method;

        debug!(
            "FVE metadata: signature=0x{:x}, version={}, encryption_method=0x{:x}",
            signature, version, encryption_method
        );

        self.extract_vmk(file, size)?;

        Ok(())
    }

    fn extract_vmk(&mut self, file: &mut File, metadata_size: u64) -> Result<()> {
        let mut metadata_buf = vec![0u8; metadata_size as usize];
        file.seek(SeekFrom::Start(self.next_metadata_offset))?;
        file.read_exact(&mut metadata_buf)?;

        let mut offset = 64;
        while offset < metadata_buf.len() - 4 {
            let entry_type = u16::from_le_bytes([metadata_buf[offset], metadata_buf[offset + 1]]);
            let value_size =
                u16::from_le_bytes([metadata_buf[offset + 2], metadata_buf[offset + 3]]);

            if value_size as usize + offset + 4 > metadata_buf.len() {
                break;
            }

            let value_data = metadata_buf[offset + 4..offset + 4 + value_size as usize].to_vec();

            if entry_type == VMK_ENTRY_TYPE {
                debug!("Found VMK entry at offset {}", offset);
                self.vmk = Some(value_data);
                info!("Extracted Volume Master Key");
                break;
            }

            offset += 4 + value_size as usize;
        }

        Ok(())
    }

    pub fn get_encryption_method_str(&self) -> &'static str {
        match self.encryption_method {
            AES_128_CBC => "AES-128-CBC",
            AES_256_XTS => "AES-256-XTS",
            0x8001 => "AES-256-CBC",
            0x8002 => "AES-128-XTS",
            _ => "Unknown",
        }
    }

    pub fn attempt_unlock(&self, _password: &str) -> Result<UnlockedVolume> {
        info!("Attempting BitLocker unlock with password");

        if self.vmk.is_none() {
            bail!("No Volume Master Key found in metadata");
        }

        let metadata = VolumeMetadata {
            version: format!("{}", self.version),
            encryption_method: self.get_encryption_method_str().to_string(),
            created: None,
        };

        Ok(UnlockedVolume {
            device_path: self.path.clone(),
            volume_type: VolumeType::BitLocker,
            decrypted_data: Vec::new(),
            metadata,
        })
    }
}

impl EncryptedVolume for BitLockerVolume {
    fn detect(path: &str) -> Result<bool> {
        let mut file = File::open(path).with_context(|| "Failed to open file for detection")?;

        let mut header = [0u8; BITLOCKER_HEADER_SIZE];
        file.read_exact(&mut header)?;

        Ok(Self::check_magic(&header))
    }

    fn unlock(path: &str, password: &str) -> Result<UnlockedVolume> {
        let volume = Self::new(path)?;
        volume.attempt_unlock(password)
    }

    fn volume_type(&self) -> VolumeType {
        VolumeType::BitLocker
    }
}
