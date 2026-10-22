use crate::common::{EncryptedVolume, UnlockedVolume, VolumeMetadata, VolumeType};
use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::{debug, info};

const CORESTORAGE_MAGIC: &[u8; 4] = b"CSNI";
const CORESTORAGE_MAGIC_V2: &[u8; 4] = b"CSLV";
const FILEVAULT_HEADER_SIZE: usize = 4096;
const FILEVAULT_SECTOR_SIZE: usize = 512;

const LVF_SIGNATURE: u32 = 0x4C564600;
const ENCRYPTED_FLAG: u32 = 0x00000001;

const AES_128_XTS: u32 = 0x00000001;
const AES_256_XTS: u32 = 0x00000002;

#[derive(Debug)]
pub struct FileVaultVolume {
    pub path: String,
    pub version: u32,
    pub lvf_offset: u64,
    pub encryption_method: u32,
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug)]
struct CoreStorageHeader {
    signature: [u8; 4],
    version: u32,
    header_size: u32,
    checksum: u64,
}

#[derive(Debug)]
struct LvfHeader {
    signature: u32,
    version: u32,
    flags: u32,
    size: u64,
    encryption_type: u32,
    key_size: u32,
    block_size: u32,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_type: u32,
    pub key_size: u32,
    pub wrapped_key: Vec<u8>,
}

impl FileVaultVolume {
    pub fn new(path: &str) -> Result<Self> {
        let mut volume = Self {
            path: path.to_string(),
            version: 0,
            lvf_offset: 0,
            encryption_method: 0,
            key_info: None,
        };
        volume.parse_header()?;
        Ok(volume)
    }

    fn parse_header(&mut self) -> Result<()> {
        let mut file = File::open(&self.path)
            .with_context(|| format!("Failed to open FileVault volume: {}", self.path))?;

        let mut header = [0u8; FILEVAULT_HEADER_SIZE];
        file.read_exact(&mut header)
            .with_context(|| "Failed to read FileVault header")?;

        if !Self::check_corestorage_magic(&header) {
            bail!("Invalid CoreStorage magic bytes");
        }

        let mut cursor = Cursor::new(&header[..]);

        let _signature = cursor.read_u32::<BigEndian>()?;
        let version = cursor.read_u32::<BigEndian>()?;
        let header_size = cursor.read_u32::<BigEndian>()?;

        debug!(
            "CoreStorage header: version={}, header_size={}",
            version, header_size
        );

        self.version = version;
        self.find_lvf_header(&mut file)?;

        Ok(())
    }

    fn check_corestorage_magic(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        data.starts_with(CORESTORAGE_MAGIC) || data.starts_with(CORESTORAGE_MAGIC_V2)
    }

    fn find_lvf_header(&mut self, file: &mut File) -> Result<()> {
        let search_offsets = [0x1000, 0x2000, 0x4000, 0x8000];

        for offset in search_offsets {
            file.seek(SeekFrom::Start(offset))?;
            let mut header_buf = [0u8; 256];
            if file.read_exact(&mut header_buf).is_err() {
                continue;
            }

            let mut cursor = Cursor::new(&header_buf[..]);
            let _signature = cursor.read_u32::<BigEndian>()?;

            if _signature == LVF_SIGNATURE {
                debug!("Found LVF header at offset 0x{:x}", offset);
                self.lvf_offset = offset;
                self.parse_lvf_header(&header_buf)?;
                return Ok(());
            }
        }

        debug!("LVF header not found in standard locations");
        Ok(())
    }

    fn parse_lvf_header(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(data);

        let _signature = cursor.read_u32::<BigEndian>()?;
        let version = cursor.read_u32::<BigEndian>()?;
        let flags = cursor.read_u32::<BigEndian>()?;
        let _size = cursor.read_u64::<BigEndian>()?;
        let encryption_type = cursor.read_u32::<BigEndian>()?;
        let key_size = cursor.read_u32::<BigEndian>()?;
        let _block_size = cursor.read_u32::<BigEndian>()?;

        self.version = version;
        self.encryption_method = encryption_type;

        debug!(
            "LVF header: version={}, flags=0x{:x}, encryption_type={}, key_size={}",
            version, flags, encryption_type, key_size
        );

        self.extract_key_info(&mut cursor, key_size)?;

        Ok(())
    }

    fn extract_key_info(&mut self, cursor: &mut Cursor<&[u8]>, key_size: u32) -> Result<()> {
        let key_type = cursor.read_u32::<BigEndian>()?;
        let wrapped_key_size = cursor.read_u32::<BigEndian>()?;

        let mut wrapped_key = vec![0u8; wrapped_key_size as usize];
        cursor.read_exact(&mut wrapped_key)?;

        self.key_info = Some(KeyInfo {
            key_type,
            key_size,
            wrapped_key,
        });

        debug!(
            "Extracted key info: type={}, size={}, wrapped_key_size={}",
            key_type, key_size, wrapped_key_size
        );

        Ok(())
    }

    pub fn get_encryption_method_str(&self) -> &'static str {
        match self.encryption_method {
            AES_128_XTS => "AES-128-XTS",
            AES_256_XTS => "AES-256-XTS",
            _ => "Unknown",
        }
    }

    pub fn attempt_unlock(&self, _password: &str) -> Result<UnlockedVolume> {
        info!("Attempting FileVault unlock with password");

        if self.key_info.is_none() {
            bail!("No key info found in LVF header");
        }

        let metadata = VolumeMetadata {
            version: format!("{}", self.version),
            encryption_method: self.get_encryption_method_str().to_string(),
            created: None,
        };

        Ok(UnlockedVolume {
            device_path: self.path.clone(),
            volume_type: VolumeType::FileVault,
            decrypted_data: Vec::new(),
            metadata,
        })
    }
}

impl EncryptedVolume for FileVaultVolume {
    fn detect(path: &str) -> Result<bool> {
        let mut file = File::open(path).with_context(|| "Failed to open file for detection")?;

        let mut header = [0u8; FILEVAULT_HEADER_SIZE];
        file.read_exact(&mut header)?;

        Ok(Self::check_corestorage_magic(&header))
    }

    fn unlock(path: &str, password: &str) -> Result<UnlockedVolume> {
        let volume = Self::new(path)?;
        volume.attempt_unlock(password)
    }

    fn volume_type(&self) -> VolumeType {
        VolumeType::FileVault
    }
}
