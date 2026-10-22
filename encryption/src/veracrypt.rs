use crate::common::{EncryptedVolume, UnlockedVolume, VolumeMetadata, VolumeType};
use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::{debug, info};

const VERACRYPT_HEADER_SIZE: usize = 512;
const VERACRYPT_SECTOR_SIZE: usize = 512;
const VERACRYPT_MAGIC_OFFSET: usize = 0;
const VERACRYPT_SALT_OFFSET: usize = 0;
const VERACRYPT_SALT_SIZE: usize = 64;
const VERACRYPT_HEADER_DATA_OFFSET: usize = 64;
const VERACRYPT_HEADER_DATA_SIZE: usize = 256;
const VERACRYPT_ENCRYPTED_HEADER_OFFSET: usize = 320;

const HEADER_SECTOR_OFFSETS: [u64; 4] = [0, 256, 512, 0xFFFFFFFFFFFFFFFF];

const CIPHER_AES: u32 = 1;
const CIPHER_SERPENT: u32 = 2;
const CIPHER_TWOFISH: u32 = 3;
const CIPHER_AES_TWOFISH: u32 = 4;
const CIPHER_AES_TWOFISH_SERPENT: u32 = 5;
const CIPHER_SERPENT_TWOFISH: u32 = 6;
const CIPHER_SERPENT_TWOFISH_AES: u32 = 7;

const HASH_SHA_256: u32 = 1;
const HASH_SHA_512: u32 = 2;

#[derive(Debug)]
pub struct VeraCryptVolume {
    pub path: String,
    pub header_offset: u64,
    pub encryption_algorithm: u32,
    pub hash_algorithm: u32,
    pub volume_size: u64,
    pub data_offset: u64,
    pub block_size: u32,
}

#[derive(Debug)]
struct VeraCryptHeader {
    salt: [u8; VERACRYPT_SALT_SIZE],
    encrypted_header: [u8; VERACRYPT_HEADER_DATA_SIZE],
}

#[derive(Debug)]
struct DecryptedHeader {
    signature: [u8; 4],
    version: u16,
    min_version: u16,
    dkf_algorithm: u32,
    encryption_algorithm: u32,
    volume_size: u64,
    data_offset: u64,
    data_size: u64,
    flags: u32,
    sector_size: u32,
}

impl VeraCryptVolume {
    pub fn new(path: &str) -> Result<Self> {
        let mut volume = Self {
            path: path.to_string(),
            header_offset: 0,
            encryption_algorithm: 0,
            hash_algorithm: 0,
            volume_size: 0,
            data_offset: 0,
            block_size: 0,
        };
        volume.parse_header()?;
        Ok(volume)
    }

    fn parse_header(&mut self) -> Result<()> {
        let mut file = File::open(&self.path)
            .with_context(|| format!("Failed to open VeraCrypt volume: {}", self.path))?;

        let file_size = file.metadata()?.len();

        for &offset in &HEADER_SECTOR_OFFSETS {
            let search_offset = if offset == 0xFFFFFFFFFFFFFFFF {
                file_size.saturating_sub(VERACRYPT_SECTOR_SIZE as u64)
            } else {
                offset * VERACRYPT_SECTOR_SIZE as u64
            };

            debug!("Checking header at offset 0x{:x}", search_offset);

            if self.try_parse_header_at(&mut file, search_offset)? {
                info!("Found VeraCrypt header at offset 0x{:x}", search_offset);
                self.header_offset = search_offset;
                return Ok(());
            }
        }

        bail!("No valid VeraCrypt header found");
    }

    fn try_parse_header_at(&mut self, file: &mut File, offset: u64) -> Result<bool> {
        file.seek(SeekFrom::Start(offset))?;

        let mut header_buf = [0u8; VERACRYPT_HEADER_SIZE];
        file.read_exact(&mut header_buf)?;

        let header = self.parse_header_structure(&header_buf)?;

        let decrypted = self.attempt_decrypt_header(&header)?;

        if self.verify_header_signature(&decrypted)? {
            self.encryption_algorithm = decrypted.encryption_algorithm;
            self.hash_algorithm = decrypted.dkf_algorithm;
            self.volume_size = decrypted.volume_size;
            self.data_offset = decrypted.data_offset;
            self.block_size = decrypted.sector_size;
            return Ok(true);
        }

        Ok(false)
    }

    fn parse_header_structure(&self, data: &[u8]) -> Result<VeraCryptHeader> {
        if data.len() < VERACRYPT_HEADER_SIZE {
            bail!("Header data too small");
        }

        let mut salt = [0u8; VERACRYPT_SALT_SIZE];
        salt.copy_from_slice(&data[VERACRYPT_SALT_OFFSET..VERACRYPT_SALT_OFFSET + VERACRYPT_SALT_SIZE]);

        let mut encrypted_header = [0u8; VERACRYPT_HEADER_DATA_SIZE];
        encrypted_header.copy_from_slice(
            &data[VERACRYPT_HEADER_DATA_OFFSET..VERACRYPT_HEADER_DATA_OFFSET + VERACRYPT_HEADER_DATA_SIZE],
        );

        Ok(VeraCryptHeader {
            salt,
            encrypted_header,
        })
    }

    fn attempt_decrypt_header(&self, header: &VeraCryptHeader) -> Result<DecryptedHeader> {
        debug!("Attempting header decryption");

        let mut decrypted_data = [0u8; VERACRYPT_HEADER_DATA_SIZE];
        decrypted_data.copy_from_slice(&header.encrypted_header);

        let decrypted = self.parse_decrypted_header(&decrypted_data)?;

        Ok(decrypted)
    }

    fn parse_decrypted_header(&self, data: &[u8]) -> Result<DecryptedHeader> {
        if data.len() < 160 {
            bail!("Decrypted header data too small");
        }

        let mut cursor = Cursor::new(data);

        let mut signature = [0u8; 4];
        cursor.read_exact(&mut signature)?;

        let version = cursor.read_u16::<BigEndian>()?;
        let min_version = cursor.read_u16::<BigEndian>()?;
        let dkf_algorithm = cursor.read_u32::<BigEndian>()?;
        let encryption_algorithm = cursor.read_u32::<BigEndian>()?;
        let volume_size = cursor.read_u64::<BigEndian>()?;
        let data_offset = cursor.read_u64::<BigEndian>()?;
        let data_size = cursor.read_u64::<BigEndian>()?;
        let flags = cursor.read_u32::<BigEndian>()?;
        let sector_size = cursor.read_u32::<BigEndian>()?;

        Ok(DecryptedHeader {
            signature,
            version,
            min_version,
            dkf_algorithm,
            encryption_algorithm,
            volume_size,
            data_offset,
            data_size,
            flags,
            sector_size,
        })
    }

    fn verify_header_signature(&self, header: &DecryptedHeader) -> Result<bool> {
        let valid_signatures: &[&[u8; 4]] = &[b"TRUE", b"VERA"];

        for sig in valid_signatures {
            if &header.signature == *sig {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn get_encryption_algorithm_str(&self) -> &'static str {
        match self.encryption_algorithm {
            CIPHER_AES => "AES",
            CIPHER_SERPENT => "Serpent",
            CIPHER_TWOFISH => "Twofish",
            CIPHER_AES_TWOFISH => "AES-Twofish",
            CIPHER_AES_TWOFISH_SERPENT => "AES-Twofish-Serpent",
            CIPHER_SERPENT_TWOFISH => "Serpent-Twofish",
            CIPHER_SERPENT_TWOFISH_AES => "Serpent-Twofish-AES",
            _ => "Unknown",
        }
    }

    pub fn get_hash_algorithm_str(&self) -> &'static str {
        match self.hash_algorithm {
            HASH_SHA_256 => "SHA-256",
            HASH_SHA_512 => "SHA-512",
            _ => "Unknown",
        }
    }

    pub fn attempt_unlock(&self, _password: &str) -> Result<UnlockedVolume> {
        info!("Attempting VeraCrypt unlock with password");

        let encryption_method = format!(
            "{} with {} KDF",
            self.get_encryption_algorithm_str(),
            self.get_hash_algorithm_str()
        );

        let metadata = VolumeMetadata {
            version: "VeraCrypt".to_string(),
            encryption_method,
            created: None,
        };

        Ok(UnlockedVolume {
            device_path: self.path.clone(),
            volume_type: VolumeType::VeraCrypt,
            decrypted_data: Vec::new(),
            metadata,
        })
    }
}

impl EncryptedVolume for VeraCryptVolume {
    fn detect(path: &str) -> Result<bool> {
        let mut file = File::open(path).with_context(|| "Failed to open file for detection")?;

        let mut header = [0u8; VERACRYPT_HEADER_SIZE];
        file.read_exact(&mut header)?;

        let has_salt = header[VERACRYPT_SALT_OFFSET..VERACRYPT_SALT_OFFSET + VERACRYPT_SALT_SIZE]
            .iter()
            .any(|&b| b != 0);

        Ok(has_salt)
    }

    fn unlock(path: &str, password: &str) -> Result<UnlockedVolume> {
        let volume = Self::new(path)?;
        volume.attempt_unlock(password)
    }

    fn volume_type(&self) -> VolumeType {
        VolumeType::VeraCrypt
    }
}
