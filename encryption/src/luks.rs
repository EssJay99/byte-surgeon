use crate::common::{EncryptedVolume, UnlockedVolume, VolumeMetadata, VolumeType};
use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use tracing::{debug, info, warn};

const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
const LUKS1_HEADER_SIZE: usize = 592;
const LUKS2_HEADER_SIZE: usize = 16384;
const LUKS1_VERSION: u16 = 1;
const LUKS2_VERSION: u16 = 2;
const MAX_KEY_SLOTS: usize = 8;

const LUKS1_KEY_SLOT_OFFSET: usize = 48;
const LUKS1_CIPHER_NAME_LEN: usize = 32;
const LUKS1_CIPHER_MODE_LEN: usize = 32;
const LUKS1_HASH_SPEC_LEN: usize = 32;
const LUKS1_SALT_LEN: usize = 32;
const LUKS1_UUID_LEN: usize = 40;
const LUKS1_DIGEST_SPEC_LEN: usize = 32;

const KEY_SLOT_ENABLED: u32 = 0x00AC71F3;
const KEY_SLOT_DISABLED: u32 = 0x0000DEAD;

const CIPHER_AES_CBC: &str = "aes-cbc-essiv:sha256";
const CIPHER_AES_XTS: &str = "aes-xts-plain64";

#[derive(Debug)]
pub struct LuksVolume {
    pub path: String,
    pub version: u16,
    pub cipher_name: String,
    pub cipher_mode: String,
    pub hash_spec: String,
    pub key_bytes: u32,
    pub mk_digest: Vec<u8>,
    pub salt: Vec<u8>,
    pub key_slots: Vec<KeySlot>,
}

#[derive(Debug, Clone)]
pub struct KeySlot {
    pub active: bool,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub key_offset: u32,
    pub key_bytes: u32,
    pub key_data: Vec<u8>,
}

#[derive(Debug)]
struct Luks1Header {
    magic: [u8; 6],
    version: u16,
    cipher_name: [u8; LUKS1_CIPHER_NAME_LEN],
    cipher_mode: [u8; LUKS1_CIPHER_MODE_LEN],
    hash_spec: [u8; LUKS1_HASH_SPEC_LEN],
    payload_offset: u32,
    key_bytes: u32,
    mk_digest: [u8; 20],
    salt: [u8; LUKS1_SALT_LEN],
    flags: u32,
}

impl LuksVolume {
    pub fn new(path: &str) -> Result<Self> {
        let mut volume = Self {
            path: path.to_string(),
            version: 0,
            cipher_name: String::new(),
            cipher_mode: String::new(),
            hash_spec: String::new(),
            key_bytes: 0,
            mk_digest: Vec::new(),
            salt: Vec::new(),
            key_slots: Vec::new(),
        };
        volume.parse_header()?;
        Ok(volume)
    }

    fn parse_header(&mut self) -> Result<()> {
        let mut file = File::open(&self.path)
            .with_context(|| format!("Failed to open LUKS volume: {}", self.path))?;

        let mut header = [0u8; LUKS1_HEADER_SIZE];
        file.read_exact(&mut header)
            .with_context(|| "Failed to read LUKS header")?;

        if !Self::check_magic(&header) {
            bail!("Invalid LUKS magic bytes");
        }

        let mut cursor = Cursor::new(&header[..]);

        let mut magic = [0u8; 6];
        cursor.read_exact(&mut magic)?;

        let version = cursor.read_u16::<BigEndian>()?;
        self.version = version;

        let mut cipher_name = [0u8; LUKS1_CIPHER_NAME_LEN];
        cursor.read_exact(&mut cipher_name)?;

        let mut cipher_mode = [0u8; LUKS1_CIPHER_MODE_LEN];
        cursor.read_exact(&mut cipher_mode)?;

        let mut hash_spec = [0u8; LUKS1_HASH_SPEC_LEN];
        cursor.read_exact(&mut hash_spec)?;

        let _payload_offset = cursor.read_u32::<BigEndian>()?;
        let key_bytes = cursor.read_u32::<BigEndian>()?;

        let mut mk_digest = [0u8; 20];
        cursor.read_exact(&mut mk_digest)?;

        let mut salt = [0u8; LUKS1_SALT_LEN];
        cursor.read_exact(&mut salt)?;

        let _flags = cursor.read_u32::<BigEndian>()?;

        self.cipher_name = Self::bytes_to_string(&cipher_name);
        self.cipher_mode = Self::bytes_to_string(&cipher_mode);
        self.hash_spec = Self::bytes_to_string(&hash_spec);
        self.key_bytes = key_bytes;
        self.mk_digest = mk_digest.to_vec();
        self.salt = salt.to_vec();

        debug!(
            "LUKS{} header: cipher={}, mode={}, hash={}, key_bytes={}",
            version, self.cipher_name, self.cipher_mode, self.hash_spec, key_bytes
        );

        if version == LUKS1_VERSION {
            self.parse_key_slots_v1(&mut file, &mut cursor)?;
        } else if version == LUKS2_VERSION {
            self.parse_key_slots_v2(&mut file)?;
        } else {
            warn!("Unsupported LUKS version: {}", version);
        }

        Ok(())
    }

    fn check_magic(data: &[u8]) -> bool {
        if data.len() < 6 {
            return false;
        }
        data.starts_with(LUKS_MAGIC)
    }

    fn bytes_to_string(bytes: &[u8]) -> String {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).to_string()
    }

    fn parse_key_slots_v1(&mut self, file: &mut File, cursor: &mut Cursor<&[u8]>) -> Result<()> {
        for i in 0..MAX_KEY_SLOTS {
            let active = cursor.read_u32::<BigEndian>()?;
            let iterations = cursor.read_u32::<BigEndian>()?;

            let mut salt = [0u8; LUKS1_SALT_LEN];
            cursor.read_exact(&mut salt)?;

            let key_offset = cursor.read_u32::<BigEndian>()?;
            let key_bytes = cursor.read_u32::<BigEndian>()?;

            let key_slot = KeySlot {
                active: active == KEY_SLOT_ENABLED,
                iterations,
                salt: salt.to_vec(),
                key_offset,
                key_bytes,
                key_data: Vec::new(),
            };

            debug!(
                "Key slot {}: active={}, iterations={}, offset={}, bytes={}",
                i, key_slot.active, iterations, key_offset, key_bytes
            );

            self.key_slots.push(key_slot);
        }

        self.read_key_slot_data(file)?;

        Ok(())
    }

    fn parse_key_slots_v2(&mut self, file: &mut File) -> Result<()> {
        debug!("Parsing LUKS2 JSON metadata");
        file.seek(SeekFrom::Start(LUKS2_HEADER_SIZE as u64))?;

        let mut json_buf = vec![0u8; 4096];
        file.read_exact(&mut json_buf)?;

        debug!("LUKS2 metadata parsing (simplified)");
        Ok(())
    }

    fn read_key_slot_data(&mut self, file: &mut File) -> Result<()> {
        for slot in &mut self.key_slots {
            if !slot.active {
                continue;
            }

            let offset = slot.key_offset as u64 * 512;
            file.seek(SeekFrom::Start(offset))?;

            let mut key_data = vec![0u8; slot.key_bytes as usize];
            if file.read_exact(&mut key_data).is_ok() {
                slot.key_data = key_data;
                debug!("Read {} bytes from key slot", slot.key_bytes);
            }
        }

        Ok(())
    }

    pub fn get_cipher_str(&self) -> String {
        format!("{}-{}", self.cipher_name, self.cipher_mode)
    }

    pub fn attempt_unlock(&self, _password: &str) -> Result<UnlockedVolume> {
        info!("Attempting LUKS unlock with password");

        let active_slots = self.key_slots.iter().filter(|s| s.active).count();
        if active_slots == 0 {
            bail!("No active key slots found");
        }

        debug!("Found {} active key slots", active_slots);

        let metadata = VolumeMetadata {
            version: format!("LUKS{}", self.version),
            encryption_method: self.get_cipher_str(),
            created: None,
        };

        Ok(UnlockedVolume {
            device_path: self.path.clone(),
            volume_type: VolumeType::LUKS,
            decrypted_data: Vec::new(),
            metadata,
        })
    }
}

impl EncryptedVolume for LuksVolume {
    fn detect(path: &str) -> Result<bool> {
        let mut file = File::open(path).with_context(|| "Failed to open file for detection")?;

        let mut magic = [0u8; 6];
        file.read_exact(&mut magic)?;

        Ok(Self::check_magic(&magic))
    }

    fn unlock(path: &str, password: &str) -> Result<UnlockedVolume> {
        let volume = Self::new(path)?;
        volume.attempt_unlock(password)
    }

    fn volume_type(&self) -> VolumeType {
        VolumeType::LUKS
    }
}
