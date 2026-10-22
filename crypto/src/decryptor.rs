use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use datadoctor_core::Error;
use datadoctor_core::Result;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use tracing::{debug, info};

const ZIP_LOCAL_HEADER: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const OLE2_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const PDF_MAGIC: [u8; 4] = [0x25, 0x50, 0x44, 0x46];
const AES_GCM_NONCE_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;
const AES_GCM_HEADER_SIZE: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionType {
    Aes256Gcm,
    ZipAes,
    PdfEncrypted,
    OfficeEncrypted,
    Unknown,
}

impl std::fmt::Display for EncryptionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionType::Aes256Gcm => write!(f, "AES-256-GCM"),
            EncryptionType::ZipAes => write!(f, "ZIP/AES"),
            EncryptionType::PdfEncrypted => write!(f, "PDF/Encrypted"),
            EncryptionType::OfficeEncrypted => write!(f, "Office/Encrypted"),
            EncryptionType::Unknown => write!(f, "Unknown"),
        }
    }
}

pub struct FileDecryptor;

impl FileDecryptor {
    pub fn new() -> Self {
        Self
    }

    fn is_zip(data: &[u8]) -> bool {
        data.len() >= 4 && data[0..4] == ZIP_LOCAL_HEADER
    }

    fn is_pdf(data: &[u8]) -> bool {
        data.len() >= 4 && data[0..4] == PDF_MAGIC
    }

    fn is_ole2(data: &[u8]) -> bool {
        data.len() >= 8 && data[0..8] == OLE2_MAGIC
    }

    fn is_zip_encrypted(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        let gpbf = u16::from_le_bytes([data[6], data[7]]);
        gpbf & 0x0001 != 0
    }

    fn has_pdf_encryption(data: &[u8]) -> bool {
        let search = b"/Encrypt";
        data.windows(search.len()).any(|w| w == search)
    }

    fn has_encrypted_package_stream(data: &[u8]) -> bool {
        let search = b"EncryptedPackage";
        data.windows(search.len()).any(|w| w == search)
    }

    fn is_likely_aes_gcm(data: &[u8]) -> bool {
        if data.len() < AES_GCM_HEADER_SIZE + 32 {
            return false;
        }
        if Self::is_zip(data) || Self::is_pdf(data) || Self::is_ole2(data) {
            return false;
        }
        let start = AES_GCM_HEADER_SIZE;
        let end = data.len().min(start + 512);
        let sample = &data[start..end];
        if sample.len() < 32 {
            return false;
        }
        let unique: HashSet<u8> = sample.iter().copied().collect();
        unique.len() > 200
    }

    fn detect_type(data: &[u8]) -> EncryptionType {
        if data.len() < 8 {
            return EncryptionType::Unknown;
        }

        if Self::is_zip(data) && Self::is_zip_encrypted(data) {
            return EncryptionType::ZipAes;
        }

        if Self::is_ole2(data) && Self::has_encrypted_package_stream(data) {
            return EncryptionType::OfficeEncrypted;
        }

        if Self::is_pdf(data) && Self::has_pdf_encryption(data) {
            return EncryptionType::PdfEncrypted;
        }

        if Self::is_likely_aes_gcm(data) {
            return EncryptionType::Aes256Gcm;
        }

        EncryptionType::Unknown
    }

    fn derive_key_sha256(password: &str, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    fn aes256gcm_decrypt(key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::DecryptionFailed(format!("Invalid AES key: {}", e)))?;
        let nonce = GenericArray::from_slice(nonce_bytes);

        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        cipher
            .decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|e| Error::DecryptionFailed(format!("AES-256-GCM auth failed: {}", e)))
    }

    fn parse_aes_gcm_format(data: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
        if data.len() <= AES_GCM_HEADER_SIZE {
            return Err(Error::DecryptionFailed(
                "Data too small for AES-256-GCM format".into(),
            ));
        }
        let nonce = &data[..AES_GCM_NONCE_SIZE];
        let tag = &data[AES_GCM_NONCE_SIZE..AES_GCM_HEADER_SIZE];
        let ciphertext = &data[AES_GCM_HEADER_SIZE..];
        Ok((nonce, tag, ciphertext))
    }

    fn decrypt_aes256gcm_file(data: &[u8], password: &str) -> Result<Vec<u8>> {
        let (nonce, tag, ciphertext) = Self::parse_aes_gcm_format(data)?;
        let key = Self::derive_key_sha256(password, nonce);
        Self::aes256gcm_decrypt(&key, nonce, ciphertext, tag)
    }

    fn decrypt_zip_entry(data: &[u8], password: &str) -> Result<Vec<u8>> {
        let cursor = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| Error::DecryptionFailed(format!("Invalid ZIP archive: {}", e)))?;

        info!("ZIP archive contains {} entries", archive.len());

        let mut output = Vec::new();
        let mut had_errors = false;

        for i in 0..archive.len() {
            match archive.by_index(i) {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    match file.read_to_end(&mut buf) {
                        Ok(_) => output.extend_from_slice(&buf),
                        Err(e) => {
                            debug!("Failed to read ZIP entry {}: {}", i, e);
                            had_errors = true;
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to access ZIP entry {}: {}", i, e);
                    had_errors = true;
                }
            }
        }

        if !output.is_empty() {
            return Ok(output);
        }

        if had_errors || output.is_empty() {
            debug!("ZIP crate could not decrypt entries, trying raw AES-GCM extraction");
        }

        if data.len() < 30 {
            return Err(Error::DecryptionFailed("ZIP file too small for raw extraction".into()));
        }

        let fname_len = u16::from_le_bytes([data[26], data[27]]) as usize;
        let extra_len = u16::from_le_bytes([data[28], data[29]]) as usize;
        let data_offset = 30 + fname_len + extra_len;

        if data_offset + AES_GCM_HEADER_SIZE >= data.len() {
            return Err(Error::DecryptionFailed(
                "No encrypted payload found in ZIP entry".into(),
            ));
        }

        let encrypted_payload = &data[data_offset..];
        let (nonce, tag, ciphertext) = Self::parse_aes_gcm_format(encrypted_payload)?;
        let key = Self::derive_key_sha256(password, nonce);
        Self::aes256gcm_decrypt(&key, nonce, ciphertext, tag)
    }

    fn decrypt_pdf_file(data: &[u8], password: &str) -> Result<Vec<u8>> {
        info!("Scanning PDF for encrypted streams");

        let stream_marker = b"stream\r\n";
        let stream_marker_alt = b"stream\n";
        let endstream_marker = b"endstream";

        let mut decrypted_data = Vec::new();
        let mut search_pos = 0;

        while search_pos < data.len() {
            let stream_start = Self::find_marker(data, search_pos, stream_marker)
                .or_else(|| Self::find_marker(data, search_pos, stream_marker_alt));

            let stream_start = match stream_start {
                Some(pos) => pos,
                None => break,
            };

            let marker_len = if data[stream_start..].starts_with(stream_marker) {
                stream_marker.len()
            } else {
                stream_marker_alt.len()
            };

            let content_start = stream_start + marker_len;

            let stream_end = match Self::find_marker(data, content_start, endstream_marker) {
                Some(pos) => pos,
                None => break,
            };

            let stream_data = &data[content_start..stream_end];

            if stream_data.len() > AES_GCM_HEADER_SIZE + 16 {
                match Self::parse_aes_gcm_format(stream_data) {
                    Ok((nonce, tag, ciphertext)) => {
                        let key = Self::derive_key_sha256(password, nonce);
                        match Self::aes256gcm_decrypt(&key, nonce, ciphertext, tag) {
                            Ok(decrypted) => {
                                debug!("Decrypted PDF stream at offset {}", content_start);
                                decrypted_data.extend_from_slice(&decrypted);
                            }
                            Err(_) => {
                                decrypted_data.extend_from_slice(stream_data);
                            }
                        }
                    }
                    Err(_) => {
                        decrypted_data.extend_from_slice(stream_data);
                    }
                }
            } else {
                decrypted_data.extend_from_slice(stream_data);
            }

            search_pos = stream_end + endstream_marker.len();
        }

        if decrypted_data.is_empty() {
            return Err(Error::DecryptionFailed(
                "No decryptable streams found in PDF".into(),
            ));
        }

        Ok(decrypted_data)
    }

    fn find_marker(data: &[u8], start: usize, marker: &[u8]) -> Option<usize> {
        if start + marker.len() > data.len() {
            return None;
        }
        data[start..]
            .windows(marker.len())
            .position(|w| w == marker)
            .map(|pos| start + pos)
    }

    fn decrypt_office_file(data: &[u8], password: &str) -> Result<Vec<u8>> {
        info!("Scanning OLE2 container for EncryptedPackage stream");

        let search = b"EncryptedPackage";

        let pkg_pos = data
            .windows(search.len())
            .position(|w| w == search)
            .ok_or_else(|| {
                Error::DecryptionFailed("EncryptedPackage stream not found in OLE2 container".into())
            })?;

        let data_start = pkg_pos + search.len();

        let mut offset = data_start;
        while offset < data.len() && offset < data_start + 16 {
            let remaining = &data[offset..];
            if remaining.len() > AES_GCM_HEADER_SIZE + 16 {
                match Self::parse_aes_gcm_format(remaining) {
                    Ok((nonce, tag, ciphertext)) => {
                        let key = Self::derive_key_sha256(password, nonce);
                        if let Ok(decrypted) = Self::aes256gcm_decrypt(&key, nonce, ciphertext, tag)
                        {
                            info!("Decrypted Office EncryptedPackage at offset {}", offset);
                            return Ok(decrypted);
                        }
                    }
                    Err(_) => {}
                }
            }
            offset += 1;
        }

        Err(Error::DecryptionFailed(
            "Could not decrypt EncryptedPackage from Office document".into(),
        ))
    }

    pub fn verify_password(&self, path: &Path, password: &str) -> Result<bool> {
        let data = fs::read(path)?;
        let enc_type = Self::detect_type(&data);

        match enc_type {
            EncryptionType::Aes256Gcm => match Self::decrypt_aes256gcm_file(&data, password) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            EncryptionType::ZipAes => match Self::decrypt_zip_entry(&data, password) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            EncryptionType::PdfEncrypted => match Self::decrypt_pdf_file(&data, password) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            EncryptionType::OfficeEncrypted => match Self::decrypt_office_file(&data, password) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            },
            EncryptionType::Unknown => Err(Error::DecryptionFailed(
                "Unknown encryption type cannot be verified".into(),
            )),
        }
    }

    pub fn try_decrypt_bytes(data: &[u8], password: &str) -> Result<Vec<u8>> {
        if data.len() <= AES_GCM_HEADER_SIZE {
            return Err(Error::DecryptionFailed("Data too small".into()));
        }

        let (nonce, tag, ciphertext) = Self::parse_aes_gcm_format(data)?;
        let key = Self::derive_key_sha256(password, nonce);
        Self::aes256gcm_decrypt(&key, nonce, ciphertext, tag)
    }
}

impl Default for FileDecryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::DecryptionEngine for FileDecryptor {
    fn decrypt_file(&self, input: &Path, output: &Path, password: &str) -> Result<()> {
        info!("Decrypting file: {} -> {}", input.display(), output.display());

        let data = fs::read(input)?;

        if data.len() < 8 {
            return Err(Error::DecryptionFailed("File too small to contain encrypted data".into()));
        }

        let enc_type = Self::detect_type(&data);
        info!("Detected encryption type: {}", enc_type);

        let decrypted = match enc_type {
            EncryptionType::Aes256Gcm => Self::decrypt_aes256gcm_file(&data, password)?,
            EncryptionType::ZipAes => Self::decrypt_zip_entry(&data, password)?,
            EncryptionType::PdfEncrypted => Self::decrypt_pdf_file(&data, password)?,
            EncryptionType::OfficeEncrypted => Self::decrypt_office_file(&data, password)?,
            EncryptionType::Unknown => {
                return Err(Error::DecryptionFailed(
                    "Unable to detect encryption type for file".into(),
                ));
            }
        };

        fs::write(output, &decrypted)?;
        info!("Successfully decrypted {} bytes to {}", decrypted.len(), output.display());

        Ok(())
    }

    fn is_encrypted(&self, path: &Path) -> Result<bool> {
        let data = fs::read(path)?;
        if data.len() < 8 {
            return Ok(false);
        }
        Ok(Self::detect_type(&data) != EncryptionType::Unknown)
    }

    fn get_encryption_type(&self, path: &Path) -> Result<String> {
        let data = fs::read(path)?;
        if data.len() < 8 {
            return Ok("Unknown".to_string());
        }
        Ok(Self::detect_type(&data).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptionEngine;
    use tempfile::TempDir;
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::Aes256Gcm;

    #[test]
    fn test_file_decryptor_creation() {
        let decryptor = FileDecryptor::new();
        let _ = decryptor;
    }

    #[test]
    fn test_file_decryptor_default() {
        let decryptor = FileDecryptor::default();
        let _ = decryptor;
    }

    #[test]
    fn test_detect_unencrypted_file_returns_false() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("plain.txt");
        std::fs::write(&file_path, b"Hello, this is plain text").unwrap();

        let decryptor = FileDecryptor::new();
        let is_enc = decryptor.is_encrypted(&file_path).unwrap();
        assert!(!is_enc);
    }

    #[test]
    fn test_detect_encrypted_zip_returns_true() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("encrypted.zip");

        let mut zip_data = vec![0x50, 0x4B, 0x03, 0x04];
        zip_data.extend_from_slice(&[0x14, 0x00]);
        let gpbf: u16 = 0x0001;
        zip_data.extend_from_slice(&gpbf.to_le_bytes());
        zip_data.extend_from_slice(&[0x00; 100]);
        std::fs::write(&file_path, &zip_data).unwrap();

        let decryptor = FileDecryptor::new();
        let is_enc = decryptor.is_encrypted(&file_path).unwrap();
        assert!(is_enc);

        let enc_type = decryptor.get_encryption_type(&file_path).unwrap();
        assert_eq!(enc_type, "ZIP/AES");
    }

    #[test]
    fn test_encryption_type_detection_pdf() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("encrypted.pdf");

        let mut pdf_data = b"%PDF-1.4\n/Encrypt << /Filter /Standard >>\n".to_vec();
        pdf_data.extend_from_slice(&[0u8; 100]);
        std::fs::write(&file_path, &pdf_data).unwrap();

        let decryptor = FileDecryptor::new();
        let enc_type = decryptor.get_encryption_type(&file_path).unwrap();
        assert_eq!(enc_type, "PDF/Encrypted");
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip() {
        let password = "testpassword";
        let nonce_bytes = [0x01u8; 12];
        let plaintext = b"secret message for testing roundtrip";

        let derived_key = FileDecryptor::derive_key_sha256(password, &nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&derived_key).unwrap();
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ciphertext_with_tag = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let ciphertext_len = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[..ciphertext_len];
        let tag = &ciphertext_with_tag[ciphertext_len..];

        let decrypted = FileDecryptor::aes256gcm_decrypt(&derived_key, &nonce_bytes, ciphertext, tag);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_detect_small_file_unknown() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("tiny.bin");
        std::fs::write(&file_path, &[0x00; 4]).unwrap();

        let decryptor = FileDecryptor::new();
        let enc_type = decryptor.get_encryption_type(&file_path).unwrap();
        assert_eq!(enc_type, "Unknown");
    }
}
