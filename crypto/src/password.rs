use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use datadoctor_core::Error;
use datadoctor_core::Result;
use std::fs;
use std::path::Path;
use tracing::{debug, info};

const AES_GCM_NONCE_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;
const AES_GCM_HEADER_SIZE: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;

pub struct PasswordCracker {
    wordlist: Vec<String>,
}

impl PasswordCracker {
    pub fn new() -> Self {
        Self {
            wordlist: Self::default_wordlist(),
        }
    }

    fn default_wordlist() -> Vec<String> {
        [
            "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
            "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
            "ashley", "michael", "shadow", "123123", "654321", "admin", "welcome", "login",
            "princess", "football", "shadow123", "000000", "passw0rd", "hello", "charlie",
            "donald", "password1", "pa55word", "test", "1234", "12345", "987654321",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    pub fn with_custom_words(mut self, words: Vec<String>) -> Self {
        self.wordlist.extend(words);
        self
    }

    pub fn with_wordlist_file(mut self, path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let words: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        if words.is_empty() {
            return Err(Error::DecryptionFailed(format!(
                "Wordlist file is empty: {}",
                path.display()
            )));
        }

        info!("Loaded {} words from {}", words.len(), path.display());
        self.wordlist.extend(words);
        Ok(self)
    }

    pub fn with_replacement_wordlist(mut self, words: Vec<String>) -> Self {
        self.wordlist = words;
        self
    }

    fn derive_key_argon2(password: &str, salt: &[u8]) -> std::result::Result<[u8; 32], String> {
        use argon2::Argon2;

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;
        Ok(key)
    }

    fn try_decrypt_with_password(
        encrypted_data: &[u8],
        password: &str,
    ) -> std::result::Result<Vec<u8>, String> {
        if encrypted_data.len() <= AES_GCM_HEADER_SIZE {
            return Err("Data too small for AES-256-GCM format".into());
        }

        let nonce_bytes = &encrypted_data[..AES_GCM_NONCE_SIZE];
        let tag = &encrypted_data[AES_GCM_NONCE_SIZE..AES_GCM_HEADER_SIZE];
        let ciphertext = &encrypted_data[AES_GCM_HEADER_SIZE..];

        let key = Self::derive_key_argon2(password, nonce_bytes)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| format!("Invalid AES key: {}", e))?;
        let nonce = GenericArray::from_slice(nonce_bytes);

        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        cipher
            .decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|_| "AES-GCM authentication failed".into())
    }

    pub fn try_crack<F>(&self, encrypted_data: &[u8], mut callback: F) -> Result<Option<String>>
    where
        F: FnMut(&str) -> bool,
    {
        info!(
            "Starting password crack attempt with {} candidates",
            self.wordlist.len()
        );

        if encrypted_data.len() <= AES_GCM_HEADER_SIZE {
            return Err(Error::DecryptionFailed(
                "Encrypted data too small for AES-256-GCM format".into(),
            ));
        }

        let total = self.wordlist.len();

        for (idx, password) in self.wordlist.iter().enumerate() {
            if !callback(password) {
                info!("Password cracking cancelled by callback at attempt {}", idx);
                return Ok(None);
            }

            debug!(
                "Trying password candidate {}/{}: {}",
                idx + 1,
                total,
                password
            );

            match Self::try_decrypt_with_password(encrypted_data, password) {
                Ok(_plaintext) => {
                    info!("Password found after {} attempts: {}", idx + 1, password);
                    return Ok(Some(password.clone()));
                }
                Err(_) => {
                    continue;
                }
            }
        }

        info!("Password not found after {} attempts", total);
        Ok(None)
    }

    pub fn try_crack_file<F>(&self, path: &Path, callback: F) -> Result<Option<String>>
    where
        F: FnMut(&str) -> bool,
    {
        info!("Loading encrypted file for cracking: {}", path.display());
        let data = fs::read(path)?;
        self.try_crack(&data, callback)
    }

    pub fn wordlist_size(&self) -> usize {
        self.wordlist.len()
    }
}

impl Default for PasswordCracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_password_cracker_creation() {
        let cracker = PasswordCracker::new();
        assert!(cracker.wordlist_size() > 0);
    }

    #[test]
    fn test_default_wordlist() {
        let cracker = PasswordCracker::new();
        assert!(cracker.wordlist.contains(&"password".to_string()));
        assert!(cracker.wordlist.contains(&"123456".to_string()));
        assert!(cracker.wordlist.contains(&"qwerty".to_string()));
    }

    #[test]
    fn test_custom_wordlist() {
        let cracker = PasswordCracker::new().with_custom_words(vec!["mysecret".to_string()]);
        assert!(cracker.wordlist.contains(&"mysecret".to_string()));
        assert!(cracker.wordlist.contains(&"password".to_string()));
    }

    #[test]
    fn test_replacement_wordlist() {
        let cracker = PasswordCracker::new().with_replacement_wordlist(vec!["only_this".to_string()]);
        assert_eq!(cracker.wordlist_size(), 1);
        assert!(cracker.wordlist.contains(&"only_this".to_string()));
    }

    #[test]
    fn test_custom_wordlist_file() {
        let temp_dir = TempDir::new().unwrap();
        let wordlist_path = temp_dir.path().join("words.txt");
        std::fs::write(&wordlist_path, "word1\nword2\nword3\n").unwrap();

        let cracker = PasswordCracker::new().with_wordlist_file(&wordlist_path).unwrap();
        assert!(cracker.wordlist.contains(&"word1".to_string()));
        assert!(cracker.wordlist.contains(&"word2".to_string()));
        assert!(cracker.wordlist.contains(&"word3".to_string()));
    }

    #[test]
    fn test_crack_returns_none_for_unknown_password() {
        let cracker = PasswordCracker::new().with_replacement_wordlist(vec![
            "wrong1".to_string(),
            "wrong2".to_string(),
        ]);

        let mut fake_encrypted = vec![0u8; 12 + 16 + 64];
        for b in fake_encrypted.iter_mut().skip(28) {
            *b = 0xFF;
        }

        let result = cracker.try_crack(&fake_encrypted, |_| true).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_crack_callback_cancel() {
        let cracker = PasswordCracker::new();

        let fake_encrypted = vec![0u8; 12 + 16 + 64];
        let result = cracker.try_crack(&fake_encrypted, |_| false).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_default_trait() {
        let cracker = PasswordCracker::default();
        assert!(cracker.wordlist_size() > 0);
    }
}
