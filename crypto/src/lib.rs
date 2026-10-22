pub mod decryptor;
pub mod password;

use datadoctor_core::Result;
use std::path::Path;

pub trait DecryptionEngine {
    fn decrypt_file(&self, input: &Path, output: &Path, password: &str) -> Result<()>;
    fn is_encrypted(&self, path: &Path) -> Result<bool>;
    fn get_encryption_type(&self, path: &Path) -> Result<String>;
}
