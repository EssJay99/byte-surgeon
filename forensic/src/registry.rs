use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::path::Path;

use crate::error::{Error, Result};

const REGF_MAGIC: &[u8; 4] = b"regf";
#[allow(dead_code)]
const HBIN_MAGIC: &[u8; 4] = b"hbin";
#[allow(dead_code)]
const NK_MAGIC: u16 = 0x6B6E;
#[allow(dead_code)]
const VK_MAGIC: u16 = 0x6B76;
#[allow(dead_code)]
const LF_MAGIC: u16 = 0x666C;
#[allow(dead_code)]
const LH_MAGIC: u16 = 0x686C;
#[allow(dead_code)]
const LI_MAGIC: u16 = 0x696C;
#[allow(dead_code)]
const RI_MAGIC: u16 = 0x6972;
#[allow(dead_code)]
const DB_MAGIC: u16 = 0x6264;

#[allow(dead_code)]
const REG_SZ: u32 = 1;
#[allow(dead_code)]
const REG_EXPAND_SZ: u32 = 2;
#[allow(dead_code)]
const REG_BINARY: u32 = 3;
#[allow(dead_code)]
const REG_DWORD: u32 = 4;
#[allow(dead_code)]
const REG_MULTI_SZ: u32 = 7;
#[allow(dead_code)]
const REG_QWORD: u32 = 11;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryKey {
    pub name: String,
    pub path: String,
    pub last_write_time: NaiveDateTime,
    pub values: Vec<RegistryValue>,
    pub subkeys: Vec<RegistryKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
    pub data_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivity {
    pub timestamp: NaiveDateTime,
    pub activity_type: String,
    pub details: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: Option<NaiveDateTime>,
    pub uninstall_string: String,
}

pub struct RegistryParser {
    hive_data: Vec<u8>,
    root_key: Option<RegistryKey>,
}

impl RegistryParser {
    pub fn new() -> Self {
        Self {
            hive_data: Vec::new(),
            root_key: None,
        }
    }

    pub fn parse_hive(hive_path: &Path) -> Result<RegistryKey> {
        let data = std::fs::read(hive_path)
            .map_err(|e| Error::RegistryError(format!("Failed to read hive file: {}", e)))?;

        Self::parse_hive_data(&data)
    }

    pub fn parse_hive_data(data: &[u8]) -> Result<RegistryKey> {
        if data.len() < 4 || &data[0..4] != REGF_MAGIC {
            return Err(Error::RegistryError("Invalid registry hive magic".into()));
        }

        let mut parser = Self::new();
        parser.hive_data = data.to_vec();

        let root = parser.parse_registry_structure()?;
        Ok(root)
    }

    pub fn load_from_data(data: &[u8]) -> Result<Self> {
        if data.len() < 4 || &data[0..4] != REGF_MAGIC {
            return Err(Error::RegistryError("Invalid registry hive magic".into()));
        }

        let mut parser = Self::new();
        parser.hive_data = data.to_vec();

        let root = parser.parse_registry_structure()?;
        parser.root_key = Some(root);
        Ok(parser)
    }

    pub fn root_key(&self) -> Option<&RegistryKey> {
        self.root_key.as_ref()
    }

    pub fn get_value(&self, key_path: &str, value_name: &str) -> Result<RegistryValue> {
        let root = self.root_key.as_ref()
            .ok_or_else(|| Error::RegistryError("No hive loaded".into()))?;

        let key = Self::find_key_by_path(root, key_path)?;

        key.values
            .iter()
            .find(|v| v.name == value_name)
            .cloned()
            .ok_or_else(|| Error::RegistryError(format!("Value {} not found", value_name)))
    }

    pub fn extract_user_activity(&self) -> Vec<UserActivity> {
        let mut activities = Vec::new();

        if let Some(root) = &self.root_key {
            if let Ok(mru_key) = Self::find_key_by_path(root, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs") {
                for value in &mru_key.values {
                    activities.push(UserActivity {
                        timestamp: mru_key.last_write_time,
                        activity_type: "Recent Document".to_string(),
                        details: format!("{}: {}", value.name, value.data_string),
                        source: "RecentDocs".to_string(),
                    });
                }
            }

            if let Ok(run_key) = Self::find_key_by_path(root, "Software\\Microsoft\\Windows\\CurrentVersion\\Run") {
                for value in &run_key.values {
                    activities.push(UserActivity {
                        timestamp: run_key.last_write_time,
                        activity_type: "Startup Program".to_string(),
                        details: format!("{}: {}", value.name, value.data_string),
                        source: "Run".to_string(),
                    });
                }
            }
        }

        activities
    }

    pub fn extract_installed_software(&self) -> Vec<SoftwareEntry> {
        let mut software = Vec::new();

        if let Some(root) = &self.root_key {
            let paths = [
                "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            ];

            for path in &paths {
                if let Ok(uninstall_key) = Self::find_key_by_path(root, path) {
                    for subkey in &uninstall_key.subkeys {
                        let name = subkey.values.iter()
                            .find(|v| v.name == "DisplayName")
                            .map(|v| v.data_string.clone())
                            .unwrap_or_else(|| subkey.name.clone());

                        let version = subkey.values.iter()
                            .find(|v| v.name == "DisplayVersion")
                            .map(|v| v.data_string.clone())
                            .unwrap_or_default();

                        let publisher = subkey.values.iter()
                            .find(|v| v.name == "Publisher")
                            .map(|v| v.data_string.clone())
                            .unwrap_or_default();

                        let uninstall_string = subkey.values.iter()
                            .find(|v| v.name == "UninstallString")
                            .map(|v| v.data_string.clone())
                            .unwrap_or_default();

                        let install_date = subkey.values.iter()
                            .find(|v| v.name == "InstallDate")
                            .and_then(|v| NaiveDateTime::parse_from_str(&v.data_string, "%Y%m%d").ok());

                        software.push(SoftwareEntry {
                            name,
                            version,
                            publisher,
                            install_date,
                            uninstall_string,
                        });
                    }
                }
            }
        }

        software
    }

    fn parse_registry_structure(&mut self) -> Result<RegistryKey> {
        let mut cursor = Cursor::new(&self.hive_data[..]);
        cursor.set_position(0);

        let _magic = Self::read_bytes(&mut cursor, 4)?;
        let _seq1 = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Seq1 read error: {}", e)))?;
        let _seq2 = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Seq2 read error: {}", e)))?;

        let timestamp = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Timestamp read error: {}", e)))?;

        cursor.set_position(36);
        let _major_version = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Major version read error: {}", e)))?;
        let _minor_version = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Minor version read error: {}", e)))?;
        let _file_type = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("File type read error: {}", e)))?;
        let _hive_flags = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Hive flags read error: {}", e)))?;

        cursor.set_position(0x24);
        let _root_key_offset = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Root key offset read error: {}", e)))?;

        let last_write_time = Self::windows_filetime_to_datetime(timestamp)
            .unwrap_or_else(NaiveDateTime::default);

        let root_key = RegistryKey {
            name: "Root".to_string(),
            path: String::new(),
            last_write_time,
            values: Vec::new(),
            subkeys: Vec::new(),
        };

        self.root_key = Some(root_key.clone());
        Ok(root_key)
    }

    fn find_key_by_path<'a>(key: &'a RegistryKey, path: &str) -> Result<&'a RegistryKey> {
        let parts: Vec<&str> = path.split('\\').collect();
        let mut current = key;

        for part in parts {
            if part.is_empty() {
                continue;
            }

            let found = current.subkeys.iter().find(|k| k.name == part);
            match found {
                Some(k) => current = k,
                None => return Err(Error::RegistryError(format!("Key {} not found", path))),
            }
        }

        Ok(current)
    }

    fn read_bytes(cursor: &mut Cursor<&[u8]>, count: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; count];
        cursor.read_exact(&mut buf)
            .map_err(|e| Error::Parse(format!("Read error: {}", e)))?;
        Ok(buf)
    }

    fn windows_filetime_to_datetime(filetime: u64) -> Option<NaiveDateTime> {
        if filetime == 0 {
            return None;
        }
        let ticks_since_epoch = filetime.saturating_sub(116444736000000000);
        let secs = (ticks_since_epoch / 10_000_000) as i64;
        let nsecs = ((ticks_since_epoch % 10_000_000) * 100) as u32;
        Utc.timestamp_opt(secs, nsecs).single().map(|dt| dt.naive_utc())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_hive() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(REGF_MAGIC);
        data.extend_from_slice(&[0u8; 4]);
        data.extend_from_slice(&[0u8; 4]);
        data.extend_from_slice(&132456789012345678u64.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 20]);
        data
    }

    #[test]
    fn test_parse_hive_magic() {
        let data = build_minimal_hive();
        let result = RegistryParser::parse_hive_data(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_hive() {
        let data = b"invalid hive data";
        let result = RegistryParser::parse_hive_data(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_windows_filetime_to_datetime() {
        let filetime: u64 = 132456789012345678;
        let dt = RegistryParser::windows_filetime_to_datetime(filetime);
        assert!(dt.is_some());
    }

    #[test]
    fn test_find_key_by_path_empty() {
        let key = RegistryKey {
            name: "Root".to_string(),
            path: String::new(),
            last_write_time: NaiveDateTime::default(),
            values: Vec::new(),
            subkeys: Vec::new(),
        };
        let result = RegistryParser::find_key_by_path(&key, "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_user_activity_empty() {
        let parser = RegistryParser::new();
        let activities = parser.extract_user_activity();
        assert!(activities.is_empty());
    }

    #[test]
    fn test_extract_installed_software_empty() {
        let parser = RegistryParser::new();
        let software = parser.extract_installed_software();
        assert!(software.is_empty());
    }
}
