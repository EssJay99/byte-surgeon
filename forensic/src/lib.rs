pub mod error;
pub mod fragments;
pub mod registry;
pub mod repair;
pub mod shadow_copy;
pub mod usn_journal;

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::fragments::FileSystemType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnEntry {
    pub filename: String,
    pub parent_ref: u64,
    pub usn: u64,
    pub timestamp: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopy {
    pub id: String,
    pub volume: String,
    pub size: u64,
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {
    pub offset: u64,
    pub size: u64,
    pub signature: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    pub success: bool,
    pub format: String,
    pub input_size: u64,
    pub output_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryResult {
    pub keys: Vec<String>,
    pub values: Vec<String>,
    pub user_activity: Vec<String>,
}

pub struct UsnJournalParser;

impl UsnJournalParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, device_path: &str) -> Result<Vec<UsnEntry>, String> {
        let data = std::fs::read(device_path)
            .map_err(|e| format!("Failed to read device {}: {}", device_path, e))?;

        let entries = usn_journal::UsnJournalParser::parse_journal(&data)
            .map_err(|e| format!("USN journal parse error: {}", e))?;

        let deleted = usn_journal::UsnJournalParser::find_deleted_files(&entries);

        let mut result: Vec<UsnEntry> = entries
            .iter()
            .map(|e| UsnEntry {
                filename: e.file_name.clone(),
                parent_ref: e.parent_reference_number,
                usn: e.usn,
                timestamp: e.timestamp.to_string(),
                reason: format!("{:?}", e.reason),
            })
            .collect();

        if result.is_empty() && !deleted.is_empty() {
            result = deleted
                .iter()
                .map(|d| UsnEntry {
                    filename: d.file_name.clone(),
                    parent_ref: d.parent_reference_number,
                    usn: 0,
                    timestamp: d.deleted_at.to_string(),
                    reason: "FILE_DELETED".to_string(),
                })
                .collect();
        }

        Ok(result)
    }
}

pub struct ShadowCopyDetector;

impl ShadowCopyDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, device_path: &str) -> Result<Vec<ShadowCopy>, String> {
        let data = std::fs::read(device_path)
            .map_err(|e| format!("Failed to read device {}: {}", device_path, e))?;

        let copies = shadow_copy::ShadowCopyParser::detect_shadow_copies(&data)
            .map_err(|e| format!("Shadow copy detection error: {}", e))?;

        Ok(copies
            .iter()
            .map(|c| ShadowCopy {
                id: c.id.clone(),
                volume: c.volume_path.clone(),
                size: c.size_bytes,
                created: c.creation_time.to_string(),
            })
            .collect())
    }
}

pub struct FragmentScanner;

impl FragmentScanner {
    pub fn new() -> Self {
        Self
    }

    pub fn scan(&self, device_path: &str) -> Result<Vec<Fragment>, String> {
        let data = std::fs::read(device_path)
            .map_err(|e| format!("Failed to read device {}: {}", device_path, e))?;

        let fs_type = Self::detect_file_system(&data);

        let file_fragments = fragments::FragmentScanner::scan_fragments(&data, fs_type)
            .map_err(|e| format!("Fragment scan error: {}", e))?;

        Ok(file_fragments
            .iter()
            .map(|f| {
                let confidence = if f.file_signature.is_some() {
                    0.9
                } else {
                    0.3
                };
                Fragment {
                    offset: f.offset,
                    size: f.size as u64,
                    signature: f.file_signature.clone().unwrap_or_else(|| "unknown".to_string()),
                    confidence,
                }
            })
            .collect())
    }

    fn detect_file_system(data: &[u8]) -> FileSystemType {
        if data.len() < 512 {
            return FileSystemType::Unknown;
        }
        if data.len() > 0x200 {
            let ntfs_check = &data[3..7];
            if ntfs_check == b"NTFS" {
                return FileSystemType::NTFS;
            }
        }
        if data.len() > 0x36 {
            let fat_check = &data[0x36..0x3A];
            if fat_check == b"FAT " || fat_check == b"FAT1" || fat_check == b"FAT3" {
                return FileSystemType::FAT;
            }
        }
        if data.len() > 0x400 {
            if &data[0x438..0x43C] == [0x53, 0xEF, 0x01, 0x00] {
                return FileSystemType::Ext4;
            }
        }
        FileSystemType::NTFS
    }
}

pub struct FileReparer;

impl FileReparer {
    pub fn new() -> Self {
        Self
    }

    pub fn repair(
        &self,
        input_path: &Path,
        output_path: &Path,
        format: &str,
    ) -> Result<RepairResult, String> {
        let input_data = std::fs::read(input_path)
            .map_err(|e| format!("Failed to read input file: {}", e))?;

        let input_size = input_data.len() as u64;
        let engine = repair::FileRepairEngine::new();

        let repair_result = match format.to_lowercase().as_str() {
            "jpeg" | "jpg" => engine
                .repair_jpeg(&input_data)
                .map_err(|e| format!("JPEG repair error: {}", e))?,
            "zip" => engine
                .repair_zip(&input_data)
                .map_err(|e| format!("ZIP repair error: {}", e))?,
            "pdf" => engine
                .repair_pdf(&input_data)
                .map_err(|e| format!("PDF repair error: {}", e))?,
            "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" => engine
                .repair_office(&input_data)
                .map_err(|e| format!("Office repair error: {}", e))?,
            "mp4" | "mov" => engine
                .repair_video(&input_data, format)
                .map_err(|e| format!("Video repair error: {}", e))?,
            _ => {
                let result = repair::RepairResult {
                    success: false,
                    original_size: input_size,
                    repaired_size: 0,
                    repairs_applied: vec![format!("Unsupported format: {}", format)],
                    data: Vec::new(),
                };
                return Ok(RepairResult {
                    success: result.success,
                    format: format.to_string(),
                    input_size,
                    output_size: 0,
                });
            }
        };

        let output_size = repair_result.data.len() as u64;

        if let Some(parent) = output_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        std::fs::write(output_path, &repair_result.data)
            .map_err(|e| format!("Failed to write output file: {}", e))?;

        Ok(RepairResult {
            success: repair_result.success,
            format: format.to_string(),
            input_size,
            output_size,
        })
    }
}

pub struct RegistryParser;

impl RegistryParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, hive_path: &str) -> Result<RegistryResult, String> {
        let path = Path::new(hive_path);

        let hive_data = std::fs::read(path)
            .map_err(|e| format!("Failed to read hive file: {}", e))?;

        let parser = registry::RegistryParser::load_from_data(&hive_data)
            .map_err(|e| format!("Registry parse error: {}", e))?;

        let root_key = parser.root_key()
            .ok_or_else(|| "Failed to extract root key".to_string())?;

        let mut keys = Vec::new();
        let mut values = Vec::new();
        Self::collect_keys_and_values(root_key, &mut keys, &mut values);

        let user_activities = parser.extract_user_activity();
        let user_activity: Vec<String> = user_activities
            .iter()
            .map(|a| format!("[{}] {} - {}", a.timestamp, a.activity_type, a.details))
            .collect();

        let software = parser.extract_installed_software();
        for sw in &software {
            values.push(format!("Software: {} v{} ({})", sw.name, sw.version, sw.publisher));
        }

        Ok(RegistryResult {
            keys,
            values,
            user_activity,
        })
    }

    fn collect_keys_and_values(
        key: &registry::RegistryKey,
        keys: &mut Vec<String>,
        values: &mut Vec<String>,
    ) {
        keys.push(key.path.clone());
        for value in &key.values {
            values.push(format!("{} = {}", value.name, value.data_string));
        }
        for subkey in &key.subkeys {
            Self::collect_keys_and_values(subkey, keys, values);
        }
    }
}
