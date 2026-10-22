use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use tracing::debug;

use crate::error::{Error, Result};

const FAT_CLUSTER_SIZE: u32 = 512;
const NTFS_CLUSTER_SIZE: u32 = 4096;
const EXT4_BLOCK_SIZE: u32 = 4096;

const JPEG_SIGNATURE: &[u8] = &[0xFF, 0xD8, 0xFF];
const PNG_SIGNATURE: &[u8] = &[0x89, 0x50, 0x4E, 0x47];
const PDF_SIGNATURE: &[u8] = b"%PDF";
const ZIP_SIGNATURE: &[u8] = b"PK\x03\x04";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileSystemType {
    FAT,
    NTFS,
    Ext4,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFragment {
    pub cluster_id: u64,
    pub offset: u64,
    pub size: u32,
    pub data: Vec<u8>,
    pub file_signature: Option<String>,
    pub fragment_index: u32,
    pub file_system: FileSystemType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassembledFile {
    pub file_name: String,
    pub file_type: String,
    pub data: Vec<u8>,
    pub size: u64,
    pub fragments_used: Vec<u64>,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
struct FileSignatureDef {
    name: &'static str,
    magic: &'static [u8],
    extension: &'static str,
}

pub struct FragmentScanner {
    fragments: Vec<FileFragment>,
    file_system: FileSystemType,
    cluster_size: u32,
}

impl FragmentScanner {
    pub fn new() -> Self {
        Self {
            fragments: Vec::new(),
            file_system: FileSystemType::Unknown,
            cluster_size: NTFS_CLUSTER_SIZE,
        }
    }

    pub fn scan_fragments(data: &[u8], file_system: FileSystemType) -> Result<Vec<FileFragment>> {
        let mut scanner = Self::new();
        scanner.file_system = file_system.clone();
        scanner.cluster_size = match file_system {
            FileSystemType::FAT => FAT_CLUSTER_SIZE,
            FileSystemType::NTFS => NTFS_CLUSTER_SIZE,
            FileSystemType::Ext4 => EXT4_BLOCK_SIZE,
            FileSystemType::Unknown => NTFS_CLUSTER_SIZE,
        };
        scanner.scan_clusters(data)?;
        Ok(scanner.fragments)
    }

    pub fn reassemble_file(fragments: &[FileFragment]) -> Result<ReassembledFile> {
        if fragments.is_empty() {
            return Err(Error::ReassemblyFailed("No fragments provided".into()));
        }

        let mut sorted_frags = fragments.to_vec();
        sorted_frags.sort_by_key(|f| f.fragment_index);

        let mut data = Vec::new();
        let mut fragment_ids = Vec::new();

        for frag in &sorted_frags {
            data.extend_from_slice(&frag.data);
            fragment_ids.push(frag.cluster_id);
        }

        let file_type = Self::detect_file_type(&data)
            .unwrap_or_else(|| "unknown".to_string());

        let confidence = Self::calculate_confidence(&sorted_frags, &data);

        Ok(ReassembledFile {
            file_name: format!("recovered_{}.{}", fragment_ids[0], file_type),
            file_type,
            size: data.len() as u64,
            fragments_used: fragment_ids,
            confidence,
            data,
        })
    }

    fn scan_clusters(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(data);
        let data_len = data.len() as u64;
        let mut cluster_id = 0u64;
        let mut fragment_index = 0u32;

        while cursor.position() < data_len {
            let cluster_start = cursor.position();
            let cluster_end = (cluster_start + self.cluster_size as u64).min(data_len);
            let cluster_size = (cluster_end - cluster_start) as u32;

            let mut cluster_data = vec![0u8; cluster_size as usize];
            cursor.read_exact(&mut cluster_data)
                .map_err(|e| Error::Parse(format!("Cluster read error: {}", e)))?;

            if !Self::is_empty_cluster(&cluster_data) {
                let file_signature = Self::detect_signature(&cluster_data);

                self.fragments.push(FileFragment {
                    cluster_id,
                    offset: cluster_start,
                    size: cluster_size,
                    data: cluster_data,
                    file_signature,
                    fragment_index,
                    file_system: self.file_system.clone(),
                });

                fragment_index += 1;
            }

            cluster_id += 1;
        }

        debug!("Scanned {} fragments from {} clusters", self.fragments.len(), cluster_id);
        Ok(())
    }

    fn is_empty_cluster(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0 || b == 0xFF)
    }

    fn detect_signature(data: &[u8]) -> Option<String> {
        let signatures = vec![
            FileSignatureDef { name: "JPEG", magic: JPEG_SIGNATURE, extension: "jpg" },
            FileSignatureDef { name: "PNG", magic: PNG_SIGNATURE, extension: "png" },
            FileSignatureDef { name: "PDF", magic: PDF_SIGNATURE, extension: "pdf" },
            FileSignatureDef { name: "ZIP", magic: ZIP_SIGNATURE, extension: "zip" },
        ];

        for sig in signatures {
            if data.len() >= sig.magic.len() && &data[..sig.magic.len()] == sig.magic {
                return Some(sig.name.to_string());
            }
        }

        None
    }

    fn detect_file_type(data: &[u8]) -> Option<String> {
        let signatures = vec![
            FileSignatureDef { name: "jpeg", magic: JPEG_SIGNATURE, extension: "jpg" },
            FileSignatureDef { name: "png", magic: PNG_SIGNATURE, extension: "png" },
            FileSignatureDef { name: "pdf", magic: PDF_SIGNATURE, extension: "pdf" },
            FileSignatureDef { name: "zip", magic: ZIP_SIGNATURE, extension: "zip" },
        ];

        for sig in signatures {
            if data.len() >= sig.magic.len() && &data[..sig.magic.len()] == sig.magic {
                return Some(sig.extension.to_string());
            }
        }

        None
    }

    fn calculate_confidence(fragments: &[FileFragment], data: &[u8]) -> f32 {
        let mut confidence: f32 = 0.5;

        if Self::detect_file_type(data).is_some() {
            confidence += 0.3;
        }

        if fragments.windows(2).all(|w| w[0].fragment_index + 1 == w[1].fragment_index) {
            confidence += 0.2;
        }

        if !data.is_empty() && data[0] != 0 {
            confidence += 0.1;
        }

        confidence.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_signature_jpeg() {
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let sig = FragmentScanner::detect_signature(&data);
        assert_eq!(sig, Some("JPEG".to_string()));
    }

    #[test]
    fn test_detect_signature_png() {
        let data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let sig = FragmentScanner::detect_signature(&data);
        assert_eq!(sig, Some("PNG".to_string()));
    }

    #[test]
    fn test_detect_signature_none() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let sig = FragmentScanner::detect_signature(&data);
        assert_eq!(sig, None);
    }

    #[test]
    fn test_is_empty_cluster() {
        assert!(FragmentScanner::is_empty_cluster(&[0; 512]));
        assert!(FragmentScanner::is_empty_cluster(&[0xFF; 512]));
        assert!(!FragmentScanner::is_empty_cluster(&[0x00, 0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_reassemble_empty() {
        let result = FragmentScanner::reassemble_file(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_reassemble_single_fragment() {
        let frag = FileFragment {
            cluster_id: 0,
            offset: 0,
            size: 4,
            data: vec![0xFF, 0xD8, 0xFF, 0xE0],
            file_signature: Some("JPEG".to_string()),
            fragment_index: 0,
            file_system: FileSystemType::NTFS,
        };

        let result = FragmentScanner::reassemble_file(&[frag]).unwrap();
        assert_eq!(result.data.len(), 4);
        assert_eq!(result.file_type, "jpg");
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_reassemble_multiple_fragments() {
        let fragments = vec![
            FileFragment {
                cluster_id: 0,
                offset: 0,
                size: 4,
                data: vec![0xFF, 0xD8, 0xFF, 0xE0],
                file_signature: Some("JPEG".to_string()),
                fragment_index: 0,
                file_system: FileSystemType::NTFS,
            },
            FileFragment {
                cluster_id: 1,
                offset: 4096,
                size: 4,
                data: vec![0x00, 0x10, 0x01, 0x02],
                file_signature: None,
                fragment_index: 1,
                file_system: FileSystemType::NTFS,
            },
        ];

        let result = FragmentScanner::reassemble_file(&fragments).unwrap();
        assert_eq!(result.data.len(), 8);
        assert_eq!(result.fragments_used.len(), 2);
    }

    #[test]
    fn test_scan_fragments() {
        let mut data = vec![0u8; 2048];
        data[0..4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        data[1024..1028].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47]);

        let fragments = FragmentScanner::scan_fragments(&data, FileSystemType::FAT).unwrap();
        assert!(fragments.len() >= 2);
    }
}
