use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use tracing::debug;

use crate::error::{Error, Result};

#[allow(dead_code)]
const VSS_MAGIC: &[u8; 8] = b"VSS\x00\x00\x00\x00\x00";
const VSS_STORE_MAGIC: u32 = 0x20040428;
const CATALOG_MAGIC: u64 = 0x434154414C4F4700;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowCopy {
    pub id: String,
    pub volume_path: String,
    pub creation_time: NaiveDateTime,
    pub size_bytes: u64,
    pub file_count: u64,
    pub store_offset: u64,
    pub catalog_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowFile {
    pub path: String,
    pub size: u64,
    pub offset: u64,
    pub attributes: u32,
    pub creation_time: NaiveDateTime,
    pub modification_time: NaiveDateTime,
}

pub struct ShadowCopyParser {
    shadow_copies: Vec<ShadowCopy>,
}

impl ShadowCopyParser {
    pub fn new() -> Self {
        Self {
            shadow_copies: Vec::new(),
        }
    }

    pub fn detect_shadow_copies(data: &[u8]) -> Result<Vec<ShadowCopy>> {
        let mut parser = Self::new();
        parser.scan_for_shadow_stores(data)?;
        Ok(parser.shadow_copies)
    }

    pub fn extract_file(data: &[u8], shadow_id: &str, file_path: &str) -> Result<Vec<u8>> {
        let shadow_copies = Self::detect_shadow_copies(data)?;
        let shadow = shadow_copies
            .iter()
            .find(|s| s.id == shadow_id)
            .ok_or_else(|| Error::ShadowCopyError(format!("Shadow copy {} not found", shadow_id)))?;

        let catalog_data = data
            .get(shadow.catalog_offset as usize..)
            .ok_or_else(|| Error::ShadowCopyError("Catalog offset out of bounds".into()))?;

        let files = Self::parse_catalog(catalog_data)?;
        let target_file = files
            .iter()
            .find(|f| f.path == file_path)
            .ok_or_else(|| Error::ShadowCopyError(format!("File {} not found in shadow", file_path)))?;

        let file_data = data
            .get(target_file.offset as usize..target_file.offset as usize + target_file.size as usize)
            .ok_or_else(|| Error::ShadowCopyError("File data out of bounds".into()))?;

        Ok(file_data.to_vec())
    }

    fn scan_for_shadow_stores(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(data);
        let data_len = data.len() as u64;

        while cursor.position() < data_len.saturating_sub(512) {
            let pos = cursor.position();

            let magic = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };

            if magic == VSS_STORE_MAGIC {
                if let Ok(shadow) = self.parse_shadow_store(&mut cursor, pos) {
                    debug!("Found shadow copy: {} at offset {}", shadow.id, pos);
                    self.shadow_copies.push(shadow);
                }
            }

            cursor.set_position(pos + 512);
        }

        Ok(())
    }

    fn parse_shadow_store(&self, cursor: &mut Cursor<&[u8]>, store_offset: u64) -> Result<ShadowCopy> {
        cursor.set_position(store_offset + 4);

        let _version = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Version read error: {}", e)))?;

        let catalog_offset = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Catalog offset read error: {}", e)))?;

        let store_size = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Store size read error: {}", e)))?;

        let creation_time_raw = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Creation time read error: {}", e)))?;

        let mut id_bytes = [0u8; 16];
        cursor.read_exact(&mut id_bytes)
            .map_err(|e| Error::Parse(format!("ID read error: {}", e)))?;

        let id = Self::format_guid(&id_bytes);

        let mut volume_path_bytes = [0u8; 256];
        cursor.read_exact(&mut volume_path_bytes)
            .map_err(|e| Error::Parse(format!("Volume path read error: {}", e)))?;

        let volume_path = Self::decode_utf16le_null(&volume_path_bytes);

        let creation_time = Self::windows_filetime_to_datetime(creation_time_raw)
            .unwrap_or_else(NaiveDateTime::default);

        Ok(ShadowCopy {
            id,
            volume_path,
            creation_time,
            size_bytes: store_size,
            file_count: 0,
            store_offset,
            catalog_offset,
        })
    }

    fn parse_catalog(data: &[u8]) -> Result<Vec<ShadowFile>> {
        let mut files = Vec::new();
        let mut cursor = Cursor::new(data);
        let data_len = data.len() as u64;

        let catalog_magic = match cursor.read_u64::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => return Ok(files),
        };

        if catalog_magic != CATALOG_MAGIC {
            debug!("Invalid catalog magic: {:x}", catalog_magic);
            return Ok(files);
        }

        let _version = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Catalog version read error: {}", e)))?;

        let entry_count = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Entry count read error: {}", e)))?;

        for _ in 0..entry_count {
            if cursor.position() >= data_len {
                break;
            }

            let file_offset = cursor.read_u64::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("File offset read error: {}", e)))?;

            let file_size = cursor.read_u64::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("File size read error: {}", e)))?;

            let attributes = cursor.read_u32::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Attributes read error: {}", e)))?;

            let creation_time = cursor.read_u64::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Creation time read error: {}", e)))?;

            let modification_time = cursor.read_u64::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Modification time read error: {}", e)))?;

            let path_length = cursor.read_u16::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Path length read error: {}", e)))?;

            let path = if path_length > 0 && (cursor.position() + path_length as u64) <= data_len {
                let mut path_bytes = vec![0u8; path_length as usize];
                cursor.read_exact(&mut path_bytes)
                    .map_err(|e| Error::Parse(format!("Path read error: {}", e)))?;
                Self::decode_utf16le(&path_bytes)
            } else {
                String::new()
            };

            files.push(ShadowFile {
                path,
                size: file_size,
                offset: file_offset,
                attributes,
                creation_time: Self::windows_filetime_to_datetime(creation_time)
                    .unwrap_or_else(NaiveDateTime::default),
                modification_time: Self::windows_filetime_to_datetime(modification_time)
                    .unwrap_or_else(NaiveDateTime::default),
            });
        }

        Ok(files)
    }

    fn format_guid(bytes: &[u8; 16]) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
            u16::from_le_bytes([bytes[6], bytes[7]]),
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }

    fn decode_utf16le(data: &[u8]) -> String {
        char::decode_utf16(
            data.chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        )
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
    }

    fn decode_utf16le_null(data: &[u8]) -> String {
        Self::decode_utf16le(data)
            .trim_end_matches('\0')
            .to_string()
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

    #[test]
    fn test_format_guid() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06,
            0x07, 0x08,
            0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        let guid = ShadowCopyParser::format_guid(&bytes);
        assert_eq!(guid, "04030201-0605-0807-090a-0b0c0d0e0f10");
    }

    #[test]
    fn test_decode_utf16le() {
        let input = b"h\x00e\x00l\x00l\x00o\x00";
        assert_eq!(ShadowCopyParser::decode_utf16le(input), "hello");
    }

    #[test]
    fn test_decode_utf16le_null() {
        let input = b"h\x00i\x00\x00\x00\x00\x00";
        assert_eq!(ShadowCopyParser::decode_utf16le_null(input), "hi");
    }

    #[test]
    fn test_windows_filetime_to_datetime() {
        let filetime: u64 = 132456789012345678;
        let dt = ShadowCopyParser::windows_filetime_to_datetime(filetime);
        assert!(dt.is_some());
    }

    #[test]
    fn test_empty_detection() {
        let copies = ShadowCopyParser::detect_shadow_copies(&[]).unwrap();
        assert!(copies.is_empty());
    }

    #[test]
    fn test_shadow_store_magic() {
        let mut data = vec![0u8; 1024];
        data[0..4].copy_from_slice(&VSS_STORE_MAGIC.to_le_bytes());
        let copies = ShadowCopyParser::detect_shadow_copies(&data).unwrap();
        assert!(!copies.is_empty());
    }
}
