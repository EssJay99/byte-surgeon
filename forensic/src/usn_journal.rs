use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{NaiveDateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read};
use tracing::debug;

use crate::error::{Error, Result};

#[allow(dead_code)]
const USN_RECORD_V2_HEADER_SIZE: u32 = 60;
#[allow(dead_code)]
const USN_RECORD_V3_HEADER_SIZE: u32 = 56;
#[allow(dead_code)]
const MAX_RECORD_SIZE: u32 = 4096;

#[allow(dead_code)]
const FILE_ATTRIBUTE_READONLY: u32 = 0x01;
#[allow(dead_code)]
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;
#[allow(dead_code)]
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x04;
#[allow(dead_code)]
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
#[allow(dead_code)]
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReasonCode: u32 {
        const FILE_CREATED       = 0x00000001;
        const FILE_DELETED       = 0x00000002;
        const FILE_EXTENDED      = 0x00000004;
        const FILE_TRUNCATED     = 0x00000008;
        const FILE_MODIFIED      = 0x00000010;
        const FILE_RENAMED_OLD   = 0x00000020;
        const FILE_RENAMED_NEW   = 0x00000040;
        const EA_CHANGED         = 0x00000100;
        const USN_CLOSE          = 0x80000000;
        const OVERFLOW           = 0x00000000;
    }
}

impl Serialize for ReasonCode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReasonCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(ReasonCode::from_bits_truncate(bits))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnRecord {
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference_number: u64,
    pub parent_file_reference_number: u64,
    pub usn: u64,
    pub timestamp: NaiveDateTime,
    pub reason: ReasonCode,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnEntry {
    pub usn: u64,
    pub file_reference_number: u64,
    pub parent_reference_number: u64,
    pub file_name: String,
    pub file_path: String,
    pub timestamp: NaiveDateTime,
    pub reason: ReasonCode,
    pub file_attributes: u32,
    pub is_directory: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedFile {
    pub file_name: String,
    pub file_path: String,
    pub deleted_at: NaiveDateTime,
    pub file_reference_number: u64,
    pub parent_reference_number: u64,
    pub size_estimate: Option<u64>,
}

pub struct UsnJournalParser {
    entries: Vec<UsnEntry>,
    frn_to_path: HashMap<u64, String>,
}

impl UsnJournalParser {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            frn_to_path: HashMap::new(),
        }
    }

    pub fn parse_journal(data: &[u8]) -> Result<Vec<UsnEntry>> {
        let mut parser = Self::new();
        parser.parse_usn_records(data)?;
        parser.build_path_map();
        parser.resolve_paths();
        Ok(parser.entries)
    }

    pub fn find_deleted_files(entries: &[UsnEntry]) -> Vec<DeletedFile> {
        entries
            .iter()
            .filter(|e| e.reason.contains(ReasonCode::FILE_DELETED))
            .map(|e| DeletedFile {
                file_name: e.file_name.clone(),
                file_path: e.file_path.clone(),
                deleted_at: e.timestamp,
                file_reference_number: e.file_reference_number,
                parent_reference_number: e.parent_reference_number,
                size_estimate: None,
            })
            .collect()
    }

    fn parse_usn_records(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = Cursor::new(data);
        let data_len = data.len() as u64;

        while cursor.position() < data_len {
            let start_pos = cursor.position();

            let record_length = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };

            if record_length == 0 || record_length > MAX_RECORD_SIZE {
                cursor.set_position(start_pos + 4);
                continue;
            }

            let major_version = cursor.read_u16::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Failed to read major version: {}", e)))?;
            let _minor_version = cursor.read_u16::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Failed to read minor version: {}", e)))?;

            let entry = match major_version {
                2 => self.parse_v2_record(&mut cursor, record_length)?,
                3 => self.parse_v3_record(&mut cursor, record_length)?,
                4 => self.parse_v4_record(&mut cursor, record_length)?,
                _ => {
                    debug!("Unknown USN record version: {}", major_version);
                    cursor.set_position(start_pos + record_length as u64);
                    continue;
                }
            };

            if let Some(entry) = entry {
                debug!("Parsed USN entry: {} (USN: {})", entry.file_name, entry.usn);
                self.entries.push(entry);
            }

            cursor.set_position(start_pos + record_length as u64);
        }

        Ok(())
    }

    fn parse_v2_record(&self, cursor: &mut Cursor<&[u8]>, _record_length: u32) -> Result<Option<UsnEntry>> {
        let file_reference_number = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("FRN read error: {}", e)))?;

        let parent_file_reference_number = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Parent FRN read error: {}", e)))?;

        let usn = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("USN read error: {}", e)))?;

        let timestamp_raw = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Timestamp read error: {}", e)))?;

        let reason = ReasonCode::from_bits_truncate(
            cursor.read_u32::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Reason read error: {}", e)))?
        );

        let _source_info = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Source info read error: {}", e)))?;

        let _security_id = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Security ID read error: {}", e)))?;

        let file_attributes = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("File attributes read error: {}", e)))?;

        let file_name_length = cursor.read_u16::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Filename length read error: {}", e)))?;

        let _file_name_offset = cursor.read_u16::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Filename offset read error: {}", e)))?;

        let file_name = if file_name_length > 0 {
            let mut name_buf = vec![0u8; file_name_length as usize];
            cursor.read_exact(&mut name_buf)
                .map_err(|e| Error::Parse(format!("Filename read error: {}", e)))?;
            Self::decode_utf16le(&name_buf)
        } else {
            String::new()
        };

        let timestamp = Self::windows_filetime_to_datetime(timestamp_raw)
            .unwrap_or_else(|| NaiveDateTime::default());

        let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        Ok(Some(UsnEntry {
            usn,
            file_reference_number,
            parent_reference_number: parent_file_reference_number,
            file_name,
            file_path: String::new(),
            timestamp,
            reason,
            file_attributes,
            is_directory,
        }))
    }

    fn parse_v3_record(&self, cursor: &mut Cursor<&[u8]>, _record_length: u32) -> Result<Option<UsnEntry>> {
        let file_reference_number = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("FRN read error: {}", e)))?;

        let parent_file_reference_number = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Parent FRN read error: {}", e)))?;

        let usn = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("USN read error: {}", e)))?;

        let reason = ReasonCode::from_bits_truncate(
            cursor.read_u32::<LittleEndian>()
                .map_err(|e| Error::Parse(format!("Reason read error: {}", e)))?
        );

        let _source_info = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Source info read error: {}", e)))?;

        let _sid = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("SID read error: {}", e)))?;

        let file_attributes = cursor.read_u32::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("File attributes read error: {}", e)))?;

        let file_name_length = cursor.read_u16::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Filename length read error: {}", e)))?;

        let _file_name_offset = cursor.read_u16::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Filename offset read error: {}", e)))?;

        let file_name = if file_name_length > 0 {
            let mut name_buf = vec![0u8; file_name_length as usize];
            cursor.read_exact(&mut name_buf)
                .map_err(|e| Error::Parse(format!("Filename read error: {}", e)))?;
            Self::decode_utf16le(&name_buf)
        } else {
            String::new()
        };

        let is_directory = (file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        Ok(Some(UsnEntry {
            usn,
            file_reference_number,
            parent_reference_number: parent_file_reference_number,
            file_name,
            file_path: String::new(),
            timestamp: NaiveDateTime::default(),
            reason,
            file_attributes,
            is_directory,
        }))
    }

    fn parse_v4_record(&self, cursor: &mut Cursor<&[u8]>, record_length: u32) -> Result<Option<UsnEntry>> {
        let file_reference_number = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("FRN read error: {}", e)))?;

        let parent_file_reference_number = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("Parent FRN read error: {}", e)))?;

        let usn = cursor.read_u64::<LittleEndian>()
            .map_err(|e| Error::Parse(format!("USN read error: {}", e)))?;

        let remaining = record_length.saturating_sub(24);
        let mut _extra = vec![0u8; remaining as usize];
        cursor.read_exact(&mut _extra)
            .map_err(|e| Error::Parse(format!("Extra data read error: {}", e)))?;

        Ok(Some(UsnEntry {
            usn,
            file_reference_number,
            parent_reference_number: parent_file_reference_number,
            file_name: String::new(),
            file_path: String::new(),
            timestamp: NaiveDateTime::default(),
            reason: ReasonCode::empty(),
            file_attributes: 0,
            is_directory: false,
        }))
    }

    fn build_path_map(&mut self) {
        let sorted_entries: Vec<&UsnEntry> = self.entries.iter().collect();

        for entry in &sorted_entries {
            if entry.is_directory && !entry.file_name.is_empty() {
                if entry.parent_reference_number == 0x5000000000005 {
                    self.frn_to_path.insert(entry.file_reference_number, entry.file_name.clone());
                } else if let Some(parent_path) = self.frn_to_path.get(&entry.parent_reference_number).cloned() {
                    let full_path = format!("{}\\{}", parent_path, entry.file_name);
                    self.frn_to_path.insert(entry.file_reference_number, full_path);
                }
            }
        }
    }

    fn resolve_paths(&mut self) {
        for entry in &mut self.entries {
            if let Some(parent_path) = self.frn_to_path.get(&entry.parent_reference_number) {
                entry.file_path = format!("{}\\{}", parent_path, entry.file_name);
            } else {
                entry.file_path = entry.file_name.clone();
            }
        }
    }

    fn decode_utf16le(data: &[u8]) -> String {
        let u16_iter = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
        char::decode_utf16(u16_iter)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect()
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

    fn build_v2_record(
        frn: u64,
        parent_frn: u64,
        usn: u64,
        timestamp: u64,
        reason: u32,
        file_attributes: u32,
        filename: &str,
    ) -> Vec<u8> {
        let name_bytes: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let name_len = name_bytes.len() as u16;
        let record_length: u32 = 60 + name_bytes.len() as u32;

        let mut buf = Vec::new();
        buf.extend_from_slice(&record_length.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&frn.to_le_bytes());
        buf.extend_from_slice(&parent_frn.to_le_bytes());
        buf.extend_from_slice(&usn.to_le_bytes());
        buf.extend_from_slice(&timestamp.to_le_bytes());
        buf.extend_from_slice(&reason.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&file_attributes.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&60u16.to_le_bytes());
        buf.extend_from_slice(&name_bytes);
        buf
    }

    #[test]
    fn test_parse_single_v2_record() {
        let record = build_v2_record(
            100,
            0x5000000000005,
            1,
            132456789012345678,
            ReasonCode::FILE_CREATED.bits(),
            0x20,
            "test.txt",
        );
        let entries = UsnJournalParser::parse_journal(&record).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name, "test.txt");
        assert_eq!(entries[0].file_reference_number, 100);
        assert_eq!(entries[0].usn, 1);
        assert!(entries[0].reason.contains(ReasonCode::FILE_CREATED));
        assert!(!entries[0].is_directory);
    }

    #[test]
    fn test_parse_deleted_file() {
        let mut data = Vec::new();
        data.extend(build_v2_record(
            0x5000000000005,
            0,
            0,
            0,
            0,
            FILE_ATTRIBUTE_DIRECTORY,
            "Documents",
        ));
        data.extend(build_v2_record(
            200,
            0x5000000000005,
            2,
            132456789012345678,
            ReasonCode::FILE_DELETED.bits(),
            0x20,
            "secret.doc",
        ));

        let entries = UsnJournalParser::parse_journal(&data).unwrap();
        let deleted = UsnJournalParser::find_deleted_files(&entries);
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].file_name, "secret.doc");
    }

    #[test]
    fn test_decode_utf16le() {
        let input = b"h\x00i\x00";
        assert_eq!(UsnJournalParser::decode_utf16le(input), "hi");
    }

    #[test]
    fn test_windows_filetime_to_datetime() {
        let filetime: u64 = 132456789012345678;
        let dt = UsnJournalParser::windows_filetime_to_datetime(filetime);
        assert!(dt.is_some());
    }

    #[test]
    fn test_empty_journal() {
        let entries = UsnJournalParser::parse_journal(&[]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_multiple_entries() {
        let mut data = Vec::new();
        for i in 0..5 {
            data.extend(build_v2_record(
                i + 100,
                0x5000000000005,
                i,
                132456789012345678 + i,
                ReasonCode::FILE_CREATED.bits(),
                0x20,
                &format!("file{}.txt", i),
            ));
        }
        let entries = UsnJournalParser::parse_journal(&data).unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_reason_code_flags() {
        let reason = ReasonCode::FILE_CREATED | ReasonCode::FILE_MODIFIED;
        assert!(reason.contains(ReasonCode::FILE_CREATED));
        assert!(reason.contains(ReasonCode::FILE_MODIFIED));
        assert!(!reason.contains(ReasonCode::FILE_DELETED));
    }
}
