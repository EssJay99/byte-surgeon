#![allow(dead_code)]
use crate::common::{FileSystem, SuperblockInfo, DirectoryEntry, FileEntry};
use bytesurgeon_core::{Result, Error, FileMetadata};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use byteorder::ReadBytesExt;
use tracing::{debug, warn};
use chrono::{DateTime, Utc};

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_OBJECT_ID: u32 = 0x40;
const ATTR_SECURITY_DESCRIPTOR: u32 = 0x50;
const ATTR_VOLUME_NAME: u32 = 0x60;
const ATTR_VOLUME_INFORMATION: u32 = 0x70;
const ATTR_DATA: u32 = 0x80;
const ATTR_INDEX_ROOT: u32 = 0x90;
const ATTR_INDEX_ALLOCATION: u32 = 0xA0;
const ATTR_BITMAP: u32 = 0xB0;
const ATTR_REPARSE_POINT: u32 = 0xC0;
const ATTR_END: u32 = 0xFFFF_FFFF;

const MFT_RECORD_IN_USE: u16 = 0x01;
const MFT_RECORD_IS_DIRECTORY: u16 = 0x02;

const NS_POSIX: u8 = 0;
const NS_WIN32: u8 = 1;
const NS_DOS: u8 = 2;
const NS_WIN32_AND_DOS: u8 = 3;

const ROOT_DIR_MFT_REF: u64 = 5;
const MFT_MFT_REF: u64 = 0;
const MFTMIRR_MFT_REF: u64 = 1;
const LOGFILE_MFT_REF: u64 = 2;
const VOLUME_MFT_REF: u64 = 3;

const FILETIME_EPOCH_DIFF: i64 = 11_644_473_600;
const MAX_MFT_SCAN_RECORDS: u64 = 1_000_000;

#[derive(Debug, Clone)]
struct StandardInfo {
    created: u64,
    modified: u64,
    mft_modified: u64,
    accessed: u64,
    dos_permissions: u32,
}

#[derive(Debug, Clone)]
struct FileNameInfo {
    parent_ref: u64,
    created: u64,
    modified: u64,
    mft_modified: u64,
    accessed: u64,
    allocated_size: u64,
    actual_size: u64,
    flags: u32,
    name: String,
    namespace: u8,
}

#[derive(Debug, Clone)]
enum DataAttr {
    Resident(Vec<u8>),
    NonResident {
        runs: Vec<(u64, u64)>,
        actual_size: u64,
        allocated_size: u64,
    },
}

#[derive(Debug)]
struct ParsedMftRecord {
    record_number: u64,
    flags: u16,
    is_in_use: bool,
    is_directory: bool,
    standard_info: Option<StandardInfo>,
    file_names: Vec<FileNameInfo>,
    data_attr: Option<DataAttr>,
    index_root_data: Option<Vec<u8>>,
    index_alloc_attr: Option<DataAttr>,
}

pub struct NTFSParser {
    device_path: String,
    sector_size: u16,
    cluster_size: u32,
    mft_cluster: u64,
    mft_mirror_cluster: u64,
    mft_record_size: u32,
    index_record_size: u32,
    total_sectors: u64,
    volume_serial: u64,
    mft_record_count: u64,
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
        buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
    ])
}

fn filetime_to_datetime(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    let unix_secs = (ft / 10_000_000) as i64 - FILETIME_EPOCH_DIFF;
    if unix_secs < 0 {
        return None;
    }
    DateTime::from_timestamp(unix_secs, 0)
}

fn decode_utf16le(data: &[u8], char_count: usize) -> String {
    let mut chars = Vec::with_capacity(char_count);
    for i in 0..char_count {
        let off = i * 2;
        if off + 1 >= data.len() {
            break;
        }
        let code_unit = u16::from_le_bytes([data[off], data[off + 1]]);
        if let Some(ch) = char::from_u32(code_unit as u32) {
            chars.push(ch);
        } else {
            chars.push('\u{FFFD}');
        }
    }
    chars.into_iter().collect()
}

fn parse_data_runs(data: &[u8], start_offset: usize, end: usize) -> Vec<(u64, u64)> {
    let mut runs = Vec::new();
    let mut pos = start_offset;
    let mut prev_offset: i64 = 0;

    while pos < end {
        let mut cursor = Cursor::new(&data[pos..]);
        let header = match cursor.read_u8() {
            Ok(h) => h,
            Err(_) => break,
        };
        if header == 0 {
            break;
        }

        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;

        if len_bytes == 0 {
            break;
        }

        let mut length: u64 = 0;
        for _ in 0..len_bytes {
            match cursor.read_u8() {
                Ok(b) => { length = (length << 8) | b as u64; }
                Err(_) => { return runs; }
            }
        }

        let mut raw_offset: u64 = 0;
        let mut off_bytes_buf = [0u8; 8];
        for i in 0..off_bytes {
            match cursor.read_u8() {
                Ok(b) => { off_bytes_buf[i] = b; }
                Err(_) => { return runs; }
            }
        }
        for i in (0..off_bytes).rev() {
            raw_offset = (raw_offset << 8) | off_bytes_buf[i] as u64;
        }

        let signed_offset: i64 = if off_bytes > 0 && off_bytes < 8 && (raw_offset >> (off_bytes * 8 - 1)) & 1 == 1 {
            let mask = !((1u64 << (off_bytes * 8)) - 1);
            (raw_offset | mask) as i64
        } else {
            raw_offset as i64
        };

        pos += 1 + len_bytes + off_bytes;

        let abs_offset = prev_offset + signed_offset;
        prev_offset = abs_offset;

        if abs_offset < 0 {
            warn!("Negative absolute offset in data run, skipping");
            continue;
        }

        runs.push((abs_offset as u64, length));
    }

    runs
}

impl NTFSParser {
    pub fn new(device_path: &str) -> Result<Self> {
        let mut parser = Self {
            device_path: device_path.to_string(),
            sector_size: 512,
            cluster_size: 4096,
            mft_cluster: 0,
            mft_mirror_cluster: 0,
            mft_record_size: 1024,
            index_record_size: 4096,
            total_sectors: 0,
            volume_serial: 0,
            mft_record_count: 0,
        };

        parser.read_boot_sector()?;
        parser.compute_mft_record_count();
        Ok(parser)
    }

    fn read_boot_sector(&mut self) -> Result<()> {
        let mut file = File::open(&self.device_path)?;
        let mut boot = [0u8; 512];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut boot)?;

        if &boot[3..11] != b"NTFS    " {
            return Err(Error::InvalidDevice("Not an NTFS volume".to_string()));
        }

        self.sector_size = read_u16(&boot, 11);
        let sectors_per_cluster = boot[13] as u32;
        self.cluster_size = sectors_per_cluster * self.sector_size as u32;

        self.total_sectors = read_u64(&boot, 40);
        self.mft_cluster = read_u64(&boot, 48);
        self.mft_mirror_cluster = read_u64(&boot, 56);

        let raw_mft_rec = boot[64] as i8;
        self.mft_record_size = if raw_mft_rec < 0 {
            1u32 << ((-raw_mft_rec) as u32)
        } else {
            (raw_mft_rec as u32) * self.cluster_size
        };

        let raw_idx = boot[66] as i8;
        self.index_record_size = if raw_idx < 0 {
            1u32 << ((-raw_idx) as u32)
        } else {
            (raw_idx as u32) * self.cluster_size
        };

        if boot.len() >= 80 {
            self.volume_serial = read_u64(&boot, 72);
        }

        debug!(
            "NTFS Boot Sector: sector_size={}, cluster_size={}, mft_cluster={}, \
             mft_record_size={}, index_record_size={}, total_sectors={}",
            self.sector_size, self.cluster_size, self.mft_cluster,
            self.mft_record_size, self.index_record_size, self.total_sectors
        );

        Ok(())
    }

    fn compute_mft_record_count(&mut self) {
        match self.read_raw_mft_record(MFT_MFT_REF) {
            Ok(raw) => {
                match self.parse_mft_record_raw(MFT_MFT_REF, &raw) {
                    Ok(record) => {
                        let mft_total_size = match &record.data_attr {
                            Some(DataAttr::NonResident { actual_size, .. }) => *actual_size,
                            Some(DataAttr::Resident(data)) => data.len() as u64,
                            _ => 0,
                        };
                        if mft_total_size > 0 && self.mft_record_size > 0 {
                            self.mft_record_count = mft_total_size / self.mft_record_size as u64;
                            debug!("MFT contains {} records", self.mft_record_count);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse $MFT record: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read $MFT record: {}", e);
            }
        }

        if self.mft_record_count == 0 {
            let mft_byte_start = self.mft_cluster * self.cluster_size as u64;
            let volume_bytes = self.total_sectors * self.sector_size as u64;
            if volume_bytes > mft_byte_start && self.mft_record_size > 0 {
                let estimated = (volume_bytes - mft_byte_start) / self.mft_record_size as u64;
                self.mft_record_count = estimated.min(MAX_MFT_SCAN_RECORDS);
            } else {
                self.mft_record_count = 1024;
            }
            debug!("Estimated MFT record count: {}", self.mft_record_count);
        }
    }

    fn apply_fixup(record: &mut [u8], sector_size: usize) -> Result<()> {
        if record.len() < 6 {
            return Err(Error::RecoveryFailed("MFT record too small".to_string()));
        }

        let us_offset = read_u16(record, 4) as usize;
        let us_size = read_u16(record, 6) as usize;

        if us_size < 2 || us_offset + us_size * 2 > record.len() {
            return Err(Error::RecoveryFailed("Invalid update sequence".to_string()));
        }

        let usn = read_u16(record, us_offset);

        let sector_count = record.len() / sector_size;
        let fixup_count = us_size - 1;

        if fixup_count > sector_count {
            return Err(Error::RecoveryFailed(
                format!("Update sequence count {} exceeds sector count {}", fixup_count, sector_count),
            ));
        }

        for i in 0..fixup_count {
            let sector_end = (i + 1) * sector_size;
            let fixup_value = read_u16(record, us_offset + 2 + i * 2);

            let tail_offset = sector_end - 2;
            let current_usn = read_u16(record, tail_offset);

            if current_usn != usn {
                warn!(
                    "Update sequence mismatch at sector {}: expected 0x{:04X}, got 0x{:04X}",
                    i, usn, current_usn
                );
            }

            record[tail_offset] = fixup_value as u8;
            record[tail_offset + 1] = (fixup_value >> 8) as u8;
        }

        Ok(())
    }

    fn read_raw_mft_record(&self, record_number: u64) -> Result<Vec<u8>> {
        let mft_byte_start = self.mft_cluster * self.cluster_size as u64;
        let offset = mft_byte_start + record_number * self.mft_record_size as u64;

        let mut file = File::open(&self.device_path)?;
        let mut buf = vec![0u8; self.mft_record_size as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        if &buf[0..4] != b"FILE" {
            return Err(Error::RecoveryFailed(
                format!("Invalid MFT record signature at record {}", record_number),
            ));
        }

        Self::apply_fixup(&mut buf, self.sector_size as usize)?;
        Ok(buf)
    }

    fn read_raw_mft_record_mirr(&self, record_number: u64) -> Result<Vec<u8>> {
        let mirr_byte_start = self.mft_mirror_cluster * self.cluster_size as u64;
        let offset = mirr_byte_start + record_number * self.mft_record_size as u64;

        let mut file = File::open(&self.device_path)?;
        let mut buf = vec![0u8; self.mft_record_size as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;

        if &buf[0..4] != b"FILE" {
            return Err(Error::RecoveryFailed("Invalid MFTMirr record".to_string()));
        }

        Self::apply_fixup(&mut buf, self.sector_size as usize)?;
        Ok(buf)
    }

    fn read_mft_record_with_fallback(&self, record_number: u64) -> Result<Vec<u8>> {
        match self.read_raw_mft_record(record_number) {
            Ok(buf) => Ok(buf),
            Err(e) => {
                if record_number <= 3 {
                    debug!("MFT record {} failed, trying MFTMirr: {}", record_number, e);
                    self.read_raw_mft_record_mirr(record_number)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn parse_mft_record_raw(&self, record_number: u64, raw: &[u8]) -> Result<ParsedMftRecord> {
        let flags = read_u16(raw, 22);
        let is_in_use = flags & MFT_RECORD_IN_USE != 0;
        let is_directory = flags & MFT_RECORD_IS_DIRECTORY != 0;

        let first_attr_offset = read_u16(raw, 20) as usize;

        let mut standard_info = None;
        let mut file_names = Vec::new();
        let mut data_attr = None;
        let mut index_root_data = None;
        let mut index_alloc_attr = None;

        let mut offset = first_attr_offset;

        while offset + 4 <= raw.len() {
            let attr_type = read_u32(raw, offset);
            if attr_type == ATTR_END || attr_type == 0 {
                break;
            }

            let attr_len = read_u32(raw, offset + 4) as usize;
            if attr_len < 16 || offset + attr_len > raw.len() {
                break;
            }

            let non_resident = raw[offset + 8];
            let name_len = raw[offset + 9] as usize;
            let _name_offset = read_u16(raw, offset + 10) as usize;

            match attr_type {
                ATTR_STANDARD_INFORMATION => {
                    standard_info = self.parse_standard_info_attr(raw, offset, non_resident);
                }
                ATTR_FILE_NAME => {
                    if let Some(fn_info) = self.parse_file_name_attr(raw, offset, non_resident, name_len) {
                        file_names.push(fn_info);
                    }
                }
                ATTR_DATA => {
                    data_attr = self.parse_data_attr(raw, offset, non_resident, attr_len);
                }
                ATTR_INDEX_ROOT => {
                    index_root_data = self.parse_resident_attr_data(raw, offset, non_resident, attr_len);
                }
                ATTR_INDEX_ALLOCATION => {
                    index_alloc_attr = self.parse_data_attr(raw, offset, non_resident, attr_len);
                }
                _ => {}
            }

            offset += attr_len;
        }

        Ok(ParsedMftRecord {
            record_number,
            flags,
            is_in_use,
            is_directory,
            standard_info,
            file_names,
            data_attr,
            index_root_data,
            index_alloc_attr,
        })
    }

    fn parse_standard_info_attr(&self, raw: &[u8], offset: usize, non_resident: u8) -> Option<StandardInfo> {
        let data = if non_resident == 0 {
            self.get_resident_value(raw, offset)?
        } else {
            return None;
        };

        if data.len() < 36 {
            return None;
        }

        Some(StandardInfo {
            created: read_u64(&data, 0),
            modified: read_u64(&data, 8),
            mft_modified: read_u64(&data, 16),
            accessed: read_u64(&data, 24),
            dos_permissions: read_u32(&data, 32),
        })
    }

    fn parse_file_name_attr(&self, raw: &[u8], offset: usize, non_resident: u8, _name_len: usize) -> Option<FileNameInfo> {
        let data = if non_resident == 0 {
            self.get_resident_value(raw, offset)?
        } else {
            return None;
        };

        if data.len() < 68 {
            return None;
        }

        let parent_ref = read_u64(&data, 0) & 0x0000_FFFF_FFFF_FFFF;
        let created = read_u64(&data, 8);
        let modified = read_u64(&data, 16);
        let mft_modified = read_u64(&data, 24);
        let accessed = read_u64(&data, 32);
        let allocated_size = read_u64(&data, 40);
        let actual_size = read_u64(&data, 48);
        let flags = read_u32(&data, 56);
        let fn_len = data[64] as usize;
        let fn_ns = data[65];

        if 66 + fn_len * 2 > data.len() {
            return None;
        }

        let name = decode_utf16le(&data[66..], fn_len);

        Some(FileNameInfo {
            parent_ref,
            created,
            modified,
            mft_modified,
            accessed,
            allocated_size,
            actual_size,
            flags,
            name,
            namespace: fn_ns,
        })
    }

    fn parse_data_attr(&self, raw: &[u8], offset: usize, non_resident: u8, attr_len: usize) -> Option<DataAttr> {
        if non_resident == 0 {
            let data = self.get_resident_value(raw, offset)?;
            Some(DataAttr::Resident(data))
        } else {
            if offset + 64 > raw.len() {
                return None;
            }

            let data_runs_offset = read_u16(raw, offset + 32) as usize;
            let allocated_size = read_u64(raw, offset + 40);
            let actual_size = read_u64(raw, offset + 48);

            let runs_end = offset + attr_len;
            let runs_start = offset + data_runs_offset;

            if runs_start >= raw.len() || runs_start > runs_end {
                return None;
            }

            let runs = parse_data_runs(raw, runs_start, runs_end.min(raw.len()));

            Some(DataAttr::NonResident {
                runs,
                actual_size,
                allocated_size,
            })
        }
    }

    fn parse_resident_attr_data(&self, raw: &[u8], offset: usize, non_resident: u8, _attr_len: usize) -> Option<Vec<u8>> {
        if non_resident != 0 {
            return None;
        }
        self.get_resident_value(raw, offset)
    }

    fn get_resident_value(&self, raw: &[u8], attr_offset: usize) -> Option<Vec<u8>> {
        if attr_offset + 22 > raw.len() {
            return None;
        }

        let value_len = read_u32(raw, attr_offset + 16) as usize;
        let value_offset = read_u16(raw, attr_offset + 20) as usize;
        let start = attr_offset + value_offset;
        let end = start + value_len;

        if end > raw.len() {
            return None;
        }

        Some(raw[start..end].to_vec())
    }

    fn read_data_from_runs(&self, runs: &[(u64, u64)], actual_size: u64) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(actual_size as usize);
        let mut device = File::open(&self.device_path)?;

        for (cluster_offset, cluster_count) in runs {
            let byte_offset = cluster_offset * self.cluster_size as u64;
            let byte_count = (*cluster_count as usize) * (self.cluster_size as usize);

            let mut buf = vec![0u8; byte_count];
            device.seek(SeekFrom::Start(byte_offset))?;
            device.read_exact(&mut buf)?;
            data.extend_from_slice(&buf);
        }

        data.truncate(actual_size as usize);
        Ok(data)
    }

    fn read_file_data(&self, data_attr: &DataAttr) -> Result<Vec<u8>> {
        match data_attr {
            DataAttr::Resident(data) => Ok(data.clone()),
            DataAttr::NonResident { runs, actual_size, .. } => {
                self.read_data_from_runs(runs, *actual_size)
            }
        }
    }

    fn best_filename(record: &ParsedMftRecord) -> Option<String> {
        if record.file_names.is_empty() {
            return None;
        }

        for fn_info in &record.file_names {
            if fn_info.namespace == NS_WIN32 {
                return Some(fn_info.name.clone());
            }
        }

        for fn_info in &record.file_names {
            if fn_info.namespace == NS_POSIX {
                return Some(fn_info.name.clone());
            }
        }

        for fn_info in &record.file_names {
            if fn_info.namespace == NS_WIN32_AND_DOS {
                return Some(fn_info.name.clone());
            }
        }

        Some(record.file_names[0].name.clone())
    }

    fn build_metadata(record: &ParsedMftRecord) -> Option<FileMetadata> {
        let si = record.standard_info.as_ref();
        let fn_info = record.file_names.first();

        let created = si
            .and_then(|s| filetime_to_datetime(s.created))
            .or_else(|| fn_info.and_then(|f| filetime_to_datetime(f.created)));

        let modified = si
            .and_then(|s| filetime_to_datetime(s.modified))
            .or_else(|| fn_info.and_then(|f| filetime_to_datetime(f.modified)));

        let accessed = si
            .and_then(|s| filetime_to_datetime(s.accessed))
            .or_else(|| fn_info.and_then(|f| filetime_to_datetime(f.accessed)));

        let permissions = si.map(|s| s.dos_permissions);

        let mut attributes = Vec::new();
        if record.is_directory {
            attributes.push("directory".to_string());
        }
        if !record.is_in_use {
            attributes.push("deleted".to_string());
        }
        if let Some(si) = si {
            if si.dos_permissions & 0x01 != 0 {
                attributes.push("readonly".to_string());
            }
            if si.dos_permissions & 0x02 != 0 {
                attributes.push("hidden".to_string());
            }
            if si.dos_permissions & 0x04 != 0 {
                attributes.push("system".to_string());
            }
            if si.dos_permissions & 0x20 != 0 {
                attributes.push("archive".to_string());
            }
        }

        Some(FileMetadata {
            created,
            modified,
            accessed,
            permissions,
            owner: None,
            attributes,
        })
    }

    fn parse_index_entries_from_root(&self, index_data: &[u8]) -> Vec<DirectoryEntry> {
        let mut entries = Vec::new();

        if index_data.len() < 32 {
            return entries;
        }

        let entries_offset = read_u32(index_data, 16) as usize;
        let entries_size = read_u32(index_data, 20) as usize;
        let _flags = index_data.get(28).copied().unwrap_or(0);

        let entry_start = 16 + entries_offset;
        let entry_end = (entry_start + entries_size).min(index_data.len());

        self.parse_index_entry_list(index_data, entry_start, entry_end, &mut entries);

        entries
    }

    fn parse_index_allocation_data(&self, data: &[u8]) -> Vec<DirectoryEntry> {
        let mut entries = Vec::new();
        let idx_rec_size = self.index_record_size as usize;

        if idx_rec_size == 0 {
            return entries;
        }

        let num_records = data.len() / idx_rec_size;

        for i in 0..num_records {
            let record_start = i * idx_rec_size;
            let record_data = &data[record_start..record_start + idx_rec_size];

            if record_data.len() < 4 || &record_data[0..4] != b"INDX" {
                continue;
            }

            if record_data.len() < 28 {
                continue;
            }

            let us_offset = read_u16(record_data, 4) as usize;
            let us_size = read_u16(record_data, 6) as usize;

            let mut fixed = record_data.to_vec();
            if us_size >= 2 && us_offset + us_size * 2 <= fixed.len() {
                let _usn = read_u16(&fixed, us_offset);
                let fixup_count = us_size - 1;
                let sector_size = self.sector_size as usize;

                for j in 0..fixup_count {
                    let sector_end = (j + 1) * sector_size;
                    if sector_end <= fixed.len() {
                        let fixup_value = read_u16(&fixed, us_offset + 2 + j * 2);
                        fixed[sector_end - 2] = fixup_value as u8;
                        fixed[sector_end - 1] = (fixup_value >> 8) as u8;
                    }
                }
            }

            if fixed.len() < 32 {
                continue;
            }

            let idx_entries_offset = read_u32(&fixed, 24) as usize;
            let idx_entries_size = read_u32(&fixed, 28) as usize;

            let entry_start = 24 + idx_entries_offset;
            let entry_end = (entry_start + idx_entries_size).min(fixed.len());

            self.parse_index_entry_list(&fixed, entry_start, entry_end, &mut entries);
        }

        entries
    }

    fn parse_index_entry_list(&self, data: &[u8], start: usize, end: usize, entries: &mut Vec<DirectoryEntry>) {
        let mut pos = start;

        while pos + 16 <= end {
            let entry_len = read_u16(data, pos + 8) as usize;
            if entry_len == 0 || entry_len < 16 {
                break;
            }

            let stream_len = read_u16(data, pos + 10) as usize;
            let entry_flags = read_u16(data, pos + 12);

            let is_last = entry_flags & 0x02 != 0;
            if is_last {
                break;
            }

            let file_ref = read_u64(data, pos) & 0x0000_FFFF_FFFF_FFFF;

            let fn_data_start = pos + 16;
            if stream_len >= 68 && fn_data_start + 68 <= end {
                let fn_data = &data[fn_data_start..];
                if fn_data.len() >= 68 {
                    let fn_len = fn_data[64] as usize;
                    let _fn_ns = fn_data[65];
                    let fn_actual_size = read_u64(fn_data, 48);
                    let fn_flags = read_u32(fn_data, 56);

                    if 66 + fn_len * 2 <= fn_data.len() {
                        let name = decode_utf16le(&fn_data[66..], fn_len);
                        let is_dir = fn_flags & 0x10000000 != 0;

                        let metadata = FileMetadata {
                            created: filetime_to_datetime(read_u64(fn_data, 8)),
                            modified: filetime_to_datetime(read_u64(fn_data, 16)),
                            accessed: filetime_to_datetime(read_u64(fn_data, 32)),
                            permissions: None,
                            owner: None,
                            attributes: if is_dir { vec!["directory".to_string()] } else { vec![] },
                        };

                        entries.push(DirectoryEntry {
                            name,
                            inode: file_ref,
                            is_directory: is_dir,
                            size: fn_actual_size,
                            metadata: Some(metadata),
                        });
                    }
                }
            }

            pos += entry_len;
        }
    }

    fn read_volume_name(&self) -> Option<String> {
        let raw = self.read_mft_record_with_fallback(VOLUME_MFT_REF).ok()?;
        let _record = self.parse_mft_record_raw(VOLUME_MFT_REF, &raw).ok()?;

        let mut file = File::open(&self.device_path).ok()?;
        let mft_byte_start = self.mft_cluster * self.cluster_size as u64;
        let offset = mft_byte_start + VOLUME_MFT_REF * self.mft_record_size as u64;
        let mut buf = vec![0u8; self.mft_record_size as usize];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut buf).ok()?;
        Self::apply_fixup(&mut buf, self.sector_size as usize).ok()?;

        let first_attr_offset = read_u16(&buf, 20) as usize;
        let mut pos = first_attr_offset;

        while pos + 4 <= buf.len() {
            let attr_type = read_u32(&buf, pos);
            if attr_type == ATTR_END || attr_type == 0 {
                break;
            }

            let attr_len = read_u32(&buf, pos + 4) as usize;
            if attr_len < 16 || pos + attr_len > buf.len() {
                break;
            }

            if attr_type == ATTR_VOLUME_NAME && buf[pos + 8] == 0 {
                let value_len = read_u32(&buf, pos + 16) as usize;
                let value_offset = read_u16(&buf, pos + 20) as usize;
                let value_start = pos + value_offset;
                let value_end = value_start + value_len;

                if value_end <= buf.len() && value_len > 0 {
                    return Some(decode_utf16le(&buf[value_start..value_end], value_len / 2));
                }
            }

            pos += attr_len;
        }

        None
    }

    fn collect_directory_entries(&self, record: &ParsedMftRecord) -> Result<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();

        if let Some(ref index_data) = record.index_root_data {
            let root_entries = self.parse_index_entries_from_root(index_data);
            entries.extend(root_entries);
        }

        if let Some(ref idx_alloc) = record.index_alloc_attr {
            match idx_alloc {
                DataAttr::Resident(data) => {
                    let alloc_entries = self.parse_index_allocation_data(data);
                    entries.extend(alloc_entries);
                }
                DataAttr::NonResident { runs, actual_size, .. } => {
                    match self.read_data_from_runs(runs, *actual_size) {
                        Ok(data) => {
                            let alloc_entries = self.parse_index_allocation_data(&data);
                            entries.extend(alloc_entries);
                        }
                        Err(e) => {
                            warn!("Failed to read INDEX_ALLOCATION data: {}", e);
                        }
                    }
                }
            }
        }

        Ok(entries)
    }
}

impl FileSystem for NTFSParser {
    fn read_superblock(&self) -> Result<SuperblockInfo> {
        let file = File::open(&self.device_path)?;
        let total_size = file.metadata()?.len();

        let volume_name = self.read_volume_name();

        let block_size = self.cluster_size as u64;
        let total_blocks = if block_size > 0 {
            total_size / block_size
        } else {
            0
        };

        debug!(
            "NTFS superblock: volume_name={:?}, total_size={}, block_size={}",
            volume_name, total_size, block_size
        );

        Ok(SuperblockInfo {
            volume_name,
            total_size,
            free_space: 0,
            block_size,
            total_blocks,
            free_blocks: 0,
            file_system_type: "NTFS".to_string(),
            created_at: None,
        })
    }

    fn list_root_directory(&self) -> Result<Vec<DirectoryEntry>> {
        self.list_directory(ROOT_DIR_MFT_REF)
    }

    fn list_directory(&self, inode: u64) -> Result<Vec<DirectoryEntry>> {
        let raw = self.read_mft_record_with_fallback(inode)?;
        let record = self.parse_mft_record_raw(inode, &raw)?;

        if !record.is_in_use {
            return Err(Error::RecoveryFailed(
                format!("MFT record {} is not in use", inode),
            ));
        }

        if !record.is_directory {
            return Err(Error::RecoveryFailed(
                format!("MFT record {} is not a directory", inode),
            ));
        }

        self.collect_directory_entries(&record)
    }

    fn read_file(&self, inode: u64) -> Result<Vec<u8>> {
        let raw = self.read_mft_record_with_fallback(inode)?;
        let record = self.parse_mft_record_raw(inode, &raw)?;

        match record.data_attr {
            Some(ref data) => self.read_file_data(data),
            None => {
                if record.is_directory {
                    Err(Error::RecoveryFailed("Cannot read directory as file".to_string()))
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    fn find_deleted_files(&self) -> Result<Vec<FileEntry>> {
        let mut deleted = Vec::new();
        let record_count = self.mft_record_count.min(MAX_MFT_SCAN_RECORDS);

        debug!("Scanning {} MFT records for deleted files", record_count);

        for i in 0..record_count {
            let raw = match self.read_raw_mft_record(i) {
                Ok(buf) => buf,
                Err(_) => continue,
            };

            if &raw[0..4] != b"FILE" {
                continue;
            }

            let flags = read_u16(&raw, 22);
            let is_in_use = flags & MFT_RECORD_IN_USE != 0;

            if is_in_use {
                continue;
            }

            let record = match self.parse_mft_record_raw(i, &raw) {
                Ok(r) => r,
                Err(_) => continue,
            };

            if record.file_names.is_empty() {
                continue;
            }

            let name = Self::best_filename(&record);
            let metadata = Self::build_metadata(&record);

            let size = record.file_names.first().map(|f| f.actual_size).unwrap_or(0);

            let data_offset = match &record.data_attr {
                Some(DataAttr::NonResident { runs, .. }) if !runs.is_empty() => {
                    runs[0].0 * self.cluster_size as u64
                }
                _ => 0,
            };

            debug!("Found deleted file: {:?} (MFT record {})", name, i);

            deleted.push(FileEntry {
                inode: i,
                name,
                size,
                data_offset,
                is_deleted: true,
                metadata,
            });
        }

        debug!("Found {} deleted files", deleted.len());
        Ok(deleted)
    }

    fn get_file_metadata(&self, inode: u64) -> Result<FileMetadata> {
        let raw = self.read_mft_record_with_fallback(inode)?;
        let record = self.parse_mft_record_raw(inode, &raw)?;

        Self::build_metadata(&record).ok_or_else(|| {
            Error::RecoveryFailed("No metadata available for record".to_string())
        })
    }
}
