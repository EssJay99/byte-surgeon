#![allow(dead_code)]
use crate::common::{FileSystem, SuperblockInfo, DirectoryEntry, FileEntry};
use datadoctor_core::{Result, Error, FileMetadata};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{LittleEndian, ReadBytesExt};
use tracing::{debug, warn};
use chrono::{DateTime, Utc, TimeZone};

const FAT32_EOC: u32 = 0x0FFFFFF8;
const FAT32_BAD_CLUSTER: u32 = 0x0FFFFFF7;
const DIR_ENTRY_SIZE: usize = 32;
const LFN_ATTR: u8 = 0x0F;
const ATTR_DIRECTORY: u8 = 0x10;
const DELETED_MARKER: u8 = 0xE5;
const END_OF_DIR: u8 = 0x00;
const MAX_FAT_CHAIN: usize = 1_000_000;

pub struct FAT32Parser {
    device_path: String,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fat_count: u8,
    total_sectors: u32,
    sectors_per_fat: u32,
    root_cluster: u32,
    data_start: u64,
    fat_start: u64,
    cluster_size: u64,
    volume_label: String,
    fsinfo_sector: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DirEntryRaw {
    name: String,
    is_directory: bool,
    size: u32,
    start_cluster: u32,
    create_time: Option<DateTime<Utc>>,
    modify_time: Option<DateTime<Utc>>,
    access_time: Option<DateTime<Utc>>,
    attributes: u8,
    is_deleted: bool,
    lfn_entries: Vec<[u8; 13]>,
}

impl FAT32Parser {
    pub fn new(device_path: &str) -> Result<Self> {
        let mut parser = Self {
            device_path: device_path.to_string(),
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            reserved_sectors: 32,
            fat_count: 2,
            total_sectors: 0,
            sectors_per_fat: 0,
            root_cluster: 2,
            data_start: 0,
            fat_start: 0,
            cluster_size: 0,
            volume_label: String::new(),
            fsinfo_sector: 1,
        };

        parser.read_boot_sector()?;
        Ok(parser)
    }

    fn read_boot_sector(&mut self) -> Result<()> {
        let mut file = File::open(&self.device_path)?;
        let mut buffer = [0u8; 512];

        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut buffer)?;

        let boot_sig = u16::from_le_bytes([buffer[510], buffer[511]]);
        if boot_sig != 0xAA55 {
            warn!("FAT32 boot sector signature mismatch: 0x{:04X}", boot_sig);
        }

        self.bytes_per_sector = u16::from_le_bytes([buffer[11], buffer[12]]);
        self.sectors_per_cluster = buffer[13];
        self.reserved_sectors = u16::from_le_bytes([buffer[14], buffer[15]]);
        self.fat_count = buffer[16];

        let total_sectors_16 = u16::from_le_bytes([buffer[19], buffer[20]]);
        let total_sectors_32 = u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]);
        self.total_sectors = if total_sectors_16 != 0 {
            total_sectors_16 as u32
        } else {
            total_sectors_32
        };

        self.sectors_per_fat = u32::from_le_bytes([buffer[36], buffer[37], buffer[38], buffer[39]]);
        self.root_cluster = u32::from_le_bytes([buffer[44], buffer[45], buffer[46], buffer[47]]);
        self.fsinfo_sector = u16::from_le_bytes([buffer[48], buffer[49]]);

        self.fat_start = self.reserved_sectors as u64 * self.bytes_per_sector as u64;
        let fat_size_bytes = self.sectors_per_fat as u64 * self.bytes_per_sector as u64;
        self.data_start = self.fat_start + (fat_size_bytes * self.fat_count as u64);
        self.cluster_size = self.sectors_per_cluster as u64 * self.bytes_per_sector as u64;

        let mut label_bytes = [0u8; 11];
        label_bytes.copy_from_slice(&buffer[71..82]);
        self.volume_label = String::from_utf8_lossy(&label_bytes)
            .trim_end()
            .trim_end_matches('\0')
            .to_string();

        debug!(
            "FAT32 Boot Sector - Bytes/sector: {}, Sectors/cluster: {}, Root cluster: {}, Volume: '{}'",
            self.bytes_per_sector, self.sectors_per_cluster, self.root_cluster, self.volume_label
        );

        if self.bytes_per_sector == 0 || self.sectors_per_cluster == 0 {
            return Err(Error::InvalidDevice("Invalid FAT32 boot sector parameters".to_string()));
        }

        Ok(())
    }

    fn read_fsinfo_free_clusters(&self) -> Option<u32> {
        if self.fsinfo_sector == 0 || self.fsinfo_sector == 0xFFFF {
            return None;
        }
        let mut file = File::open(&self.device_path).ok()?;
        let offset = self.fsinfo_sector as u64 * self.bytes_per_sector as u64;
        let mut buffer = [0u8; 512];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut buffer).ok()?;

        let sig1 = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        if sig1 != 0x41615252 {
            return None;
        }
        let sig2 = u32::from_le_bytes([buffer[484], buffer[485], buffer[486], buffer[487]]);
        if sig2 != 0x61417272 {
            return None;
        }
        let free_count = u32::from_le_bytes([buffer[488], buffer[489], buffer[490], buffer[491]]);
        if free_count == 0xFFFFFFFF {
            None
        } else {
            Some(free_count)
        }
    }

    fn cluster_to_offset(&self, cluster: u32) -> u64 {
        self.data_start + ((cluster as u64 - 2) * self.cluster_size)
    }

    fn read_fat_entry(&self, cluster: u32) -> Result<u32> {
        let mut file = File::open(&self.device_path)?;
        let fat_offset = self.fat_start + (cluster as u64 * 4);
        file.seek(SeekFrom::Start(fat_offset))?;
        let value = file.read_u32::<LittleEndian>()?;
        Ok(value & 0x0FFFFFFF)
    }

    fn read_cluster_chain(&self, start_cluster: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut current = start_cluster;

        loop {
            if current < 2 || current >= FAT32_EOC {
                break;
            }
            if chain.len() >= MAX_FAT_CHAIN {
                warn!("FAT chain exceeds maximum length, truncating");
                break;
            }
            chain.push(current);
            let next = self.read_fat_entry(current)?;
            if next >= FAT32_EOC || next == FAT32_BAD_CLUSTER {
                break;
            }
            current = next;
        }

        Ok(chain)
    }

    fn read_cluster_data(&self, cluster: u32) -> Result<Vec<u8>> {
        let mut file = File::open(&self.device_path)?;
        let offset = self.cluster_to_offset(cluster);
        let mut buffer = vec![0u8; self.cluster_size as usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn read_chain_data(&self, start_cluster: u32, file_size: u32) -> Result<Vec<u8>> {
        let chain = self.read_cluster_chain(start_cluster)?;
        let mut result = Vec::with_capacity(file_size as usize);
        let mut remaining = file_size as usize;

        for &cluster in &chain {
            if remaining == 0 {
                break;
            }
            let data = self.read_cluster_data(cluster)?;
            let to_read = remaining.min(data.len());
            result.extend_from_slice(&data[..to_read]);
            remaining = remaining.saturating_sub(to_read);
        }

        Ok(result)
    }

    fn decode_fat_datetime(date: u16, time: u16, tenths: u8) -> Option<DateTime<Utc>> {
        let second = ((time & 0x1F) as u32) * 2 + (tenths as u32 / 100);
        let minute = ((time >> 5) & 0x3F) as u32;
        let hour = ((time >> 11) & 0x1F) as u32;
        let day = (date & 0x1F) as u32;
        let month = ((date >> 5) & 0x0F) as u32;
        let year = ((date >> 9) & 0x7F) as u32 + 1980;

        if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
            return None;
        }

        Utc.with_ymd_and_hms(year as i32, month, day, hour, minute, second).single()
    }

    fn parse_lfn_from_entries(lfn_entries: &[[u8; 13]]) -> String {
        let mut chars: Vec<u16> = Vec::new();
        let mut sorted = lfn_entries.to_vec();
        sorted.sort_by_key(|e| e[0] & 0x3F);

        for entry in &sorted {
            for i in (1..12).step_by(2) {
                let c = u16::from_le_bytes([entry[i], entry[i + 1]]);
                if c == 0x0000 || c == 0xFFFF {
                    break;
                }
                chars.push(c);
            }
        }

        String::from_utf16_lossy(&chars)
    }

    fn parse_directory_entries_at(&self, start_cluster: u32) -> Result<Vec<DirectoryEntry>> {
        let chain = self.read_cluster_chain(start_cluster)?;
        let mut entries = Vec::new();
        let mut pending_lfn: Vec<[u8; 13]> = Vec::new();
        let mut pending_lfn_checksum: Option<u8> = None;

        for &cluster in &chain {
            let data = self.read_cluster_data(cluster)?;

            for i in (0..data.len()).step_by(DIR_ENTRY_SIZE) {
                if i + DIR_ENTRY_SIZE > data.len() {
                    break;
                }
                let entry = &data[i..i + DIR_ENTRY_SIZE];

                if entry[0] == END_OF_DIR {
                    return Ok(entries);
                }

                if entry[0] == DELETED_MARKER {
                    if entry[11] == LFN_ATTR {
                        let mut lfn_part = [0u8; 13];
                        lfn_part.copy_from_slice(&entry[1..14]);
                        pending_lfn.push(lfn_part);
                    } else {
                        pending_lfn.clear();
                        pending_lfn_checksum = None;
                    }
                    continue;
                }

                if entry[11] == LFN_ATTR {
                    let ord = entry[0];
                    let checksum = entry[13];
                    if ord & 0x40 != 0 {
                        pending_lfn.clear();
                        pending_lfn_checksum = Some(checksum);
                    }
                    let mut lfn_part = [0u8; 13];
                    lfn_part.copy_from_slice(&entry[1..14]);
                    pending_lfn.push(lfn_part);
                    continue;
                }

                let short_name = self.decode_83_name(&entry[0..11]);
                let entry_checksum = self.compute_lfn_checksum(&entry[0..11]);

                let name = if pending_lfn_checksum == Some(entry_checksum) && !pending_lfn.is_empty() {
                    let lfn = Self::parse_lfn_from_entries(&pending_lfn);
                    if !lfn.is_empty() { lfn } else { short_name.clone() }
                } else {
                    short_name.clone()
                };

                pending_lfn.clear();
                pending_lfn_checksum = None;

                let is_dir = (entry[11] & ATTR_DIRECTORY) != 0;
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                let start_cluster_lo = u16::from_le_bytes([entry[26], entry[27]]);
                let start_cluster_hi = u16::from_le_bytes([entry[20], entry[21]]);
                let file_start_cluster = ((start_cluster_hi as u32) << 16) | (start_cluster_lo as u32);

                let create_date = u16::from_le_bytes([entry[16], entry[17]]);
                let create_time = u16::from_le_bytes([entry[14], entry[15]]);
                let create_tenths = entry[13];
                let mod_date = u16::from_le_bytes([entry[24], entry[25]]);
                let mod_time = u16::from_le_bytes([entry[22], entry[23]]);
                let acc_date = u16::from_le_bytes([entry[18], entry[19]]);

                let created = Self::decode_fat_datetime(create_date, create_time, create_tenths);
                let modified = Self::decode_fat_datetime(mod_date, mod_time, 0);
                let accessed = Self::decode_fat_datetime(acc_date, 0, 0);

                let metadata = FileMetadata {
                    created,
                    modified,
                    accessed,
                    permissions: None,
                    owner: None,
                    attributes: Self::fat_attributes(entry[11]),
                };

                entries.push(DirectoryEntry {
                    name,
                    inode: file_start_cluster as u64,
                    is_directory: is_dir,
                    size: size as u64,
                    metadata: Some(metadata),
                });
            }
        }

        Ok(entries)
    }

    fn decode_83_name(&self, raw: &[u8]) -> String {
        let mut name = String::new();
        for &b in &raw[0..8] {
            if b == 0x20 || b == 0x00 {
                break;
            }
            name.push(b as char);
        }

        let mut ext = String::new();
        for &b in &raw[8..11] {
            if b == 0x20 || b == 0x00 {
                break;
            }
            ext.push(b as char);
        }

        if !ext.is_empty() {
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&ext);
        }

        name
    }

    fn compute_lfn_checksum(&self, short_name: &[u8]) -> u8 {
        let mut sum: u8 = 0;
        for &b in short_name {
            sum = sum.rotate_right(1).wrapping_add(b);
        }
        sum
    }

    fn fat_attributes(attr_byte: u8) -> Vec<String> {
        let mut attrs = Vec::new();
        if attr_byte & 0x01 != 0 { attrs.push("read_only".to_string()); }
        if attr_byte & 0x02 != 0 { attrs.push("hidden".to_string()); }
        if attr_byte & 0x04 != 0 { attrs.push("system".to_string()); }
        if attr_byte & 0x08 != 0 { attrs.push("volume_label".to_string()); }
        if attr_byte & 0x10 != 0 { attrs.push("directory".to_string()); }
        if attr_byte & 0x20 != 0 { attrs.push("archive".to_string()); }
        attrs
    }

    fn scan_for_deleted_entries(&self) -> Result<Vec<FileEntry>> {
        let mut deleted = Vec::new();
        let chain = self.read_cluster_chain(self.root_cluster)?;
        self.scan_clusters_for_deleted(&chain, &mut deleted)?;
        Ok(deleted)
    }

    fn scan_clusters_for_deleted(&self, clusters: &[u32], deleted: &mut Vec<FileEntry>) -> Result<()> {
        for &cluster in clusters {
            let data = self.read_cluster_data(cluster)?;

            for i in (0..data.len()).step_by(DIR_ENTRY_SIZE) {
                if i + DIR_ENTRY_SIZE > data.len() {
                    break;
                }
                let entry = &data[i..i + DIR_ENTRY_SIZE];

                if entry[0] == END_OF_DIR {
                    break;
                }

                if entry[0] != DELETED_MARKER {
                    continue;
                }

                if entry[11] == LFN_ATTR || entry[11] == 0x00 {
                    continue;
                }

                let short_name = self.decode_83_name(&entry[0..11]);
                let is_dir = (entry[11] & ATTR_DIRECTORY) != 0;
                let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);
                let start_cluster_lo = u16::from_le_bytes([entry[26], entry[27]]);
                let start_cluster_hi = u16::from_le_bytes([entry[20], entry[21]]);
                let file_start_cluster = ((start_cluster_hi as u32) << 16) | (start_cluster_lo as u32);

                let mod_date = u16::from_le_bytes([entry[24], entry[25]]);
                let mod_time = u16::from_le_bytes([entry[22], entry[23]]);
                let modified = Self::decode_fat_datetime(mod_date, mod_time, 0);

                let metadata = FileMetadata {
                    created: None,
                    modified,
                    accessed: None,
                    permissions: None,
                    owner: None,
                    attributes: vec!["deleted".to_string()],
                };

                let data_offset = if file_start_cluster >= 2 {
                    self.cluster_to_offset(file_start_cluster)
                } else {
                    0
                };

                deleted.push(FileEntry {
                    inode: file_start_cluster as u64,
                    name: Some(short_name),
                    size: size as u64,
                    data_offset,
                    is_deleted: true,
                    metadata: Some(metadata),
                });

                if is_dir && file_start_cluster >= 2 && file_start_cluster != self.root_cluster {
                    if let Ok(sub_chain) = self.read_cluster_chain(file_start_cluster) {
                        let _ = self.scan_clusters_for_deleted(&sub_chain, deleted);
                    }
                }
            }
        }
        Ok(())
    }
}

impl FileSystem for FAT32Parser {
    fn read_superblock(&self) -> Result<SuperblockInfo> {
        let file = File::open(&self.device_path)?;
        let total_size = file.metadata()?.len();

        let free_clusters = self.read_fsinfo_free_clusters();
        let free_blocks = free_clusters.unwrap_or(0) as u64;

        let vol_name = if self.volume_label.is_empty()
            || self.volume_label == "NO NAME"
        {
            None
        } else {
            Some(self.volume_label.clone())
        };

        Ok(SuperblockInfo {
            volume_name: vol_name,
            total_size,
            free_space: free_blocks * self.cluster_size,
            block_size: self.cluster_size,
            total_blocks: (self.total_sectors as u64 * self.bytes_per_sector as u64) / self.cluster_size,
            free_blocks,
            file_system_type: "FAT32".to_string(),
            created_at: None,
        })
    }

    fn list_root_directory(&self) -> Result<Vec<DirectoryEntry>> {
        self.parse_directory_entries_at(self.root_cluster)
    }

    fn list_directory(&self, inode: u64) -> Result<Vec<DirectoryEntry>> {
        let cluster = inode as u32;
        if cluster < 2 {
            return Err(Error::InvalidDevice("Invalid cluster number for directory".to_string()));
        }
        self.parse_directory_entries_at(cluster)
    }

    fn read_file(&self, inode: u64) -> Result<Vec<u8>> {
        let cluster = inode as u32;
        if cluster < 2 {
            return Err(Error::InvalidDevice("Invalid cluster number for file".to_string()));
        }

        let chain = self.read_cluster_chain(cluster)?;
        if chain.is_empty() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        for &c in &chain {
            let data = self.read_cluster_data(c)?;
            result.extend_from_slice(&data);
        }

        Ok(result)
    }

    fn find_deleted_files(&self) -> Result<Vec<FileEntry>> {
        self.scan_for_deleted_entries()
    }

    fn get_file_metadata(&self, inode: u64) -> Result<FileMetadata> {
        let cluster = inode as u32;

        let root_entries = self.parse_directory_entries_at(self.root_cluster)?;
        if let Some(entry) = self.find_entry_recursive(cluster, &root_entries)? {
            return Ok(entry.metadata.unwrap_or(FileMetadata {
                created: None,
                modified: None,
                accessed: None,
                permissions: None,
                owner: None,
                attributes: Vec::new(),
            }));
        }

        Ok(FileMetadata {
            created: None,
            modified: None,
            accessed: None,
            permissions: None,
            owner: None,
            attributes: Vec::new(),
        })
    }
}

impl FAT32Parser {
    fn find_entry_recursive(&self, target_cluster: u32, entries: &[DirectoryEntry]) -> Result<Option<DirectoryEntry>> {
        for entry in entries {
            if entry.inode == target_cluster as u64 {
                return Ok(Some(entry.clone()));
            }
            if entry.is_directory {
                let sub_cluster = entry.inode as u32;
                if sub_cluster >= 2 && sub_cluster != target_cluster {
                    if let Ok(sub_entries) = self.parse_directory_entries_at(sub_cluster) {
                        if let Some(found) = self.find_entry_recursive(target_cluster, &sub_entries)? {
                            return Ok(Some(found));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}
