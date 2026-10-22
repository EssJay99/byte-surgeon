use crate::{Result, Error, PartitionInfo, PartitionType, FileSystemType};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{LittleEndian, ReadBytesExt};
use tracing::{info, debug, warn};

const SECTOR_SIZE: u64 = 512;
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const MBR_PARTITION_TABLE_OFFSET: usize = 446;
const MBR_PARTITION_ENTRY_SIZE: usize = 16;
const MBR_PARTITION_COUNT: usize = 4;

const GPT_HEADER_MAGIC: &[u8; 8] = b"EFI PART";
const GPT_ENTRY_SIZE: usize = 128;
const GPT_DEFAULT_ENTRY_COUNT: u32 = 128;

pub struct MbrPartitionEntry {
    pub status: u8,
    pub partition_type: u8,
    pub lba_start: u32,
    pub sector_count: u32,
}

pub struct GptHeader {
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub partition_entry_count: u32,
    pub partition_entry_size: u32,
    pub partition_entries_crc32: u32,
}

pub struct GptPartitionEntry {
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

pub struct PartitionScanner {
    device_path: String,
}

impl PartitionScanner {
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: device_path.to_string(),
        }
    }

    pub fn read_sector(&self, file: &mut File, sector: u64) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; SECTOR_SIZE as usize];
        file.seek(SeekFrom::Start(sector * SECTOR_SIZE))?;
        file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    pub fn scan_mbr(&self) -> Result<Vec<PartitionInfo>> {
        info!("Scanning MBR partition table on {}", self.device_path);

        let mut file = File::open(&self.device_path)
            .map_err(Error::Io)?;

        let sector = self.read_sector(&mut file, 0)?;

        if sector[MBR_SIGNATURE_OFFSET] != MBR_SIGNATURE[0]
            || sector[MBR_SIGNATURE_OFFSET + 1] != MBR_SIGNATURE[1]
        {
            return Err(Error::InvalidPartitionTable(
                "Invalid MBR signature".to_string(),
            ));
        }

        let mut partitions = Vec::new();

        for i in 0..MBR_PARTITION_COUNT {
            let offset = MBR_PARTITION_TABLE_OFFSET + (i * MBR_PARTITION_ENTRY_SIZE);
            let entry = self.parse_mbr_entry(&sector[offset..offset + MBR_PARTITION_ENTRY_SIZE])?;

            if entry.partition_type == 0 || entry.sector_count == 0 {
                continue;
            }

            let partition_type = Self::mbr_type_to_partition_type(entry.partition_type);
            let filesystem = Self::mbr_type_to_filesystem(entry.partition_type);
            let is_active = entry.status & 0x80 != 0;

            partitions.push(PartitionInfo {
                index: (i + 1) as u32,
                start_sector: entry.lba_start as u64,
                end_sector: entry.lba_start as u64 + entry.sector_count as u64 - 1,
                partition_type,
                filesystem,
                is_active,
                is_gpt: false,
                guid: None,
            });

            debug!(
                "MBR partition {}: type=0x{:02X}, start={}, end={}, active={}",
                i + 1, entry.partition_type, entry.lba_start,
                entry.lba_start as u64 + entry.sector_count as u64 - 1, is_active
            );
        }

        info!("Found {} MBR partitions", partitions.len());
        Ok(partitions)
    }

    fn parse_mbr_entry(&self, data: &[u8]) -> Result<MbrPartitionEntry> {
        if data.len() < MBR_PARTITION_ENTRY_SIZE {
            return Err(Error::PartitionParse("MBR entry too short".to_string()));
        }

        let status = data[0];
        let partition_type = data[4];
        let mut lba_bytes = &data[8..12];
        let lba_start = lba_bytes.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read LBA start: {}", e))
        })?;
        let mut count_bytes = &data[12..16];
        let sector_count = count_bytes.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read sector count: {}", e))
        })?;

        Ok(MbrPartitionEntry {
            status,
            partition_type,
            lba_start,
            sector_count,
        })
    }

    pub fn scan_gpt(&self) -> Result<Vec<PartitionInfo>> {
        info!("Scanning GPT partition table on {}", self.device_path);

        let mut file = File::open(&self.device_path)
            .map_err(Error::Io)?;

        let mbr_sector = self.read_sector(&mut file, 0)?;
        if mbr_sector[MBR_SIGNATURE_OFFSET] != MBR_SIGNATURE[0]
            || mbr_sector[MBR_SIGNATURE_OFFSET + 1] != MBR_SIGNATURE[1]
        {
            return Err(Error::InvalidPartitionTable(
                "No protective MBR found".to_string(),
            ));
        }

        let mbr_type = mbr_sector[MBR_PARTITION_TABLE_OFFSET + 4];
        if mbr_type != 0xEE {
            return Err(Error::InvalidPartitionTable(
                format!("Expected protective MBR type 0xEE, got 0x{:02X}", mbr_type),
            ));
        }

        let header = self.read_gpt_header(&mut file, 1)?;

        self.parse_gpt_partitions(&mut file, &header, false)
    }

    pub fn scan_gpt_backup(&self) -> Result<Vec<PartitionInfo>> {
        info!("Scanning backup GPT partition table on {}", self.device_path);

        let mut file = File::open(&self.device_path)
            .map_err(Error::Io)?;

        let metadata = file.metadata()?;
        let disk_sectors = metadata.len() / SECTOR_SIZE;
        let backup_header_lba = disk_sectors - 1;

        let header = self.read_gpt_header(&mut file, backup_header_lba)?;

        self.parse_gpt_partitions(&mut file, &header, true)
    }

    fn read_gpt_header(&self, file: &mut File, lba: u64) -> Result<GptHeader> {
        let sector = self.read_sector(file, lba)?;

        if &sector[0..8] != GPT_HEADER_MAGIC {
            return Err(Error::InvalidPartitionTable(
                format!("Invalid GPT signature at LBA {}", lba),
            ));
        }

        let mut cursor = std::io::Cursor::new(&sector[8..]);
        let revision = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read revision: {}", e))
        })?;
        let header_size = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read header size: {}", e))
        })?;
        let header_crc32 = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read header CRC32: {}", e))
        })?;
        let _reserved = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read reserved: {}", e))
        })?;
        let my_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read my LBA: {}", e))
        })?;
        let alternate_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read alternate LBA: {}", e))
        })?;
        let first_usable_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read first usable LBA: {}", e))
        })?;
        let last_usable_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read last usable LBA: {}", e))
        })?;

        let mut disk_guid = [0u8; 16];
        cursor.read_exact(&mut disk_guid).map_err(|e| {
            Error::PartitionParse(format!("Failed to read disk GUID: {}", e))
        })?;

        let partition_entry_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read partition entry LBA: {}", e))
        })?;
        let partition_entry_count = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read partition entry count: {}", e))
        })?;
        let partition_entry_size = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read partition entry size: {}", e))
        })?;
        let partition_entries_crc32 = cursor.read_u32::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read partition entries CRC32: {}", e))
        })?;

        debug!(
            "GPT header: revision={}, entries={}, entry_size={}, disk_guid={}",
            revision, partition_entry_count, partition_entry_size,
            format_guid(&disk_guid)
        );

        Ok(GptHeader {
            revision,
            header_size,
            header_crc32,
            my_lba,
            alternate_lba,
            first_usable_lba,
            last_usable_lba,
            disk_guid,
            partition_entry_lba,
            partition_entry_count,
            partition_entry_size,
            partition_entries_crc32,
        })
    }

    fn parse_gpt_partitions(
        &self,
        file: &mut File,
        header: &GptHeader,
        is_backup: bool,
    ) -> Result<Vec<PartitionInfo>> {
        let entry_count = if header.partition_entry_count == 0 {
            GPT_DEFAULT_ENTRY_COUNT
        } else {
            header.partition_entry_count
        };
        let entry_size = if header.partition_entry_size == 0 {
            GPT_ENTRY_SIZE as u32
        } else {
            header.partition_entry_size
        };

        let total_entry_bytes = entry_count as u64 * entry_size as u64;
        let total_entry_sectors = (total_entry_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;
        let mut all_entries = Vec::with_capacity(total_entry_bytes as usize);

        for s in 0..total_entry_sectors {
            let lba = header.partition_entry_lba + s;
            let sector_data = self.read_sector(file, lba)?;
            all_entries.extend_from_slice(&sector_data);
        }

        let mut partitions = Vec::new();
        let mut index = 0u32;
        let zero_guid = [0u8; 16];

        for i in 0..entry_count {
            let offset = i as usize * entry_size as usize;
            let end = offset + entry_size as usize;
            if end > all_entries.len() {
                break;
            }

            let entry = self.parse_gpt_entry(&all_entries[offset..end])?;

            if entry.type_guid == zero_guid {
                continue;
            }

            index += 1;
            let filesystem = Self::guid_to_filesystem(&entry.type_guid);
            let guid = format_guid(&entry.unique_guid);

            partitions.push(PartitionInfo {
                index,
                start_sector: entry.first_lba,
                end_sector: entry.last_lba,
                partition_type: Self::guid_to_partition_type(&entry.type_guid),
                filesystem,
                is_active: entry.attributes & 0x01 != 0,
                is_gpt: true,
                guid: Some(guid),
            });

            debug!(
                "GPT partition {}: type={}, start={}, end={}, name={}",
                index, format_guid(&entry.type_guid),
                entry.first_lba, entry.last_lba, entry.name
            );
        }

        if is_backup {
            info!("Found {} partitions from backup GPT", partitions.len());
        } else {
            info!("Found {} GPT partitions", partitions.len());
        }
        Ok(partitions)
    }

    fn parse_gpt_entry(&self, data: &[u8]) -> Result<GptPartitionEntry> {
        if data.len() < GPT_ENTRY_SIZE {
            return Err(Error::PartitionParse("GPT entry too short".to_string()));
        }

        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&data[0..16]);

        let mut unique_guid = [0u8; 16];
        unique_guid.copy_from_slice(&data[16..32]);

        let mut cursor = std::io::Cursor::new(&data[32..]);
        let first_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read first LBA: {}", e))
        })?;
        let last_lba = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read last LBA: {}", e))
        })?;
        let attributes = cursor.read_u64::<LittleEndian>().map_err(|e| {
            Error::PartitionParse(format!("Failed to read attributes: {}", e))
        })?;

        let name_bytes = &data[56..128];
        let name = String::from_utf16_lossy(
            &name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect::<Vec<u16>>(),
        );

        Ok(GptPartitionEntry {
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
            name,
        })
    }

    pub fn find_lost_partitions(&self) -> Result<Vec<PartitionInfo>> {
        info!("Scanning for lost partitions on {}", self.device_path);

        let mut file = File::open(&self.device_path)
            .map_err(Error::Io)?;

        let total_size = file.metadata()?.len();
        let total_sectors = total_size / SECTOR_SIZE;
        let scan_step = SECTOR_SIZE;
        let mut found = Vec::new();
        let mut index = 0u32;
        let mut last_end: u64 = 0;

        let mut sector_buf = vec![0u8; SECTOR_SIZE as usize];

        let mut sector_num = 0u64;
        while sector_num < total_sectors {
            file.seek(SeekFrom::Start(sector_num * SECTOR_SIZE))?;
            let bytes_read = file.read(&mut sector_buf)?;

            if bytes_read < SECTOR_SIZE as usize {
                break;
            }

            if let Some(fs_type) = Self::detect_filesystem_signature(&sector_buf) {
                let start_sector = sector_num;
                let end_sector = Self::estimate_partition_end(
                    &mut file, sector_num, total_size, &sector_buf, &fs_type,
                )?;

                if start_sector < last_end {
                    sector_num += scan_step / SECTOR_SIZE;
                    continue;
                }

                index += 1;
                let part_type = Self::filesystem_to_partition_type(&fs_type);

                found.push(PartitionInfo {
                    index,
                    start_sector,
                    end_sector,
                    partition_type: part_type,
                    filesystem: fs_type.clone(),
                    is_active: false,
                    is_gpt: false,
                    guid: None,
                });

                debug!(
                    "Found lost partition: {:?} at sector {}-{}",
                    fs_type, start_sector, end_sector
                );

                last_end = end_sector;
                sector_num = end_sector + 1;
                continue;
            }

            sector_num += scan_step / SECTOR_SIZE;
        }

        info!("Found {} lost partitions", found.len());
        Ok(found)
    }

    fn detect_filesystem_signature(sector: &[u8]) -> Option<FileSystemType> {
        if sector.len() >= 512 {
            if sector[3..7] == *b"NTFS" {
                return Some(FileSystemType::NTFS);
            }

            if sector.len() >= 90
                && &sector[82..87] == b"FAT32"
            {
                return Some(FileSystemType::FAT32);
            }
            if sector.len() >= 54
                && &sector[54..60] == b"FAT16 "
            {
                return Some(FileSystemType::FAT32);
            }
            if sector.len() >= 54
                && &sector[54..60] == b"FAT12 "
            {
                return Some(FileSystemType::FAT32);
            }

            if sector.len() >= 0x438 + 2 {
                let magic = u16::from_le_bytes([sector[0x438], sector[0x439]]);
                if magic == 0xEF53 {
                    return Some(FileSystemType::EXT4);
                }
                if magic == 0xEF53 {
                    return Some(FileSystemType::EXT4);
                }
            }

            if sector[0..4] == *b"NXSB" {
                return Some(FileSystemType::APFS);
            }

            if sector.len() >= 0x400 + 2 {
                if &sector[0x400..0x404] == b"HX\x05\x00"
                    || (sector[0x400..0x404] == [0x48, 0x2B, 0x00, 0x04])
                {
                    return Some(FileSystemType::HFSPlus);
                }
            }
        }

        None
    }

    fn estimate_partition_end(
        file: &mut File,
        start_sector: u64,
        total_size: u64,
        first_sector: &[u8],
        fs_type: &FileSystemType,
    ) -> Result<u64> {
        match fs_type {
            FileSystemType::NTFS => {
                if first_sector.len() >= 0x28 + 8 {
                    let mut cursor = std::io::Cursor::new(&first_sector[0x28..0x30]);
                    if let Ok(total_sectors) = cursor.read_u64::<LittleEndian>() {
                        if total_sectors > 0 {
                            return Ok(start_sector + total_sectors - 1);
                        }
                    }
                }
                Self::find_partition_end_by_scan(file, start_sector, total_size)
            }
            FileSystemType::FAT32 => {
                if first_sector.len() >= 0x20 + 4 {
                    let mut cursor = std::io::Cursor::new(&first_sector[0x20..0x24]);
                    if let Ok(total_sectors_32) = cursor.read_u32::<LittleEndian>() {
                        if total_sectors_32 > 0 {
                            return Ok(start_sector + total_sectors_32 as u64 - 1);
                        }
                    }
                }
                if first_sector.len() >= 0x13 + 2 {
                    let total_sectors_16 = u16::from_le_bytes([
                        first_sector[0x13], first_sector[0x14],
                    ]) as u64;
                    if total_sectors_16 > 0 {
                        return Ok(start_sector + total_sectors_16 - 1);
                    }
                }
                Self::find_partition_end_by_scan(file, start_sector, total_size)
            }
            FileSystemType::EXT4 | FileSystemType::EXT3 => {
                if first_sector.len() >= 0x34 + 4 {
                    let mut cursor = std::io::Cursor::new(&first_sector[0x34..0x38]);
                    if let Ok(block_count) = cursor.read_u32::<LittleEndian>() {
                        let mut block_size_cursor = std::io::Cursor::new(&first_sector[0x18..0x1C]);
                        if let Ok(log_block_size) = block_size_cursor.read_u32::<LittleEndian>() {
                            let block_size = 1024u64 << log_block_size;
                            let sectors_per_block = block_size / SECTOR_SIZE;
                            let total_sectors = block_count as u64 * sectors_per_block;
                            if total_sectors > 0 {
                                return Ok(start_sector + total_sectors - 1);
                            }
                        }
                    }
                }
                Self::find_partition_end_by_scan(file, start_sector, total_size)
            }
            FileSystemType::APFS => {
                if first_sector.len() >= 0x18 + 8 {
                    let mut cursor = std::io::Cursor::new(&first_sector[0x18..0x20]);
                    if let Ok(block_count) = cursor.read_u64::<LittleEndian>() {
                        let mut block_size_cursor = std::io::Cursor::new(&first_sector[0x14..0x18]);
                        if let Ok(block_size) = block_size_cursor.read_u32::<LittleEndian>() {
                            let sectors_per_block = block_size as u64 / SECTOR_SIZE;
                            if sectors_per_block > 0 {
                                let total_sectors = block_count * sectors_per_block;
                                return Ok(start_sector + total_sectors - 1);
                            }
                        }
                    }
                }
                Self::find_partition_end_by_scan(file, start_sector, total_size)
            }
            FileSystemType::HFSPlus => {
                Self::find_partition_end_by_scan(file, start_sector, total_size)
            }
            _ => Self::find_partition_end_by_scan(file, start_sector, total_size),
        }
    }

    fn find_partition_end_by_scan(
        file: &mut File,
        start_sector: u64,
        total_size: u64,
    ) -> Result<u64> {
        let max_scan = std::cmp::min(start_sector + 1024 * 1024, total_size / SECTOR_SIZE);
        let mut last_valid = start_sector;
        let mut buf = vec![0u8; SECTOR_SIZE as usize];

        let mut sector = start_sector;
        while sector < max_scan {
            file.seek(SeekFrom::Start(sector * SECTOR_SIZE))?;
            let bytes_read = file.read(&mut buf)?;
            if bytes_read == 0 {
                break;
            }

            let non_zero = buf.iter().any(|&b| b != 0);
            if non_zero {
                last_valid = sector;
            } else if sector - last_valid > 256 {
                break;
            }

            sector += 256;
        }

        Ok(last_valid)
    }

    pub fn scan_all(&self) -> Result<Vec<PartitionInfo>> {
        let mut all_partitions = Vec::new();

        match self.scan_gpt() {
            Ok(partitions) => {
                info!("Found {} GPT partitions", partitions.len());
                all_partitions.extend(partitions);
            }
            Err(e) => {
                debug!("No valid GPT found: {}", e);
                match self.scan_mbr() {
                    Ok(partitions) => {
                        info!("Found {} MBR partitions", partitions.len());
                        all_partitions.extend(partitions);
                    }
                    Err(e2) => {
                        warn!("No valid MBR found: {}", e2);
                    }
                }
            }
        }

        match self.find_lost_partitions() {
            Ok(lost) => {
                if !lost.is_empty() {
                    info!("Found {} additional lost partitions", lost.len());
                    let existing_ranges: Vec<(u64, u64)> = all_partitions
                        .iter()
                        .map(|p| (p.start_sector, p.end_sector))
                        .collect();

                    for lost_part in lost {
                        let overlaps = existing_ranges.iter().any(|&(start, end)| {
                            lost_part.start_sector <= end && lost_part.end_sector >= start
                        });
                        if !overlaps {
                            all_partitions.push(lost_part);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Lost partition scan failed: {}", e);
            }
        }

        Ok(all_partitions)
    }

    fn mbr_type_to_partition_type(type_byte: u8) -> PartitionType {
        match type_byte {
            0x00 => PartitionType::Empty,
            0x01 => PartitionType::Fat12,
            0x04 | 0x06 | 0x0E => PartitionType::Fat16,
            0x07 => PartitionType::Ntfs,
            0x0B => PartitionType::Fat32,
            0x0C => PartitionType::Fat32Lba,
            0x82 => PartitionType::LinuxSwap,
            0x83 => PartitionType::Ext,
            0xAF => PartitionType::Apfs,
            0xEF => PartitionType::EfiSystem,
            other => PartitionType::Other(other),
        }
    }

    fn mbr_type_to_filesystem(type_byte: u8) -> FileSystemType {
        match type_byte {
            0x07 => FileSystemType::NTFS,
            0x0B | 0x0C | 0x01 | 0x04 | 0x06 | 0x0E => FileSystemType::FAT32,
            0x83 => FileSystemType::EXT4,
            0xAF => FileSystemType::APFS,
            0xEF => FileSystemType::ExFAT,
            0x82 => FileSystemType::Unknown,
            _ => FileSystemType::Unknown,
        }
    }

    fn guid_to_filesystem(guid: &[u8; 16]) -> FileSystemType {
        let type_str = format_guid(guid);
        match type_str.to_uppercase().as_str() {
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => FileSystemType::NTFS,
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => FileSystemType::ExFAT,
            "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => FileSystemType::EXT4,
            "7C3457EF-0000-11AA-AA11-00306543ECAC" => FileSystemType::APFS,
            "48465300-0000-11AA-AA11-00306543ECAC" => FileSystemType::HFSPlus,
            _ => FileSystemType::Unknown,
        }
    }

    fn guid_to_partition_type(guid: &[u8; 16]) -> PartitionType {
        let type_str = format_guid(guid);
        match type_str.to_uppercase().as_str() {
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => PartitionType::Ntfs,
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => PartitionType::EfiSystem,
            "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => PartitionType::Ext,
            "7C3457EF-0000-11AA-AA11-00306543ECAC" => PartitionType::Apfs,
            "48465300-0000-11AA-AA11-00306543ECAC" => PartitionType::HfsPlus,
            "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => PartitionType::LinuxSwap,
            _ => PartitionType::Other(0xFF),
        }
    }

    fn filesystem_to_partition_type(fs: &FileSystemType) -> PartitionType {
        match fs {
            FileSystemType::NTFS => PartitionType::Ntfs,
            FileSystemType::FAT32 => PartitionType::Fat32,
            FileSystemType::EXT4 | FileSystemType::EXT3 => PartitionType::Ext,
            FileSystemType::APFS => PartitionType::Apfs,
            FileSystemType::HFSPlus => PartitionType::HfsPlus,
            FileSystemType::ExFAT => PartitionType::EfiSystem,
            _ => PartitionType::Other(0x00),
        }
    }
}

fn format_guid(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    let d4 = u16::from_be_bytes([guid[8], guid[9]]);
    let d5 = u64::from_be_bytes([0, 0, guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]]);

    format!(
        "{:08X}-{:04X}-{:04X}-{:04X}-{:012X}",
        d1, d2, d3, d4, d5
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn build_mbr_sector(partitions: &[(u8, u8, u32, u32)]) -> Vec<u8> {
        let mut sector = vec![0u8; 512];
        for (i, &(status, ptype, lba, count)) in partitions.iter().enumerate() {
            let offset = MBR_PARTITION_TABLE_OFFSET + i * MBR_PARTITION_ENTRY_SIZE;
            sector[offset] = status;
            sector[offset + 4] = ptype;
            let lba_bytes = lba.to_le_bytes();
            sector[offset + 8..offset + 12].copy_from_slice(&lba_bytes);
            let count_bytes = count.to_le_bytes();
            sector[offset + 12..offset + 16].copy_from_slice(&count_bytes);
        }
        sector[510] = 0x55;
        sector[511] = 0xAA;
        sector
    }

    fn build_gpt_sector(header_lba: u64, _entries: &[(u64, u64)]) -> Vec<u8> {
        let mut sector = vec![0u8; 512];
        sector[0..8].copy_from_slice(b"EFI PART");
        let revision_bytes: u32 = 0x00010000;
        sector[8..12].copy_from_slice(&revision_bytes.to_le_bytes());
        let header_size: u32 = 92;
        sector[12..16].copy_from_slice(&header_size.to_le_bytes());
        sector[16..20].copy_from_slice(&0u32.to_le_bytes());
        sector[20..24].copy_from_slice(&0u32.to_le_bytes());
        sector[24..32].copy_from_slice(&header_lba.to_le_bytes());
        let alt_lba: u64 = 99999;
        sector[32..40].copy_from_slice(&alt_lba.to_le_bytes());
        let first_usable: u64 = 34;
        sector[40..48].copy_from_slice(&first_usable.to_le_bytes());
        let last_usable: u64 = 99965;
        sector[48..56].copy_from_slice(&last_usable.to_le_bytes());
        sector[72..80].copy_from_slice(&2u64.to_le_bytes());
        let entry_count: u32 = 128;
        sector[80..84].copy_from_slice(&entry_count.to_le_bytes());
        let entry_size: u32 = 128;
        sector[84..88].copy_from_slice(&entry_size.to_le_bytes());
        sector
    }

    fn build_gpt_entry(first_lba: u64, last_lba: u64) -> Vec<u8> {
        let mut entry = vec![0u8; 128];
        let type_guid: [u8; 16] = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
            0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
        ];
        entry[0..16].copy_from_slice(&type_guid);
        let unique_guid: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        entry[16..32].copy_from_slice(&unique_guid);
        entry[32..40].copy_from_slice(&first_lba.to_le_bytes());
        entry[40..48].copy_from_slice(&last_lba.to_le_bytes());
        entry
    }

    #[test]
    fn test_format_guid() {
        let guid: [u8; 16] = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
            0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
        ];
        let formatted = format_guid(&guid);
        assert_eq!(formatted, "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7");
    }

    #[test]
    fn test_mbr_type_to_partition_type() {
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0x07), PartitionType::Ntfs);
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0x0B), PartitionType::Fat32);
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0x0C), PartitionType::Fat32Lba);
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0x83), PartitionType::Ext);
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0xAF), PartitionType::Apfs);
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0x00), PartitionType::Empty);
        assert_eq!(PartitionScanner::mbr_type_to_partition_type(0x99), PartitionType::Other(0x99));
    }

    #[test]
    fn test_mbr_type_to_filesystem() {
        assert_eq!(PartitionScanner::mbr_type_to_filesystem(0x07), FileSystemType::NTFS);
        assert_eq!(PartitionScanner::mbr_type_to_filesystem(0x0B), FileSystemType::FAT32);
        assert_eq!(PartitionScanner::mbr_type_to_filesystem(0x83), FileSystemType::EXT4);
        assert_eq!(PartitionScanner::mbr_type_to_filesystem(0xAF), FileSystemType::APFS);
        assert_eq!(PartitionScanner::mbr_type_to_filesystem(0x42), FileSystemType::Unknown);
    }

    #[test]
    fn test_detect_ntfs_signature() {
        let mut sector = vec![0u8; 512];
        sector[3..7].copy_from_slice(b"NTFS");
        let result = PartitionScanner::detect_filesystem_signature(&sector);
        assert_eq!(result, Some(FileSystemType::NTFS));
    }

    #[test]
    fn test_detect_fat32_signature() {
        let mut sector = vec![0u8; 512];
        sector[82..87].copy_from_slice(b"FAT32");
        let result = PartitionScanner::detect_filesystem_signature(&sector);
        assert_eq!(result, Some(FileSystemType::FAT32));
    }

    #[test]
    fn test_detect_ext4_signature() {
        let mut sector = vec![0u8; 0x500];
        sector[0x438] = 0x53;
        sector[0x439] = 0xEF;
        let result = PartitionScanner::detect_filesystem_signature(&sector);
        assert_eq!(result, Some(FileSystemType::EXT4));
    }

    #[test]
    fn test_detect_apfs_signature() {
        let mut sector = vec![0u8; 512];
        sector[0..4].copy_from_slice(b"NXSB");
        let result = PartitionScanner::detect_filesystem_signature(&sector);
        assert_eq!(result, Some(FileSystemType::APFS));
    }

    #[test]
    fn test_detect_unknown_signature() {
        let sector = vec![0u8; 512];
        let result = PartitionScanner::detect_filesystem_signature(&sector);
        assert_eq!(result, None);
    }

    #[test]
    fn test_guid_to_filesystem_ntfs() {
        let guid: [u8; 16] = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
            0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
        ];
        assert_eq!(PartitionScanner::guid_to_filesystem(&guid), FileSystemType::NTFS);
    }

    #[test]
    fn test_guid_to_filesystem_ext4() {
        let guid: [u8; 16] = [
            0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
            0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
        ];
        assert_eq!(PartitionScanner::guid_to_filesystem(&guid), FileSystemType::EXT4);
    }

    #[test]
    fn test_guid_to_partition_type_efi() {
        let guid: [u8; 16] = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
            0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
        ];
        assert_eq!(PartitionScanner::guid_to_partition_type(&guid), PartitionType::EfiSystem);
    }

    #[test]
    fn test_parse_mbr_entry() {
        let scanner = PartitionScanner::new("/dev/null");
        let mut data = vec![0u8; 16];
        data[0] = 0x80;
        data[4] = 0x07;
        let lba: u32 = 2048;
        data[8..12].copy_from_slice(&lba.to_le_bytes());
        let count: u32 = 1024;
        data[12..16].copy_from_slice(&count.to_le_bytes());

        let entry = scanner.parse_mbr_entry(&data).unwrap();
        assert_eq!(entry.status, 0x80);
        assert_eq!(entry.partition_type, 0x07);
        assert_eq!(entry.lba_start, 2048);
        assert_eq!(entry.sector_count, 1024);
    }

    #[test]
    fn test_scan_mbr_with_valid_image() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut image = vec![0u8; 512 * 100];
        let partitions = vec![
            (0x80u8, 0x07u8, 2048u32, 1024u32),
            (0x00, 0x0B, 3072, 512),
        ];
        let mbr = build_mbr_sector(&partitions);
        image[..512].copy_from_slice(&mbr);
        tmp.write_all(&image).unwrap();
        tmp.flush().unwrap();

        let scanner = PartitionScanner::new(tmp.path().to_str().unwrap());
        let result = scanner.scan_mbr().unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(result[0].index, 1);
        assert_eq!(result[0].start_sector, 2048);
        assert_eq!(result[0].end_sector, 3071);
        assert_eq!(result[0].partition_type, PartitionType::Ntfs);
        assert!(result[0].is_active);
        assert!(!result[0].is_gpt);
        assert!(result[0].guid.is_none());

        assert_eq!(result[1].index, 2);
        assert_eq!(result[1].start_sector, 3072);
        assert_eq!(result[1].end_sector, 3583);
        assert_eq!(result[1].partition_type, PartitionType::Fat32);
        assert!(!result[1].is_active);
    }

    #[test]
    fn test_scan_mbr_invalid_signature() {
        let mut tmp = NamedTempFile::new().unwrap();
        let image = vec![0u8; 512];
        tmp.write_all(&image).unwrap();
        tmp.flush().unwrap();

        let scanner = PartitionScanner::new(tmp.path().to_str().unwrap());
        let result = scanner.scan_mbr();
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_gpt_with_valid_image() {
        let mut tmp = NamedTempFile::new().unwrap();
        let total_size = 512 * 100000;
        let mut image = vec![0u8; total_size];

        let mut protective_mbr = vec![0u8; 512];
        protective_mbr[MBR_PARTITION_TABLE_OFFSET + 4] = 0xEE;
        protective_mbr[510] = 0x55;
        protective_mbr[511] = 0xAA;
        image[..512].copy_from_slice(&protective_mbr);

        let gpt_header = build_gpt_sector(1, &[(34, 1000), (1001, 2000)]);
        image[512..1024].copy_from_slice(&gpt_header);

        let entry1 = build_gpt_entry(34, 1000);
        image[1024..1024 + 128].copy_from_slice(&entry1);

        let entry2 = build_gpt_entry(1001, 2000);
        image[1152..1152 + 128].copy_from_slice(&entry2);

        tmp.write_all(&image).unwrap();
        tmp.flush().unwrap();

        let scanner = PartitionScanner::new(tmp.path().to_str().unwrap());
        let result = scanner.scan_gpt().unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].is_gpt);
        assert!(result[0].guid.is_some());
        assert_eq!(result[0].start_sector, 34);
        assert_eq!(result[0].end_sector, 1000);
        assert_eq!(result[1].start_sector, 1001);
        assert_eq!(result[1].end_sector, 2000);
    }

    #[test]
    fn test_partition_scanner_creation() {
        let scanner = PartitionScanner::new("/dev/null");
        assert_eq!(scanner.device_path, "/dev/null");
    }

    #[test]
    fn test_filesystem_to_partition_type() {
        assert_eq!(
            PartitionScanner::filesystem_to_partition_type(&FileSystemType::NTFS),
            PartitionType::Ntfs
        );
        assert_eq!(
            PartitionScanner::filesystem_to_partition_type(&FileSystemType::FAT32),
            PartitionType::Fat32
        );
        assert_eq!(
            PartitionScanner::filesystem_to_partition_type(&FileSystemType::EXT4),
            PartitionType::Ext
        );
        assert_eq!(
            PartitionScanner::filesystem_to_partition_type(&FileSystemType::APFS),
            PartitionType::Apfs
        );
        assert_eq!(
            PartitionScanner::filesystem_to_partition_type(&FileSystemType::Unknown),
            PartitionType::Other(0x00)
        );
    }

    #[test]
    fn test_mbr_empty_entries_skipped() {
        let mut tmp = NamedTempFile::new().unwrap();
        let mut image = vec![0u8; 512 * 100];
        let partitions = vec![
            (0x00u8, 0x00u8, 0u32, 0u32),
            (0x80, 0x07, 2048, 1024),
            (0x00, 0x00, 0, 0),
            (0x00, 0x83, 4096, 2048),
        ];
        let mbr = build_mbr_sector(&partitions);
        image[..512].copy_from_slice(&mbr);
        tmp.write_all(&image).unwrap();
        tmp.flush().unwrap();

        let scanner = PartitionScanner::new(tmp.path().to_str().unwrap());
        let result = scanner.scan_mbr().unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].index, 2);
        assert_eq!(result[1].index, 4);
    }

    #[test]
    fn test_parse_gpt_entry() {
        let scanner = PartitionScanner::new("/dev/null");
        let mut entry = vec![0u8; 128];
        let type_guid: [u8; 16] = [
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
            0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
        ];
        entry[0..16].copy_from_slice(&type_guid);
        let unique: [u8; 16] = [1; 16];
        entry[16..32].copy_from_slice(&unique);
        let first: u64 = 100;
        let last: u64 = 200;
        entry[32..40].copy_from_slice(&first.to_le_bytes());
        entry[40..48].copy_from_slice(&last.to_le_bytes());
        let name_utf16: Vec<u16> = "TestPart".encode_utf16().collect();
        for (i, &c) in name_utf16.iter().enumerate() {
            let offset = 56 + i * 2;
            entry[offset] = (c & 0xFF) as u8;
            entry[offset + 1] = (c >> 8) as u8;
        }

        let parsed = scanner.parse_gpt_entry(&entry).unwrap();
        assert_eq!(parsed.type_guid, type_guid);
        assert_eq!(parsed.first_lba, 100);
        assert_eq!(parsed.last_lba, 200);
        assert_eq!(parsed.name, "TestPart");
    }
}
