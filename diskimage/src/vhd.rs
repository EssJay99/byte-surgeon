use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use byteorder::{BigEndian, ReadBytesExt};
use tracing::{info, debug};

use bytesurgeon_core::{Result, Error};
use crate::{DiskImage, ImageMetadata};

const VHD_MAGIC: &[u8; 8] = b"conectix";
const VHD_FOOTER_SIZE: usize = 512;
#[allow(dead_code)]
const VHD_HEADER_SIZE: usize = 1024;
#[allow(dead_code)]
const VHD_SECTOR_SIZE: u32 = 512;
#[allow(dead_code)]
const VHD_BLOCK_SIZE_DEFAULT: u32 = 2 * 1024 * 1024;

const VHD_DISK_FIXED: u32 = 2;
const VHD_DISK_DYNAMIC: u32 = 3;
const VHD_DISK_DIFFERENCING: u32 = 4;

const VHD_COOKIE: &[u8; 8] = b"cxsparse";

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VhdFooter {
    cookie: [u8; 8],
    features: u32,
    file_format_version: u32,
    data_offset: u64,
    timestamp: u32,
    creator_application: [u8; 4],
    creator_version: u32,
    creator_host_os: [u8; 4],
    original_size: u64,
    current_size: u64,
    disk_geometry: u32,
    disk_type: u32,
    checksum: u32,
    unique_id: [u8; 16],
    saved_state: u8,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VhdDynamicHeader {
    cookie: [u8; 8],
    data_offset: u64,
    table_offset: u64,
    header_version: u32,
    max_table_entries: u32,
    block_size: u32,
    checksum: u32,
    parent_uuid: [u8; 16],
    parent_timestamp: u32,
    parent_name: String,
}

#[allow(dead_code)]
pub struct VhdImage {
    file: File,
    path: PathBuf,
    footer: VhdFooter,
    dynamic_header: Option<VhdDynamicHeader>,
    bat: Vec<u32>,
    sector_size: u32,
    total_sectors: u64,
    block_size: u32,
    bitmap_size: u32,
}

impl VhdImage {
    fn read_footer(file: &mut File) -> Result<VhdFooter> {
        let file_size = file.metadata().map_err(|e| Error::Io(e))?.len();

        let footer_offset = if file_size > VHD_FOOTER_SIZE as u64 {
            file_size - VHD_FOOTER_SIZE as u64
        } else {
            0
        };

        file.seek(SeekFrom::Start(footer_offset))
            .map_err(|e| Error::Io(e))?;

        let mut cookie = [0u8; 8];
        file.read_exact(&mut cookie).map_err(|e| Error::Io(e))?;

        if &cookie != VHD_MAGIC {
            return Err(Error::Other(format!(
                "Invalid VHD magic: {:?}",
                String::from_utf8_lossy(&cookie)
            )));
        }

        let features = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let file_format_version = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let data_offset = file.read_u64::<BigEndian>().map_err(|e| Error::Io(e))?;
        let timestamp = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let mut creator_application = [0u8; 4];
        file.read_exact(&mut creator_application).map_err(|e| Error::Io(e))?;
        let creator_version = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let mut creator_host_os = [0u8; 4];
        file.read_exact(&mut creator_host_os).map_err(|e| Error::Io(e))?;
        let original_size = file.read_u64::<BigEndian>().map_err(|e| Error::Io(e))?;
        let current_size = file.read_u64::<BigEndian>().map_err(|e| Error::Io(e))?;
        let disk_geometry = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let disk_type = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let checksum = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let mut unique_id = [0u8; 16];
        file.read_exact(&mut unique_id).map_err(|e| Error::Io(e))?;
        let saved_state = file.read_u8().map_err(|e| Error::Io(e))?;

        debug!(
            "VHD footer: type={}, current_size={}, original_size={}",
            disk_type, current_size, original_size
        );

        Ok(VhdFooter {
            cookie,
            features,
            file_format_version,
            data_offset,
            timestamp,
            creator_application,
            creator_version,
            creator_host_os,
            original_size,
            current_size,
            disk_geometry,
            disk_type,
            checksum,
            unique_id,
            saved_state,
        })
    }

    fn read_dynamic_header(file: &mut File, offset: u64) -> Result<VhdDynamicHeader> {
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| Error::Io(e))?;

        let mut cookie = [0u8; 8];
        file.read_exact(&mut cookie).map_err(|e| Error::Io(e))?;

        if &cookie != VHD_COOKIE {
            return Err(Error::Other("Invalid VHD dynamic header cookie".to_string()));
        }

        let data_offset = file.read_u64::<BigEndian>().map_err(|e| Error::Io(e))?;
        let table_offset = file.read_u64::<BigEndian>().map_err(|e| Error::Io(e))?;
        let header_version = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let max_table_entries = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let block_size = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let checksum = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
        let mut parent_uuid = [0u8; 16];
        file.read_exact(&mut parent_uuid).map_err(|e| Error::Io(e))?;
        let parent_timestamp = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;

        let _reserved = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;

        let mut parent_name_raw = [0u8; 512];
        file.read_exact(&mut parent_name_raw).map_err(|e| Error::Io(e))?;

        let parent_name = {
            let utf16: Vec<u16> = parent_name_raw
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .take_while(|&c| c != 0)
                .collect();
            String::from_utf16_lossy(&utf16)
        };

        debug!(
            "VHD dynamic header: table_offset={}, max_entries={}, block_size={}",
            table_offset, max_table_entries, block_size
        );

        Ok(VhdDynamicHeader {
            cookie,
            data_offset,
            table_offset,
            header_version,
            max_table_entries,
            block_size,
            checksum,
            parent_uuid,
            parent_timestamp,
            parent_name,
        })
    }

    fn read_bat(
        file: &mut File,
        table_offset: u64,
        num_entries: u32,
    ) -> Result<Vec<u32>> {
        file.seek(SeekFrom::Start(table_offset))
            .map_err(|e| Error::Io(e))?;

        let mut bat = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            let entry = file.read_u32::<BigEndian>().map_err(|e| Error::Io(e))?;
            bat.push(entry);
        }

        debug!("BAT read: {} entries", bat.len());
        Ok(bat)
    }

    fn read_sector_dynamic(
        &mut self,
        sector: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let header = match &self.dynamic_header {
            Some(h) => h.clone(),
            None => return Ok(0),
        };

        let block_size = header.block_size as u64;
        let sectors_per_block = block_size / VHD_SECTOR_SIZE as u64;
        let block_index = sector / sectors_per_block;
        let sector_in_block = sector % sectors_per_block;

        if block_index as usize >= self.bat.len() {
            return Ok(0);
        }

        let bat_entry = self.bat[block_index as usize];
        const BAT_EMPTY: u32 = 0xFFFFFFFF;

        if bat_entry == BAT_EMPTY {
            let to_read = std::cmp::min(buffer.len(), VHD_SECTOR_SIZE as usize);
            for b in buffer[..to_read].iter_mut() {
                *b = 0;
            }
            return Ok(to_read);
        }

        let bitmap_size = ((sectors_per_block + 7) / 8) as u64;
        let block_offset = bat_entry as u64 * VHD_SECTOR_SIZE as u64;
        let sector_offset = block_offset + bitmap_size + sector_in_block * VHD_SECTOR_SIZE as u64;

        self.file.seek(SeekFrom::Start(sector_offset))
            .map_err(|e| Error::Io(e))?;

        let to_read = std::cmp::min(buffer.len(), VHD_SECTOR_SIZE as usize);
        let bytes_read = self.file.read(&mut buffer[..to_read])
            .map_err(|e| Error::Io(e))?;

        Ok(bytes_read)
    }
}

impl DiskImage for VhdImage {
    fn open(path: &Path) -> Result<Self> {
        info!("Opening VHD image: {:?}", path);

        let mut file = File::open(path).map_err(|e| Error::Io(e))?;
        let footer = Self::read_footer(&mut file)?;

        let (dynamic_header, bat, block_size, bitmap_size) = match footer.disk_type {
            VHD_DISK_FIXED => {
                (None, Vec::new(), 0u32, 0u32)
            }
            VHD_DISK_DYNAMIC | VHD_DISK_DIFFERENCING => {
                let dyn_header = Self::read_dynamic_header(&mut file, footer.data_offset)?;
                let bat = Self::read_bat(
                    &mut file,
                    dyn_header.table_offset,
                    dyn_header.max_table_entries,
                )?;
                let block_size = dyn_header.block_size;
                let sectors_per_block = block_size as u64 / VHD_SECTOR_SIZE as u64;
                let bitmap = ((sectors_per_block + 7) / 8) as u32;
                (Some(dyn_header), bat, block_size, bitmap)
            }
            _ => {
                return Err(Error::Other(format!(
                    "Unsupported VHD disk type: {}", footer.disk_type
                )));
            }
        };

        let sector_size = VHD_SECTOR_SIZE;
        let total_sectors = footer.current_size / sector_size as u64;

        info!(
            "VHD opened: type={}, {} total sectors, block_size={}",
            footer.disk_type, total_sectors, block_size
        );

        Ok(VhdImage {
            file,
            path: path.to_path_buf(),
            footer,
            dynamic_header,
            bat,
            sector_size,
            total_sectors,
            block_size,
            bitmap_size,
        })
    }

    fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> Result<usize> {
        if sector >= self.total_sectors {
            return Ok(0);
        }

        match self.footer.disk_type {
            VHD_DISK_FIXED => {
                let offset = sector * self.sector_size as u64;
                self.file.seek(SeekFrom::Start(offset))
                    .map_err(|e| Error::Io(e))?;

                let to_read = std::cmp::min(buffer.len(), self.sector_size as usize);
                let bytes_read = self.file.read(&mut buffer[..to_read])
                    .map_err(|e| Error::Io(e))?;
                Ok(bytes_read)
            }
            VHD_DISK_DYNAMIC | VHD_DISK_DIFFERENCING => {
                self.read_sector_dynamic(sector, buffer)
            }
            _ => Ok(0),
        }
    }

    fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn metadata(&self) -> ImageMetadata {
        let format_name = match self.footer.disk_type {
            VHD_DISK_FIXED => "vhd (fixed)",
            VHD_DISK_DYNAMIC => "vhd (dynamic)",
            VHD_DISK_DIFFERENCING => "vhd (differencing)",
            _ => "vhd (unknown)",
        };

        let parent_info = self.dynamic_header.as_ref()
            .and_then(|h| {
                if self.footer.disk_type == VHD_DISK_DIFFERENCING && !h.parent_name.is_empty() {
                    Some(format!("parent: {}", h.parent_name))
                } else {
                    None
                }
            });

        ImageMetadata {
            format: format_name.to_string(),
            size_bytes: self.footer.current_size,
            sector_size: self.sector_size,
            total_sectors: self.total_sectors,
            sha256: None,
            created: None,
            modified: None,
            examiner: None,
            case_number: None,
            evidence_number: None,
            description: parent_info,
        }
    }
}
