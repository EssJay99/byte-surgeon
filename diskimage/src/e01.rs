use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use byteorder::{LittleEndian, ReadBytesExt};
use tracing::{info, debug};

use bytesurgeon_core::{Result, Error};
use crate::{DiskImage, ImageMetadata};

const E01_MAGIC_V1: &[u8; 8] = b"EVF0\x09\r\n\x00";
const E01_MAGIC_V2: &[u8; 8] = b"EVF09\x00\x00\x00";
#[allow(dead_code)]
const E01_SECTOR_SIZE: u32 = 64;
const DEFAULT_DATA_SECTOR_SIZE: u32 = 512;

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct E01Header {
    magic: [u8; 8],
    fields_offset: u64,
    fields_size: u64,
    next_chunk_offset: u64,
    segment_count: u32,
}

#[derive(Debug, Clone)]
struct E01Segment {
    path: PathBuf,
    size_bytes: u64,
}

#[derive(Debug, Clone)]
struct E01FieldEntry {
    field_type: u16,
    data: Vec<u8>,
}

#[allow(dead_code)]
pub struct E01Image {
    segments: Vec<E01Segment>,
    current_segment: usize,
    current_segment_file: File,
    header: E01Header,
    fields: Vec<E01FieldEntry>,
    total_size_bytes: u64,
    sector_size: u32,
    data_start_offset: u64,
    data_total_sectors: u64,
    case_number: Option<String>,
    evidence_number: Option<String>,
    examiner: Option<String>,
    description: Option<String>,
}

impl E01Image {
    fn parse_header(file: &mut File) -> Result<E01Header> {
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).map_err(|e| Error::Io(e))?;

        if magic != *E01_MAGIC_V1 && magic != *E01_MAGIC_V2 {
            return Err(Error::Other("Invalid E01 magic bytes".to_string()));
        }

        let fields_offset = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let fields_size = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let next_chunk_offset = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let segment_count = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;

        debug!(
            "E01 header: fields_offset={}, fields_size={}, next_chunk={}, segments={}",
            fields_offset, fields_size, next_chunk_offset, segment_count
        );

        Ok(E01Header {
            magic,
            fields_offset,
            fields_size,
            next_chunk_offset,
            segment_count,
        })
    }

    fn read_fields(file: &mut File, header: &E01Header) -> Result<Vec<E01FieldEntry>> {
        file.seek(SeekFrom::Start(header.fields_offset))
            .map_err(|e| Error::Io(e))?;

        let mut fields = Vec::new();
        let fields_end = header.fields_offset + header.fields_size;

        while file.stream_position().map_err(|e| Error::Io(e))? < fields_end {
            let field_type = match file.read_u16::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let field_size = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;

            if field_size == 0 {
                break;
            }

            let mut data = vec![0u8; field_size as usize];
            file.read_exact(&mut data).map_err(|e| Error::Io(e))?;

            fields.push(E01FieldEntry { field_type, data });
        }

        Ok(fields)
    }

    fn extract_string_field(fields: &[E01FieldEntry], field_type: u16) -> Option<String> {
        fields.iter()
            .find(|f| f.field_type == field_type)
            .and_then(|f| {
                let end = f.data.iter().position(|&b| b == 0).unwrap_or(f.data.len());
                String::from_utf8(f.data[..end].to_vec()).ok()
            })
    }

    fn open_segment(path: &Path) -> Result<File> {
        File::open(path).map_err(|e| Error::Io(e))
    }

    fn find_segment_files(base_path: &Path) -> Result<Vec<PathBuf>> {
        let mut segments = Vec::new();
        let base_str = base_path.to_string_lossy().to_string();

        let stem = if let Some(dot_pos) = base_str.rfind('.') {
            &base_str[..dot_pos]
        } else {
            &base_str
        };

        segments.push(base_path.to_path_buf());

        for i in 1u32.. {
            let ext = format!("{:02}", i);
            let seg_path = PathBuf::from(format!("{}.{}", stem, ext));
            if seg_path.exists() {
                segments.push(seg_path);
            } else {
                break;
            }
        }

        Ok(segments)
    }
}

impl DiskImage for E01Image {
    fn open(path: &Path) -> Result<Self> {
        info!("Opening E01 forensic image: {:?}", path);

        let mut primary = File::open(path).map_err(|e| Error::Io(e))?;
        let header = Self::parse_header(&mut primary)?;
        let fields = Self::read_fields(&mut primary, &header)?;

        let case_number = Self::extract_string_field(&fields, 0x0001);
        let evidence_number = Self::extract_string_field(&fields, 0x0002);
        let examiner = Self::extract_string_field(&fields, 0x0006);
        let description = Self::extract_string_field(&fields, 0x0009);

        let segment_paths = Self::find_segment_files(path)?;
        let mut segments = Vec::new();
        let mut total_size: u64 = 0;

        for seg_path in &segment_paths {
            let file = File::open(seg_path).map_err(|e| Error::Io(e))?;
            let size = file.metadata().map_err(|e| Error::Io(e))?.len();
            segments.push(E01Segment {
                path: seg_path.clone(),
                size_bytes: size,
            });
            total_size += size;
        }

        let data_start = 512u64;
        let sector_size = DEFAULT_DATA_SECTOR_SIZE;
        let data_size = if let Some(size_field) = fields.iter().find(|f| f.field_type == 0x000F) {
            if size_field.data.len() >= 8 {
                u64::from_le_bytes(size_field.data[..8].try_into().unwrap_or([0; 8]))
            } else {
                total_size.saturating_sub(data_start)
            }
        } else {
            total_size.saturating_sub(data_start)
        };

        let total_sectors = data_size / sector_size as u64;

        let current_segment_file = Self::open_segment(path)?;

        info!(
            "E01 image opened: {} segments, {} total sectors, examiner={:?}",
            segments.len(), total_sectors, examiner
        );

        Ok(E01Image {
            segments,
            current_segment: 0,
            current_segment_file,
            header,
            fields,
            total_size_bytes: data_size,
            sector_size,
            data_start_offset: data_start,
            data_total_sectors: total_sectors,
            case_number,
            evidence_number,
            examiner,
            description,
        })
    }

    fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> Result<usize> {
        if sector >= self.data_total_sectors {
            return Ok(0);
        }

        let byte_offset = self.data_start_offset + sector * self.sector_size as u64;
        let to_read = std::cmp::min(
            buffer.len() as u64,
            (self.data_total_sectors - sector) * self.sector_size as u64,
        ) as usize;

        let mut cumulative: u64 = 0;
        let mut seg_idx = 0;
        for (i, seg) in self.segments.iter().enumerate() {
            if cumulative + seg.size_bytes > byte_offset {
                seg_idx = i;
                break;
            }
            cumulative += seg.size_bytes;
        }

        if seg_idx != self.current_segment {
            self.current_segment = seg_idx;
            self.current_segment_file = Self::open_segment(&self.segments[seg_idx].path)?;
        }

        let offset_in_segment = byte_offset - cumulative;
        self.current_segment_file
            .seek(SeekFrom::Start(offset_in_segment))
            .map_err(|e| Error::Io(e))?;

        let bytes_read = self.current_segment_file
            .read(&mut buffer[..to_read])
            .map_err(|e| Error::Io(e))?;

        Ok(bytes_read)
    }

    fn total_sectors(&self) -> u64 {
        self.data_total_sectors
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn metadata(&self) -> ImageMetadata {
        ImageMetadata {
            format: "e01".to_string(),
            size_bytes: self.total_size_bytes,
            sector_size: self.sector_size,
            total_sectors: self.data_total_sectors,
            sha256: None,
            created: None,
            modified: None,
            examiner: self.examiner.clone(),
            case_number: self.case_number.clone(),
            evidence_number: self.evidence_number.clone(),
            description: self.description.clone(),
        }
    }
}
