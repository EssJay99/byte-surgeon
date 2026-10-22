use std::fs::File;
use std::io::{Read, Seek, SeekFrom, BufRead, BufReader};
use std::path::{Path, PathBuf};
use byteorder::{LittleEndian, ReadBytesExt};
use tracing::{info, debug, warn};

use bytesurgeon_core::{Result, Error};
use crate::{DiskImage, ImageMetadata};

#[allow(dead_code)]
const VMDK_MAGIC: &str = "# Disk DescriptorFile";

#[derive(Debug, Clone, PartialEq)]
enum VmdkFormat {
    MonolithicSparse,
    MonolithicFlat,
    TwoGbMaxExtentSparse,
    TwoGbMaxExtentFlat,
}

#[derive(Debug, Clone)]
struct VmdkExtent {
    path: PathBuf,
    size_bytes: u64,
    is_sparse: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
struct SparseHeader {
    magic: u32,
    version: u32,
    header_size: u32,
    capacity_sectors: u64,
    grain_size_sectors: u64,
    gd_offset: u64,
    rgd_offset: u64,
    grain_size_bytes: u64,
}

const VMDK_SPARSE_MAGIC: u32 = 0x564d444b;

#[allow(dead_code)]
pub struct VmdkImage {
    descriptor_path: PathBuf,
    extents: Vec<VmdkExtent>,
    format: VmdkFormat,
    total_size_bytes: u64,
    sector_size: u32,
    total_sector_count: u64,
    extent_files: Vec<Option<File>>,
    sparse_headers: Vec<Option<SparseHeader>>,
    grain_tables: Vec<Vec<u32>>,
}

impl VmdkImage {
    fn parse_descriptor(path: &Path) -> Result<(VmdkFormat, Vec<VmdkExtent>, u64)> {
        let file = File::open(path).map_err(|e| Error::Io(e))?;
        let reader = BufReader::new(file);

        let format;
        let mut extents = Vec::new();
        let mut capacity_bytes: u64 = 0;
        let mut create_type = String::new();

        for line in reader.lines() {
            let line = line.map_err(|e| Error::Io(e))?;
            let trimmed = line.trim().to_string();

            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with("createType") {
                if let Some(val) = trimmed.split('=').nth(1) {
                    create_type = val.trim().trim_matches('"').to_string();
                }
            }

            if trimmed.starts_with("capacity") {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let sectors: u64 = val.trim().parse().unwrap_or(0);
                    capacity_bytes = sectors * 512;
                }
            }

            if trimmed.starts_with("extents") || trimmed.starts_with("RW") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 4 {
                    let size_sectors: u64 = parts[1].parse().unwrap_or(0);
                    let extent_type = parts[2];
                    let extent_file = parts[3].trim_matches('"');

                    let is_sparse = extent_type == "SPARSE";
                    let extent_path = if Path::new(extent_file).is_absolute() {
                        PathBuf::from(extent_file)
                    } else {
                        path.parent()
                            .unwrap_or(Path::new("."))
                            .join(extent_file)
                    };

                    extents.push(VmdkExtent {
                        path: extent_path,
                        size_bytes: size_sectors * 512,
                        is_sparse,
                    });
                }
            }
        }

        format = match create_type.as_str() {
            "monolithicSparse" => VmdkFormat::MonolithicSparse,
            "monolithicFlat" => VmdkFormat::MonolithicFlat,
            "twoGbMaxExtentSparse" => VmdkFormat::TwoGbMaxExtentSparse,
            "twoGbMaxExtentFlat" => VmdkFormat::TwoGbMaxExtentFlat,
            _ => VmdkFormat::MonolithicSparse,
        };

        if extents.is_empty() && format == VmdkFormat::MonolithicSparse {
            let vmdk_path = path.to_path_buf();
            extents.push(VmdkExtent {
                path: vmdk_path,
                size_bytes: capacity_bytes,
                is_sparse: true,
            });
        }

        Ok((format, extents, capacity_bytes))
    }

    fn parse_sparse_header(file: &mut File) -> Result<SparseHeader> {
        file.seek(SeekFrom::Start(0)).map_err(|e| Error::Io(e))?;

        let magic = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;
        if magic != VMDK_SPARSE_MAGIC {
            return Err(Error::Other(format!(
                "Invalid VMDK sparse magic: 0x{:08x}", magic
            )));
        }

        let version = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let _flags = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let capacity_sectors = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let grain_size_sectors = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let _descriptor_offset = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let _descriptor_size = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let _num_gtes_per_gt = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let rgd_offset = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let gd_offset = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;
        let _over_head_sectors = file.read_u64::<LittleEndian>().map_err(|e| Error::Io(e))?;

        let grain_size_bytes = grain_size_sectors * 512;
        let header_size = 2048;

        debug!(
            "VMDK sparse header: version={}, capacity={} sectors, grain_size={} bytes",
            version, capacity_sectors, grain_size_bytes
        );

        Ok(SparseHeader {
            magic,
            version,
            header_size,
            capacity_sectors,
            grain_size_sectors,
            gd_offset,
            rgd_offset,
            grain_size_bytes,
        })
    }

    fn read_grain_table(
        file: &mut File,
        gt_offset: u64,
        num_entries: u32,
    ) -> Result<Vec<u32>> {
        file.seek(SeekFrom::Start(gt_offset * 512))
            .map_err(|e| Error::Io(e))?;

        let mut table = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            let entry = file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?;
            table.push(entry);
        }

        Ok(table)
    }

    fn read_sparse_sector(
        &mut self,
        extent_idx: usize,
        sector_in_extent: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let header = match &self.sparse_headers[extent_idx] {
            Some(h) => h,
            None => return Ok(0),
        };

        let grain_idx = sector_in_extent / header.grain_size_sectors;
        let offset_in_grain = sector_in_extent % header.grain_size_sectors;

        let num_gtes = ((header.capacity_sectors + header.grain_size_sectors - 1)
            / header.grain_size_sectors) as u32;

        if grain_idx >= num_gtes as u64 {
            return Ok(0);
        }

        if self.grain_tables[extent_idx].is_empty() && header.gd_offset > 0 {
            let gd_entry = {
                let file = self.extent_files[extent_idx].as_mut().unwrap();
                file.seek(SeekFrom::Start(header.gd_offset * 512))
                    .map_err(|e| Error::Io(e))?;
                file.read_u32::<LittleEndian>().map_err(|e| Error::Io(e))?
            };

            if gd_entry != 0 {
                let gt = Self::read_grain_table(
                    self.extent_files[extent_idx].as_mut().unwrap(),
                    gd_entry as u64,
                    num_gtes,
                )?;
                self.grain_tables[extent_idx] = gt;
            }
        }

        let gt = &self.grain_tables[extent_idx];
        if grain_idx as usize >= gt.len() {
            return Ok(0);
        }

        let gte = gt[grain_idx as usize];
        if gte == 0 {
            let to_read = std::cmp::min(buffer.len(), 512);
            for byte in buffer[..to_read].iter_mut() {
                *byte = 0;
            }
            return Ok(to_read);
        }

        let grain_byte_offset = gte as u64 * header.grain_size_bytes;
        let read_offset = grain_byte_offset + offset_in_grain * 512;

        let file = self.extent_files[extent_idx].as_mut().unwrap();
        file.seek(SeekFrom::Start(read_offset))
            .map_err(|e| Error::Io(e))?;

        let to_read = std::cmp::min(buffer.len(), 512);
        let bytes_read = file.read(&mut buffer[..to_read])
            .map_err(|e| Error::Io(e))?;

        Ok(bytes_read)
    }

    pub fn convert_to_raw(&mut self, output_path: &Path) -> Result<()> {
        info!("Converting VMDK to raw: {:?}", output_path);
        let mut out = File::create(output_path).map_err(|e| Error::Io(e))?;

        let sector_size = self.sector_size as u64;
        let total = self.total_sector_count;
        let mut buf = vec![0u8; sector_size as usize];

        use std::io::Write;
        for sector in 0..total {
            let read = self.read_sector(sector, &mut buf)?;
            if read > 0 {
                out.write_all(&buf[..read]).map_err(|e| Error::Io(e))?;
            }
        }

        info!("Conversion complete: {} sectors written", total);
        Ok(())
    }
}

impl DiskImage for VmdkImage {
    fn open(path: &Path) -> Result<Self> {
        info!("Opening VMDK image: {:?}", path);

        let mut probe = [0u8; 21];
        {
            let mut f = File::open(path).map_err(|e| Error::Io(e))?;
            f.read_exact(&mut probe).map_err(|e| Error::Io(e))?;
        }

        let is_descriptor = String::from_utf8_lossy(&probe)
            .starts_with("# Disk DescriptorFile");

        let (format, extents, capacity) = if is_descriptor {
            Self::parse_descriptor(path)?
        } else {
            let meta = File::open(path).map_err(|e| Error::Io(e))?
                .metadata().map_err(|e| Error::Io(e))?;
            let size = meta.len();
            (
                VmdkFormat::MonolithicSparse,
                vec![VmdkExtent {
                    path: path.to_path_buf(),
                    size_bytes: size,
                    is_sparse: true,
                }],
                size,
            )
        };

        let mut extent_files = Vec::new();
        let mut sparse_headers = Vec::new();
        let mut grain_tables = Vec::new();

        for extent in &extents {
            if extent.path.exists() {
                let mut file = File::open(&extent.path).map_err(|e| Error::Io(e))?;

                if extent.is_sparse {
                    match Self::parse_sparse_header(&mut file) {
                        Ok(header) => {
                            let num_gtes = ((header.capacity_sectors
                                + header.grain_size_sectors - 1)
                                / header.grain_size_sectors) as usize;
                            sparse_headers.push(Some(header));
                            grain_tables.push(Vec::with_capacity(num_gtes));
                        }
                        Err(_) => {
                            sparse_headers.push(None);
                            grain_tables.push(Vec::new());
                        }
                    }
                } else {
                    sparse_headers.push(None);
                    grain_tables.push(Vec::new());
                }

                extent_files.push(Some(file));
            } else {
                warn!("VMDK extent not found: {:?}", extent.path);
                extent_files.push(None);
                sparse_headers.push(None);
                grain_tables.push(Vec::new());
            }
        }

        let sector_size = 512u32;
        let total_sectors = capacity / sector_size as u64;

        info!(
            "VMDK opened: format={:?}, {} extents, {} total sectors",
            format, extents.len(), total_sectors
        );

        Ok(VmdkImage {
            descriptor_path: path.to_path_buf(),
            extents,
            format,
            total_size_bytes: capacity,
            sector_size,
            total_sector_count: total_sectors,
            extent_files,
            sparse_headers,
            grain_tables,
        })
    }

    fn read_sector(&mut self, sector: u64, buffer: &mut [u8]) -> Result<usize> {
        if sector >= self.total_sector_count {
            return Ok(0);
        }

        let byte_offset = sector * self.sector_size as u64;
        let mut cumulative: u64 = 0;

        for (i, extent) in self.extents.iter().enumerate() {
            if cumulative + extent.size_bytes > byte_offset {
                let offset_in_extent = byte_offset - cumulative;
                let sector_in_extent = offset_in_extent / self.sector_size as u64;

                if extent.is_sparse {
                    return self.read_sparse_sector(i, sector_in_extent, buffer);
                }

                let file = match &mut self.extent_files[i] {
                    Some(f) => f,
                    None => return Ok(0),
                };

                file.seek(SeekFrom::Start(offset_in_extent))
                    .map_err(|e| Error::Io(e))?;

                let to_read = std::cmp::min(
                    buffer.len() as u64,
                    extent.size_bytes - offset_in_extent,
                ) as usize;

                return file.read(&mut buffer[..to_read]).map_err(|e| Error::Io(e));
            }
            cumulative += extent.size_bytes;
        }

        Ok(0)
    }

    fn total_sectors(&self) -> u64 {
        self.total_sector_count
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn metadata(&self) -> ImageMetadata {
        ImageMetadata {
            format: format!("vmdk ({:?})", self.format),
            size_bytes: self.total_size_bytes,
            sector_size: self.sector_size,
            total_sectors: self.total_sector_count,
            sha256: None,
            created: None,
            modified: None,
            examiner: None,
            case_number: None,
            evidence_number: None,
            description: None,
        }
    }
}
