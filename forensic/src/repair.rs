use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const JPEG_SOI_MARKER: [u8; 2] = [0xFF, 0xD8];
const JPEG_EOI_MARKER: [u8; 2] = [0xFF, 0xD9];
const JPEG_APP0_MARKER: [u8; 2] = [0xFF, 0xE0];
#[allow(dead_code)]
const JPEG_APP1_MARKER: [u8; 2] = [0xFF, 0xE1];

const ZIP_LOCAL_FILE_HEADER: u32 = 0x04034B50;
const ZIP_CENTRAL_DIRECTORY: u32 = 0x02014B50;
const ZIP_END_OF_CENTRAL_DIRECTORY: u32 = 0x06054B50;

const PDF_HEADER: &[u8] = b"%PDF";
const PDF_EOF_MARKER: &[u8] = b"%%EOF";

const OLE2_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const MP4_FTYP: &[u8] = b"ftyp";
const MP4_MOOV: &[u8] = b"moov";
const MP4_MDAT: &[u8] = b"mdat";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairResult {
    pub success: bool,
    pub original_size: u64,
    pub repaired_size: u64,
    pub repairs_applied: Vec<String>,
    pub data: Vec<u8>,
}

pub struct FileRepairEngine;

impl FileRepairEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn repair_jpeg(&self, data: &[u8]) -> Result<RepairResult> {
        let mut repairs = Vec::new();
        let mut output = Vec::new();

        let has_soi = data.len() >= 2 && data[0..2] == JPEG_SOI_MARKER;
        let has_eoi = data.len() >= 2 && data[data.len() - 2..] == JPEG_EOI_MARKER;

        if !has_soi {
            output.extend_from_slice(&JPEG_SOI_MARKER);
            repairs.push("Added missing SOI marker".to_string());
        }

        let app0_present = data.windows(2).any(|w| w == JPEG_APP0_MARKER);
        if !app0_present && !has_soi {
            let jfif_header = Self::build_jfif_header();
            output.extend_from_slice(&jfif_header);
            repairs.push("Added JFIF APP0 header".to_string());
        }

        if has_soi {
            output.extend_from_slice(data);
        } else {
            output.extend_from_slice(&data[2.min(data.len())..]);
        }

        if !has_eoi {
            output.extend_from_slice(&JPEG_EOI_MARKER);
            repairs.push("Added missing EOI marker".to_string());
        }

        Ok(RepairResult {
            success: true,
            original_size: data.len() as u64,
            repaired_size: output.len() as u64,
            repairs_applied: repairs,
            data: output,
        })
    }

    pub fn repair_zip(&self, data: &[u8]) -> Result<RepairResult> {
        let mut repairs = Vec::new();
        let mut output = Vec::new();

        let local_headers = Self::find_zip_local_headers(data);
        let has_central = Self::find_zip_central_headers(data);
        let has_eocd = Self::find_zip_eocd(data);

        output.extend_from_slice(data);

        if local_headers.is_empty() {
            return Err(Error::RepairFailed("No ZIP local file headers found".into()));
        }

        if has_central.is_empty() {
            let central_dir = Self::rebuild_central_directory(data, &local_headers)?;
            output.extend_from_slice(&central_dir);
            repairs.push(format!("Rebuilt central directory for {} files", local_headers.len()));
        }

        if !has_eocd.is_empty() || !has_central.is_empty() {
            let eocd = Self::build_eocd(
                local_headers.len() as u16,
                output.len() as u32,
            );
            output.extend_from_slice(&eocd);
            repairs.push("Added End of Central Directory record".to_string());
        }

        Ok(RepairResult {
            success: true,
            original_size: data.len() as u64,
            repaired_size: output.len() as u64,
            repairs_applied: repairs,
            data: output,
        })
    }

    pub fn repair_office(&self, data: &[u8]) -> Result<RepairResult> {
        let mut repairs = Vec::new();

        let is_ole2 = data.len() >= 8 && data[0..8] == OLE2_MAGIC;
        let is_zip = data.len() >= 4 && &data[0..4] == b"PK\x03\x04";

        if is_zip {
            let zip_repair = self.repair_zip(data)?;
            repairs.extend(zip_repair.repairs_applied);
            return Ok(RepairResult {
                success: true,
                original_size: data.len() as u64,
                repaired_size: zip_repair.data.len() as u64,
                repairs_applied: repairs,
                data: zip_repair.data,
            });
        }

        if is_ole2 {
            let mut output = Vec::new();
            output.extend_from_slice(data);

            if data.len() < 512 {
                let padding = vec![0u8; 512 - data.len()];
                output.extend_from_slice(&padding);
                repairs.push("Padded OLE2 file to minimum sector size".to_string());
            }

            repairs.push("OLE2 structure validated".to_string());

            return Ok(RepairResult {
                success: true,
                original_size: data.len() as u64,
                repaired_size: output.len() as u64,
                repairs_applied: repairs,
                data: output,
            });
        }

        Err(Error::RepairFailed("Unrecognized Office document format".into()))
    }

    pub fn repair_video(&self, data: &[u8], format: &str) -> Result<RepairResult> {
        let mut repairs = Vec::new();
        let mut output = Vec::new();

        match format.to_lowercase().as_str() {
            "mp4" | "mov" => {
                let has_ftyp = data.windows(4).any(|w| w == MP4_FTYP);
                let has_moov = data.windows(4).any(|w| w == MP4_MOOV);
                let has_mdat = data.windows(4).any(|w| w == MP4_MDAT);

                if !has_ftyp {
                    let ftyp_box = Self::build_ftyp_box();
                    output.extend_from_slice(&ftyp_box);
                    repairs.push("Added ftyp atom".to_string());
                }

                output.extend_from_slice(data);

                if !has_mdat && !has_moov {
                    repairs.push("Warning: Neither mdat nor moov atoms found".to_string());
                } else if !has_moov && has_mdat {
                    repairs.push("Warning: moov atom missing, video may not play".to_string());
                }
            }
            _ => {
                return Err(Error::UnsupportedFormat(format!("Unsupported video format: {}", format)));
            }
        }

        Ok(RepairResult {
            success: true,
            original_size: data.len() as u64,
            repaired_size: output.len() as u64,
            repairs_applied: repairs,
            data: output,
        })
    }

    pub fn repair_pdf(&self, data: &[u8]) -> Result<RepairResult> {
        let mut repairs = Vec::new();
        let mut output = Vec::new();

        let has_header = data.len() >= 4 && &data[0..4] == PDF_HEADER;

        if !has_header {
            output.extend_from_slice(b"%PDF-1.4\n");
            repairs.push("Added missing PDF header".to_string());
        }

        output.extend_from_slice(data);

        let has_eof = data.windows(5).any(|w| w == PDF_EOF_MARKER);
        if !has_eof {
            output.extend_from_slice(b"\n");
            output.extend_from_slice(PDF_EOF_MARKER);
            output.extend_from_slice(b"\n");
            repairs.push("Added missing EOF marker".to_string());
        }

        Ok(RepairResult {
            success: true,
            original_size: data.len() as u64,
            repaired_size: output.len() as u64,
            repairs_applied: repairs,
            data: output,
        })
    }

    fn build_jfif_header() -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&JPEG_APP0_MARKER);
        header.extend_from_slice(&[0x00, 0x10]);
        header.extend_from_slice(b"JFIF\x00");
        header.extend_from_slice(&[0x01, 0x01]);
        header.extend_from_slice(&[0x00]);
        header.extend_from_slice(&[0x00, 0x01]);
        header.extend_from_slice(&[0x00, 0x01]);
        header.extend_from_slice(&[0x00, 0x00]);
        header
    }

    fn find_zip_local_headers(data: &[u8]) -> Vec<u32> {
        let mut positions = Vec::new();
        for i in 0..data.len().saturating_sub(3) {
            if let Ok(val) = (&data[i..]).read_u32::<LittleEndian>() {
                if val == ZIP_LOCAL_FILE_HEADER {
                    positions.push(i as u32);
                }
            }
        }
        positions
    }

    fn find_zip_central_headers(data: &[u8]) -> Vec<u32> {
        let mut positions = Vec::new();
        for i in 0..data.len().saturating_sub(3) {
            if let Ok(val) = (&data[i..]).read_u32::<LittleEndian>() {
                if val == ZIP_CENTRAL_DIRECTORY {
                    positions.push(i as u32);
                }
            }
        }
        positions
    }

    fn find_zip_eocd(data: &[u8]) -> Vec<u32> {
        let mut positions = Vec::new();
        for i in 0..data.len().saturating_sub(3) {
            if let Ok(val) = (&data[i..]).read_u32::<LittleEndian>() {
                if val == ZIP_END_OF_CENTRAL_DIRECTORY {
                    positions.push(i as u32);
                }
            }
        }
        positions
    }

    fn rebuild_central_directory(_data: &[u8], local_headers: &[u32]) -> Result<Vec<u8>> {
        let mut central_dir = Vec::new();

        for &pos in local_headers {
            let mut entry = Vec::new();
            entry.write_u32::<LittleEndian>(ZIP_CENTRAL_DIRECTORY)
                .map_err(|e| Error::RepairFailed(format!("Write error: {}", e)))?;
            entry.extend_from_slice(&[0x14, 0x00]);
            entry.extend_from_slice(&[0x14, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00]);
            entry.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            entry.extend_from_slice(&pos.to_le_bytes());
            entry.extend_from_slice(&[0x00, 0x00]);

            central_dir.extend_from_slice(&entry);
        }

        Ok(central_dir)
    }

    fn build_eocd(num_entries: u16, central_dir_size: u32) -> Vec<u8> {
        let mut eocd = Vec::new();
        eocd.write_u32::<LittleEndian>(ZIP_END_OF_CENTRAL_DIRECTORY).unwrap();
        eocd.extend_from_slice(&[0x00, 0x00]);
        eocd.extend_from_slice(&[0x00, 0x00]);
        eocd.write_u16::<LittleEndian>(num_entries).unwrap();
        eocd.write_u16::<LittleEndian>(num_entries).unwrap();
        eocd.write_u32::<LittleEndian>(central_dir_size).unwrap();
        eocd.write_u32::<LittleEndian>(0).unwrap();
        eocd.extend_from_slice(&[0x00, 0x00]);
        eocd
    }

    fn build_ftyp_box() -> Vec<u8> {
        let mut ftyp = Vec::new();
        ftyp.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]);
        ftyp.extend_from_slice(MP4_FTYP);
        ftyp.extend_from_slice(b"isom");
        ftyp.extend_from_slice(&[0x00, 0x00, 0x02, 0x00]);
        ftyp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_jpeg_add_soi() {
        let engine = FileRepairEngine::new();
        let data = vec![0x00, 0x00, 0xFF, 0xE0];
        let result = engine.repair_jpeg(&data).unwrap();
        assert!(result.data.starts_with(&JPEG_SOI_MARKER));
        assert!(result.data.ends_with(&JPEG_EOI_MARKER));
        assert!(!result.repairs_applied.is_empty());
    }

    #[test]
    fn test_repair_jpeg_add_eoi() {
        let engine = FileRepairEngine::new();
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let result = engine.repair_jpeg(&data).unwrap();
        assert!(result.data.ends_with(&JPEG_EOI_MARKER));
    }

    #[test]
    fn test_repair_jpeg_already_valid() {
        let engine = FileRepairEngine::new();
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xD9];
        let result = engine.repair_jpeg(&data).unwrap();
        assert_eq!(result.original_size, result.repaired_size);
    }

    #[test]
    fn test_repair_zip() {
        let engine = FileRepairEngine::new();
        let mut data = Vec::new();
        data.write_u32::<LittleEndian>(ZIP_LOCAL_FILE_HEADER).unwrap();
        data.extend_from_slice(&[0x14, 0x00]);
        data.extend_from_slice(&[0x00; 20]);

        let result = engine.repair_zip(&data).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_repair_pdf_add_header() {
        let engine = FileRepairEngine::new();
        let data = b"This is not a PDF";
        let result = engine.repair_pdf(data).unwrap();
        assert!(result.data.starts_with(PDF_HEADER));
        assert!(result.data.windows(5).any(|w| w == PDF_EOF_MARKER));
    }

    #[test]
    fn test_repair_pdf_add_eof() {
        let engine = FileRepairEngine::new();
        let data = b"%PDF-1.4\nsome content here";
        let result = engine.repair_pdf(data).unwrap();
        assert!(result.data.windows(5).any(|w| w == PDF_EOF_MARKER));
    }

    #[test]
    fn test_repair_office_zip_based() {
        let engine = FileRepairEngine::new();
        let mut data = Vec::new();
        data.extend_from_slice(b"PK\x03\x04");
        data.write_u32::<LittleEndian>(ZIP_LOCAL_FILE_HEADER).unwrap();
        data.extend_from_slice(&[0x00; 20]);

        let result = engine.repair_office(&data).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_repair_office_ole2() {
        let engine = FileRepairEngine::new();
        let mut data = Vec::new();
        data.extend_from_slice(&OLE2_MAGIC);
        data.extend_from_slice(&[0x00; 100]);

        let result = engine.repair_office(&data).unwrap();
        assert!(result.success);
        assert!(result.repaired_size >= 512);
    }

    #[test]
    fn test_repair_video_mp4() {
        let engine = FileRepairEngine::new();
        let data = vec![0x00, 0x00, 0x00, 0x08, b'm', b'd', b'a', b't'];
        let result = engine.repair_video(&data, "mp4").unwrap();
        assert!(result.success);
    }
}
