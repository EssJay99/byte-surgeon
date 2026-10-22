use crate::{Result, Error};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HexDump {
    pub offset: u64,
    pub data: Vec<u8>,
    pub formatted_output: String,
}

pub struct HexViewer {
    bytes_per_line: usize,
}

impl HexViewer {
    pub fn new() -> Self {
        Self {
            bytes_per_line: 16,
        }
    }

    pub fn with_bytes_per_line(mut self, n: usize) -> Self {
        if n > 0 && n <= 64 {
            self.bytes_per_line = n;
        }
        self
    }

    pub fn read_hex(&self, source: &Path, offset: u64, length: usize) -> Result<HexDump> {
        if length == 0 {
            return Err(Error::Other("Length must be greater than 0".to_string()));
        }

        let mut file = File::open(source)?;
        let file_size = file.metadata()?.len();

        if offset >= file_size {
            return Err(Error::Other(format!(
                "Offset {} is beyond file size {}",
                offset, file_size
            )));
        }

        file.seek(SeekFrom::Start(offset))?;
        let remaining = (file_size - offset) as usize;
        let actual_len = std::cmp::min(length, remaining);
        let mut data = vec![0u8; actual_len];
        file.read_exact(&mut data)?;

        let formatted = self.format_hex_dump(&data, offset);

        debug!("Read {} bytes from offset {} in {}", actual_len, offset, source.display());

        Ok(HexDump {
            offset,
            data,
            formatted_output: formatted,
        })
    }

    pub fn read_hex_from_bytes(&self, data: &[u8], base_offset: u64) -> HexDump {
        let formatted = self.format_hex_dump(data, base_offset);
        HexDump {
            offset: base_offset,
            data: data.to_vec(),
            formatted_output: formatted,
        }
    }

    pub fn format_hex_dump(&self, data: &[u8], base_offset: u64) -> String {
        let mut output = String::new();
        let bpl = self.bytes_per_line;
        let hex_width = bpl * 3;
        let offset_width = 8;

        let offset_digits = {
            let end = base_offset + data.len() as u64;
            let mut d = 8;
            if end > 0xFFFF_FFFF {
                d = 16;
            }
            d
        };

        for (i, chunk) in data.chunks(bpl).enumerate() {
            let line_offset = base_offset + (i * bpl) as u64;

            let hex_part: String = chunk
                .iter()
                .enumerate()
                .map(|(j, &b)| {
                    let s = format!("{:02X} ", b);
                    if j == bpl / 2 - 1 {
                        format!("{} ", s)
                    } else {
                        s
                    }
                })
                .collect();

            let padding_needed = if bpl / 2 > 0 { hex_width + 1 } else { hex_width };
            let padded_hex = format!("{:<width$}", hex_part, width = padding_needed);

            let ascii_part: String = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();

            let _ = offset_width;

            output.push_str(&format!(
                "{:0>offset_digits$X}  {} |{}|\n",
                line_offset, padded_hex.trim_end(), ascii_part,
                offset_digits = offset_digits
            ));
        }

        output
    }

    pub fn format_compact_hex(&self, data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
    }

    pub fn search_bytes(source: &Path, pattern: &[u8], max_results: usize) -> Result<Vec<u64>> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }

        let mut file = File::open(source)?;
        let file_size = file.metadata()?.len();
        let chunk_size = 1024 * 1024;
        let mut buffer = vec![0u8; chunk_size + pattern.len()];
        let mut results = Vec::new();
        let mut position = 0u64;

        while position < file_size && results.len() < max_results {
            file.seek(SeekFrom::Start(position))?;
            let read_len = std::cmp::min(
                (file_size - position) as usize,
                buffer.len(),
            );
            let bytes_read = file.read(&mut buffer[..read_len])?;

            if bytes_read < pattern.len() {
                break;
            }

            let search_end = bytes_read - pattern.len() + 1;
            for i in 0..search_end {
                if buffer[i..i + pattern.len()] == *pattern {
                    results.push(position + i as u64);
                    if results.len() >= max_results {
                        break;
                    }
                }
            }

            let advance = if bytes_read >= pattern.len() {
                bytes_read - pattern.len() + 1
            } else {
                break;
            };
            position += advance as u64;
        }

        Ok(results)
    }
}

impl Default for HexViewer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_hex_viewer_creation() {
        let v = HexViewer::new();
        assert_eq!(v.bytes_per_line, 16);
    }

    #[test]
    fn test_with_bytes_per_line() {
        let v = HexViewer::new().with_bytes_per_line(32);
        assert_eq!(v.bytes_per_line, 32);
    }

    #[test]
    fn test_with_bytes_per_line_invalid() {
        let v = HexViewer::new().with_bytes_per_line(0);
        assert_eq!(v.bytes_per_line, 16);
        let v = HexViewer::new().with_bytes_per_line(100);
        assert_eq!(v.bytes_per_line, 16);
    }

    #[test]
    fn test_default() {
        let v = HexViewer::default();
        assert_eq!(v.bytes_per_line, 16);
    }

    #[test]
    fn test_format_hex_dump() {
        let v = HexViewer::new();
        let data = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F,
        ];
        let output = v.format_hex_dump(&data, 0);

        assert!(output.contains("00 01 02 03"));
        assert!(output.contains("|Hello Wo|"));
        assert!(output.contains("00000000"));
    }

    #[test]
    fn test_format_hex_dump_with_offset() {
        let v = HexViewer::new();
        let data = vec![0x41, 0x42, 0x43, 0x44];
        let output = v.format_hex_dump(&data, 0x1000);
        assert!(output.contains("00001000"));
        assert!(output.contains("|ABCD|"));
    }

    #[test]
    fn test_format_hex_dump_non_printable() {
        let v = HexViewer::new();
        let data = vec![0x00, 0x01, 0x7F, 0xFF];
        let output = v.format_hex_dump(&data, 0);
        assert!(output.contains("|....|"));
    }

    #[test]
    fn test_read_hex_from_bytes() {
        let v = HexViewer::new();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let dump = v.read_hex_from_bytes(&data, 0);
        assert_eq!(dump.offset, 0);
        assert_eq!(dump.data, data);
        assert!(!dump.formatted_output.is_empty());
        assert!(dump.formatted_output.contains("DE AD BE EF"));
    }

    #[test]
    fn test_read_hex_from_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        std::fs::write(&path, &data).unwrap();

        let v = HexViewer::new();
        let dump = v.read_hex(&path, 0, 5).unwrap();
        assert_eq!(dump.offset, 0);
        assert_eq!(dump.data, data);
    }

    #[test]
    fn test_read_hex_with_offset() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        std::fs::write(&path, &data).unwrap();

        let v = HexViewer::new();
        let dump = v.read_hex(&path, 4, 4).unwrap();
        assert_eq!(dump.offset, 4);
        assert_eq!(dump.data, vec![0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn test_read_hex_beyond_file_size() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, &[0x00; 10]).unwrap();

        let v = HexViewer::new();
        let result = v.read_hex(&path, 100, 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_hex_zero_length() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, &[0x00; 10]).unwrap();

        let v = HexViewer::new();
        let result = v.read_hex(&path, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        let data = vec![0x00, 0xAA, 0xBB, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB];
        std::fs::write(&path, &data).unwrap();

        let results = HexViewer::search_bytes(&path, &[0xAA, 0xBB], 10).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], 1);
        assert_eq!(results[1], 4);
        assert_eq!(results[2], 8);
    }

    #[test]
    fn test_search_bytes_max_results() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        let data = vec![0xFF, 0xAA, 0xFF, 0xAA, 0xFF, 0xAA, 0xFF];
        std::fs::write(&path, &data).unwrap();

        let results = HexViewer::search_bytes(&path, &[0xAA], 2).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_bytes_empty_pattern() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, &[0x00; 10]).unwrap();

        let results = HexViewer::search_bytes(&path, &[], 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_format_compact_hex() {
        let v = HexViewer::new();
        let result = v.format_compact_hex(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(result, "DE AD BE EF");
    }

    #[test]
    fn test_format_multiple_lines() {
        let v = HexViewer::new();
        let data = vec![0x41; 32];
        let output = v.format_hex_dump(&data, 0);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00000000"));
        assert!(lines[1].starts_with("00000010"));
    }
}
