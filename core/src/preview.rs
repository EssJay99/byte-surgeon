use crate::{Result, Error};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewData {
    pub file_type: String,
    pub mime_type: String,
    pub preview_bytes: Vec<u8>,
    pub thumbnail_data: Option<Vec<u8>>,
    pub text_content: Option<String>,
}

pub struct FilePreviewer {
    max_preview_bytes: usize,
}

impl FilePreviewer {
    pub fn new() -> Self {
        Self {
            max_preview_bytes: 8192,
        }
    }

    pub fn with_max_preview_bytes(mut self, size: usize) -> Self {
        self.max_preview_bytes = size;
        self
    }

    pub fn generate_preview(&self, file_path: &Path, extension: &str) -> Result<PreviewData> {
        if !file_path.exists() {
            return Err(Error::Other(format!("File not found: {}", file_path.display())));
        }

        let ext_lower = extension.to_lowercase();
        let mime = self.mime_for_extension(&ext_lower);
        let category = self.category_for_extension(&ext_lower);

        match category.as_str() {
            "image" => self.preview_image(file_path, &ext_lower, &mime),
            "document" | "text" => self.preview_document(file_path, &ext_lower, &mime),
            "archive" => self.preview_archive(file_path, &ext_lower, &mime),
            "audio" | "video" => self.preview_media(file_path, &ext_lower, &mime),
            _ => self.preview_generic(file_path, &mime),
        }
    }

    fn preview_image(&self, path: &Path, ext: &str, mime: &str) -> Result<PreviewData> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let read_len = std::cmp::min(file_size, self.max_preview_bytes);
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf)?;

        let thumb = if matches!(ext, "jpg" | "jpeg" | "png" | "gif" | "bmp") {
            let thumb_len = std::cmp::min(read_len, 4096);
            Some(buf[..thumb_len].to_vec())
        } else {
            None
        };

        debug!("Generated image preview for {} ({} bytes)", path.display(), read_len);

        Ok(PreviewData {
            file_type: ext.to_string(),
            mime_type: mime.to_string(),
            preview_bytes: buf,
            thumbnail_data: thumb,
            text_content: None,
        })
    }

    fn preview_document(&self, path: &Path, ext: &str, mime: &str) -> Result<PreviewData> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let read_len = std::cmp::min(file_size, self.max_preview_bytes);
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf)?;

        let text = match ext {
            "txt" | "csv" | "rtf" | "log" | "cfg" | "ini" | "json" | "xml" | "html" | "htm" | "md" | "yaml" | "yml" | "toml" | "sh" | "bat" | "py" | "js" | "ts" | "rs" | "c" | "cpp" | "h" | "java" | "sql" | "css" => {
                Some(String::from_utf8_lossy(&buf).into_owned())
            }
            "pdf" => self.extract_pdf_text(&buf),
            "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" => {
                self.extract_zip_text(&buf)
            }
            _ => self.try_extract_text(&buf),
        };

        Ok(PreviewData {
            file_type: ext.to_string(),
            mime_type: mime.to_string(),
            preview_bytes: buf,
            thumbnail_data: None,
            text_content: text,
        })
    }

    fn preview_archive(&self, path: &Path, ext: &str, mime: &str) -> Result<PreviewData> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let read_len = std::cmp::min(file_size, self.max_preview_bytes);
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf)?;

        let listing = match ext {
            "zip" | "jar" | "apk" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub" => {
                self.list_zip_contents(&buf)
            }
            "tar" => self.list_tar_contents(&buf),
            _ => None,
        };

        Ok(PreviewData {
            file_type: ext.to_string(),
            mime_type: mime.to_string(),
            preview_bytes: buf,
            thumbnail_data: None,
            text_content: listing,
        })
    }

    fn preview_media(&self, path: &Path, ext: &str, mime: &str) -> Result<PreviewData> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let read_len = std::cmp::min(file_size, self.max_preview_bytes);
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf)?;

        let metadata_text = self.extract_media_metadata(&buf, ext);

        Ok(PreviewData {
            file_type: ext.to_string(),
            mime_type: mime.to_string(),
            preview_bytes: buf,
            thumbnail_data: None,
            text_content: Some(metadata_text),
        })
    }

    fn preview_generic(&self, path: &Path, mime: &str) -> Result<PreviewData> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len() as usize;
        let read_len = std::cmp::min(file_size, self.max_preview_bytes);
        let mut buf = vec![0u8; read_len];
        file.read_exact(&mut buf)?;

        let text = self.try_extract_text(&buf);

        Ok(PreviewData {
            file_type: "unknown".to_string(),
            mime_type: mime.to_string(),
            preview_bytes: buf,
            thumbnail_data: None,
            text_content: text,
        })
    }

    fn extract_pdf_text(&self, data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        let mut extracted = String::new();
        let mut in_text_object = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("BT") {
                in_text_object = true;
                continue;
            }
            if trimmed.starts_with("ET") {
                in_text_object = false;
                continue;
            }
            if in_text_object {
                if let Some(start) = trimmed.find('(') {
                    if let Some(end) = trimmed[start + 1..].find(')') {
                        extracted.push_str(&trimmed[start + 1..start + 1 + end]);
                        extracted.push(' ');
                    }
                }
                if let Some(start) = trimmed.find("<") {
                    if let Some(end) = trimmed[start + 1..].find(">") {
                        let hex_str = &trimmed[start + 1..start + 1 + end];
                        if hex_str.len() % 2 == 0 {
                            for chunk in hex_str.as_bytes().chunks(2) {
                                let hi = chunk[0];
                                let lo = chunk[1];
                                let byte = (hex_val(hi) << 4) | hex_val(lo);
                                if byte.is_ascii_graphic() || byte == b' ' {
                                    extracted.push(byte as char);
                                }
                            }
                            extracted.push(' ');
                        }
                    }
                }
            }
        }

        if extracted.trim().is_empty() {
            None
        } else {
            Some(extracted.trim().to_string())
        }
    }

    fn extract_zip_text(&self, data: &[u8]) -> Option<String> {
        self.list_zip_contents(data)
    }

    fn list_zip_contents(&self, data: &[u8]) -> Option<String> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos + 30 <= data.len() {
            if data[pos] == 0x50 && data[pos + 1] == 0x4B && data[pos + 2] == 0x03 && data[pos + 3] == 0x04 {
                if pos + 30 > data.len() {
                    break;
                }
                let comp_method = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
                let comp_size = u32::from_le_bytes([data[pos + 18], data[pos + 19], data[pos + 20], data[pos + 21]]) as usize;
                let uncomp_size = u32::from_le_bytes([data[pos + 22], data[pos + 23], data[pos + 24], data[pos + 25]]) as usize;
                let name_len = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
                let extra_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;

                let name_start = pos + 30;
                let name_end = name_start + name_len;

                if name_end > data.len() {
                    break;
                }

                let name = String::from_utf8_lossy(&data[name_start..name_end]).to_string();

                entries.push(format!("{} ({} bytes, method {})", name, uncomp_size, comp_method));

                pos = name_end + extra_len + comp_size;
            } else if data[pos] == 0x50 && data[pos + 1] == 0x4B && data[pos + 2] == 0x01 && data[pos + 3] == 0x02 {
                break;
            } else if data[pos] == 0x50 && data[pos + 1] == 0x4B && data[pos + 2] == 0x05 && data[pos + 3] == 0x06 {
                break;
            } else {
                pos += 1;
            }
        }

        if entries.is_empty() {
            None
        } else {
            Some(entries.join("\n"))
        }
    }

    fn list_tar_contents(&self, data: &[u8]) -> Option<String> {
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos + 512 <= data.len() {
            let header = &data[pos..pos + 512];
            let mut all_zero = true;
            for &b in header {
                if b != 0 {
                    all_zero = false;
                    break;
                }
            }
            if all_zero {
                break;
            }

            let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
            let name = String::from_utf8_lossy(&header[..name_end]).to_string();

            if name.is_empty() {
                break;
            }

            let size_str = &header[124..135];
            let size_end = size_str.iter().position(|&b| b == 0 || b == b' ').unwrap_or(11);
            let size_str = String::from_utf8_lossy(&size_str[..size_end]).trim().to_string();
            let size = u64::from_str_radix(&size_str, 8).unwrap_or(0);

            entries.push(format!("{} ({} bytes)", name, size));

            let blocks = (size as usize + 511) / 512;
            pos += 512 + blocks * 512;
        }

        if entries.is_empty() {
            None
        } else {
            Some(entries.join("\n"))
        }
    }

    fn extract_media_metadata(&self, data: &[u8], ext: &str) -> String {
        let mut info = Vec::new();

        match ext {
            "mp3" => {
                if data.len() >= 3 && data[0] == 0x49 && data[1] == 0x44 && data[2] == 0x33 {
                    let major = data[3];
                    let minor = data[4];
                    info.push(format!("ID3v2.{}.{}", major, minor));
                    self.parse_id3_tags(data, &mut info);
                } else if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
                    let bitrate_idx = (data[2] >> 4) & 0x0F;
                    let sample_idx = (data[2] >> 2) & 0x03;
                    let bitrates_v1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
                    let samples = [44100, 48000, 32000, 0];
                    if (bitrate_idx as usize) < bitrates_v1.len() {
                        info.push(format!("Bitrate: {} kbps", bitrates_v1[bitrate_idx as usize]));
                    }
                    if (sample_idx as usize) < samples.len() {
                        info.push(format!("Sample rate: {} Hz", samples[sample_idx as usize]));
                    }
                }
            }
            "wav" => {
                if data.len() >= 44 {
                    let fmt_tag = u16::from_le_bytes([data[20], data[21]]);
                    let channels = u16::from_le_bytes([data[22], data[23]]);
                    let sample_rate = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
                    let bits_per_sample = u16::from_le_bytes([data[34], data[35]]);
                    let format_name = match fmt_tag {
                        1 => "PCM",
                        3 => "IEEE Float",
                        6 => "A-law",
                        7 => "Mu-law",
                        _ => "Unknown",
                    };
                    info.push(format!("Format: {}", format_name));
                    info.push(format!("Channels: {}", channels));
                    info.push(format!("Sample rate: {} Hz", sample_rate));
                    info.push(format!("Bits per sample: {}", bits_per_sample));
                }
            }
            "flac" => {
                if data.len() >= 18 && &data[0..4] == b"fLaC" {
                    info.push("Codec: FLAC".to_string());
                    if data.len() >= 18 {
                        let sample_rate = ((data[10] as u32) << 12) | ((data[11] as u32) << 4) | ((data[12] as u32) >> 4);
                        let channels = ((data[12] >> 1) & 0x07) + 1;
                        let bits_per_sample = ((data[12] & 0x01) << 4 | (data[13] >> 4)) + 1;
                        info.push(format!("Sample rate: {} Hz", sample_rate));
                        info.push(format!("Channels: {}", channels));
                        info.push(format!("Bits per sample: {}", bits_per_sample));
                    }
                }
            }
            "ogg" => {
                if data.len() >= 4 && &data[0..4] == b"OggS" {
                    info.push("Container: Ogg".to_string());
                    if data.len() >= 35 {
                        let codec_header = String::from_utf8_lossy(&data[28..]);
                        if codec_header.starts_with("vorbis") {
                            info.push("Codec: Vorbis".to_string());
                        } else if codec_header.starts_with("OpusHead") {
                            info.push("Codec: Opus".to_string());
                        } else if codec_header.starts_with("FLAC") {
                            info.push("Codec: FLAC (in Ogg)".to_string());
                        }
                    }
                }
            }
            "mp4" | "mov" | "m4a" | "3gp" => {
                self.parse_isobmff_boxes(data, &mut info);
            }
            "avi" => {
                if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"AVI " {
                    info.push("Container: AVI".to_string());
                }
            }
            "mkv" | "webm" => {
                if data.len() >= 4 && data[0] == 0x1A && data[1] == 0x45 && data[2] == 0xDF && data[3] == 0xA3 {
                    info.push("Container: Matroska/WebM".to_string());
                }
            }
            "flv" => {
                if data.len() >= 4 && &data[0..3] == b"FLV" {
                    let flags = data[3];
                    info.push("Container: FLV".to_string());
                    info.push(format!("Has audio: {}", (flags & 0x04) != 0));
                    info.push(format!("Has video: {}", (flags & 0x01) != 0));
                }
            }
            "wmv" | "wma" | "asf" => {
                if data.len() >= 16 && data[0] == 0x30 && data[1] == 0x26 && data[2] == 0xB2 && data[3] == 0x75 {
                    info.push("Container: ASF/WMV".to_string());
                }
            }
            "aiff" | "aif" => {
                if data.len() >= 12 && &data[0..4] == b"FORM" {
                    let channels = u16::from_be_bytes([data[21], data[22]]);
                    let num_frames = u32::from_be_bytes([data[23], data[24], data[25], data[26]]);
                    let bits_per_sample = u16::from_be_bytes([data[27], data[28]]);
                    info.push("Format: AIFF".to_string());
                    info.push(format!("Channels: {}", channels));
                    info.push(format!("Frames: {}", num_frames));
                    info.push(format!("Bits per sample: {}", bits_per_sample));
                }
            }
            _ => {
                info.push(format!("Format: {}", ext.to_uppercase()));
                let hex_preview: Vec<String> = data[..std::cmp::min(32, data.len())].iter().map(|b| format!("{:02X}", b)).collect();
                info.push(format!("Header: {}", hex_preview.join(" ")));
            }
        }

        if info.is_empty() {
            format!("Format: {}", ext.to_uppercase())
        } else {
            info.join("\n")
        }
    }

    fn parse_id3_tags(&self, data: &[u8], info: &mut Vec<String>) {
        if data.len() < 10 {
            return;
        }
        let size = ((data[6] as usize) << 21)
            | ((data[7] as usize) << 14)
            | ((data[8] as usize) << 7)
            | (data[9] as usize);

        let tag_end = std::cmp::min(10 + size, data.len());
        let mut pos = 10;

        while pos + 10 <= tag_end {
            let frame_id = &data[pos..pos + 4];
            if frame_id[0] == 0 {
                break;
            }
            let frame_size = ((data[pos + 4] as usize) << 24)
                | ((data[pos + 5] as usize) << 16)
                | ((data[pos + 6] as usize) << 8)
                | (data[pos + 7] as usize);

            let frame_name = String::from_utf8_lossy(frame_id).to_string();
            let data_start = pos + 10;
            let data_end = std::cmp::min(data_start + frame_size, tag_end);

            if data_start + 1 < data_end {
                let encoding = data[data_start];
                let text_start = data_start + 1;
                if text_start < data_end {
                    let text_bytes = &data[text_start..data_end];
                    let text = if encoding == 0 || encoding == 3 {
                        String::from_utf8_lossy(text_bytes).trim_end_matches('\0').to_string()
                    } else if encoding == 1 && text_bytes.len() >= 2 {
                        let mut s = String::new();
                        for chunk in text_bytes.chunks(2) {
                            if chunk.len() == 2 {
                                let c = u16::from_le_bytes([chunk[0], chunk[1]]);
                                if c == 0 {
                                    break;
                                }
                                if let Some(ch) = char::from_u32(c as u32) {
                                    s.push(ch);
                                }
                            }
                        }
                        s
                    } else {
                        String::from_utf8_lossy(text_bytes).trim_end_matches('\0').to_string()
                    };

                    let tag_desc = match frame_name.as_str() {
                        "TIT2" => "Title",
                        "TPE1" => "Artist",
                        "TALB" => "Album",
                        "TRCK" => "Track",
                        "TYER" | "TDRC" => "Year",
                        "TCON" => "Genre",
                        _ => "",
                    };
                    if !tag_desc.is_empty() && !text.is_empty() {
                        info.push(format!("{}: {}", tag_desc, text));
                    }
                }
            }

            pos = data_end;
        }
    }

    fn parse_isobmff_boxes(&self, data: &[u8], info: &mut Vec<String>) {
        let mut pos = 0;
        let mut depth = 0;
        let max_depth = 4;

        while pos + 8 <= data.len() && depth < max_depth {
            let size = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
            let box_type = String::from_utf8_lossy(&data[pos + 4..pos + 8]).to_string();

            match box_type.as_str() {
                "ftyp" => {
                    let brand = if pos + 12 <= data.len() {
                        String::from_utf8_lossy(&data[pos + 8..pos + 12]).to_string()
                    } else {
                        "unknown".to_string()
                    };
                    info.push(format!("Brand: {}", brand));
                    match brand.as_str() {
                        "isom" | "iso2" | "iso5" | "iso6" | "mp41" | "mp42" => info.push("Container: MP4".to_string()),
                        "qt  " => info.push("Container: QuickTime".to_string()),
                        "M4A " => info.push("Container: M4A Audio".to_string()),
                        "3gp4" | "3gp5" | "3gp6" => info.push("Container: 3GP".to_string()),
                        _ => {}
                    }
                }
                "moov" | "trak" | "mdia" | "minf" | "stbl" | "udta" | "meta" => {
                    pos += 8;
                    depth += 1;
                    continue;
                }
                _ => {}
            }

            if size == 0 {
                break;
            }
            if size == 1 {
                if pos + 16 > data.len() {
                    break;
                }
                let large_size = u64::from_be_bytes([
                    data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11],
                    data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15],
                ]) as usize;
                if large_size == 0 || pos + large_size > data.len() {
                    break;
                }
                pos += large_size;
            } else {
                if pos + size > data.len() {
                    break;
                }
                pos += size;
            }
        }
    }

    fn try_extract_text(&self, data: &[u8]) -> Option<String> {
        let mut printable = 0;
        let mut total = 0;
        let check_len = std::cmp::min(data.len(), 512);

        for &b in &data[..check_len] {
            total += 1;
            if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                printable += 1;
            }
        }

        if total > 0 && (printable as f64 / total as f64) > 0.8 {
            Some(String::from_utf8_lossy(&data[..std::cmp::min(data.len(), 4096)]).into_owned())
        } else {
            None
        }
    }

    fn mime_for_extension(&self, ext: &str) -> String {
        match ext {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "bmp" => "image/bmp",
            "tiff" | "tif" => "image/tiff",
            "psd" => "image/vnd.adobe.photoshop",
            "svg" => "image/svg+xml",
            "webp" => "image/webp",
            "heic" | "heif" => "image/heic",
            "ico" => "image/x-icon",
            "pdf" => "application/pdf",
            "doc" => "application/msword",
            "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "xls" => "application/vnd.ms-excel",
            "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "ppt" => "application/vnd.ms-powerpoint",
            "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "odt" => "application/vnd.oasis.opendocument.text",
            "ods" => "application/vnd.oasis.opendocument.spreadsheet",
            "odp" => "application/vnd.oasis.opendocument.presentation",
            "rtf" => "application/rtf",
            "txt" | "log" | "cfg" | "ini" => "text/plain",
            "csv" => "text/csv",
            "html" | "htm" => "text/html",
            "xml" => "application/xml",
            "json" => "application/json",
            "md" => "text/markdown",
            "epub" => "application/epub+zip",
            "mp3" => "audio/mpeg",
            "wav" => "audio/wav",
            "flac" => "audio/flac",
            "ogg" | "oga" => "audio/ogg",
            "aac" => "audio/aac",
            "wma" => "audio/x-ms-wma",
            "aiff" | "aif" => "audio/aiff",
            "mid" | "midi" => "audio/midi",
            "m4a" => "audio/mp4",
            "opus" => "audio/opus",
            "mp4" => "video/mp4",
            "avi" => "video/x-msvideo",
            "mov" => "video/quicktime",
            "mkv" => "video/x-matroska",
            "wmv" => "video/x-ms-wmv",
            "flv" => "video/x-flv",
            "webm" => "video/webm",
            "mpg" | "mpeg" => "video/mpeg",
            "m2ts" | "mts" => "video/mp2t",
            "3gp" => "video/3gpp",
            "zip" => "application/zip",
            "rar" => "application/vnd.rar",
            "7z" => "application/x-7z-compressed",
            "tar" => "application/x-tar",
            "gz" => "application/gzip",
            "bz2" => "application/x-bzip2",
            "xz" => "application/x-xz",
            "cab" => "application/vnd.ms-cab-compressed",
            "iso" => "application/x-iso9660-image",
            "jar" => "application/java-archive",
            "apk" => "application/vnd.android.package-archive",
            "exe" | "dll" => "application/vnd.microsoft.portable-executable",
            "elf" | "so" => "application/x-executable",
            "ttf" => "font/ttf",
            "otf" => "font/otf",
            "woff" => "font/woff",
            "woff2" => "font/woff2",
            "sqlite" | "db" | "dbf" => "application/x-sqlite3",
            "pst" | "ost" => "application/vnd.ms-outlook",
            "eml" => "message/rfc822",
            _ => "application/octet-stream",
        }.to_string()
    }

    fn category_for_extension(&self, ext: &str) -> String {
        match ext {
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "tiff" | "tif" | "psd" | "ai" | "eps" |
            "svg" | "webp" | "heic" | "heif" | "ico" | "jp2" | "jxr" | "xcf" | "pcx" | "tga" |
            "wmf" | "cr2" | "nef" | "arw" | "dng" | "orf" | "rw2" | "pef" | "srw" | "raf" => "image".to_string(),
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" |
            "rtf" | "txt" | "csv" | "epub" | "mobi" | "log" | "md" | "html" | "htm" | "xml" |
            "json" | "cfg" | "ini" | "yaml" | "yml" | "toml" => "document".to_string(),
            "mp3" | "wav" | "flac" | "ogg" | "oga" | "aac" | "wma" | "aiff" | "aif" | "mid" |
            "midi" | "m4a" | "opus" | "amr" => "audio".to_string(),
            "mp4" | "avi" | "mov" | "mkv" | "wmv" | "flv" | "webm" | "mpg" | "mpeg" | "m2ts" |
            "mts" | "3gp" | "ogv" | "ts" => "video".to_string(),
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "lz" | "cab" | "iso" | "dmg" |
            "zst" | "lz4" | "arc" | "ace" => "archive".to_string(),
            _ => "other".to_string(),
        }
    }
}

impl Default for FilePreviewer {
    fn default() -> Self {
        Self::new()
    }
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_previewer_creation() {
        let p = FilePreviewer::new();
        assert_eq!(p.max_preview_bytes, 8192);
    }

    #[test]
    fn test_with_max_preview_bytes() {
        let p = FilePreviewer::new().with_max_preview_bytes(1024);
        assert_eq!(p.max_preview_bytes, 1024);
    }

    #[test]
    fn test_default() {
        let p = FilePreviewer::default();
        assert_eq!(p.max_preview_bytes, 8192);
    }

    #[test]
    fn test_mime_for_extension() {
        let p = FilePreviewer::new();
        assert_eq!(p.mime_for_extension("jpg"), "image/jpeg");
        assert_eq!(p.mime_for_extension("png"), "image/png");
        assert_eq!(p.mime_for_extension("pdf"), "application/pdf");
        assert_eq!(p.mime_for_extension("mp3"), "audio/mpeg");
        assert_eq!(p.mime_for_extension("mp4"), "video/mp4");
        assert_eq!(p.mime_for_extension("zip"), "application/zip");
        assert_eq!(p.mime_for_extension("unknown"), "application/octet-stream");
    }

    #[test]
    fn test_category_for_extension() {
        let p = FilePreviewer::new();
        assert_eq!(p.category_for_extension("jpg"), "image");
        assert_eq!(p.category_for_extension("pdf"), "document");
        assert_eq!(p.category_for_extension("mp3"), "audio");
        assert_eq!(p.category_for_extension("mp4"), "video");
        assert_eq!(p.category_for_extension("zip"), "archive");
        assert_eq!(p.category_for_extension("xyz"), "other");
    }

    #[test]
    fn test_preview_text_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "Hello, this is a test text file.").unwrap();

        let p = FilePreviewer::new();
        let preview = p.generate_preview(&path, "txt").unwrap();
        assert_eq!(preview.file_type, "txt");
        assert_eq!(preview.mime_type, "text/plain");
        assert!(preview.text_content.is_some());
        assert!(preview.text_content.unwrap().contains("Hello"));
    }

    #[test]
    fn test_preview_image_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jpg");
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        data.extend_from_slice(&[0x00; 200]);
        data.extend_from_slice(&[0xFF, 0xD9]);
        std::fs::write(&path, &data).unwrap();

        let p = FilePreviewer::new();
        let preview = p.generate_preview(&path, "jpg").unwrap();
        assert_eq!(preview.file_type, "jpg");
        assert_eq!(preview.mime_type, "image/jpeg");
        assert!(preview.thumbnail_data.is_some());
        assert!(preview.text_content.is_none());
    }

    #[test]
    fn test_preview_wav_metadata() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.wav");
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"RIFF");
        data[8..12].copy_from_slice(b"WAVE");
        data[12..16].copy_from_slice(b"fmt ");
        let fmt_size: u32 = 16;
        data[16..20].copy_from_slice(&fmt_size.to_le_bytes());
        data[20..22].copy_from_slice(&1u16.to_le_bytes());
        data[22..24].copy_from_slice(&2u16.to_le_bytes());
        data[24..28].copy_from_slice(&44100u32.to_le_bytes());
        data[34..36].copy_from_slice(&16u16.to_le_bytes());
        std::fs::write(&path, &data).unwrap();

        let p = FilePreviewer::new();
        let preview = p.generate_preview(&path, "wav").unwrap();
        assert!(preview.text_content.is_some());
        let text = preview.text_content.unwrap();
        assert!(text.contains("44100"));
        assert!(text.contains("PCM"));
    }

    #[test]
    fn test_preview_file_not_found() {
        let p = FilePreviewer::new();
        let result = p.generate_preview(Path::new("/nonexistent/file.txt"), "txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pdf_text() {
        let data = b"%PDF-1.4\nBT\n(Hello World)\nET\n%%EOF";
        let p = FilePreviewer::new();
        let text = p.extract_pdf_text(data);
        assert!(text.is_some());
        assert!(text.unwrap().contains("Hello World"));
    }

    #[test]
    fn test_try_extract_text_binary() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let p = FilePreviewer::new();
        let result = p.try_extract_text(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_extract_text_ascii() {
        let data = b"This is a perfectly normal ASCII text file with some content.";
        let p = FilePreviewer::new();
        let result = p.try_extract_text(data);
        assert!(result.is_some());
    }
}
