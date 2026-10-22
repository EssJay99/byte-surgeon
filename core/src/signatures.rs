use crate::FileSignature;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureCategory {
    Image,
    Document,
    Audio,
    Video,
    Archive,
    Database,
    Executable,
    Font,
    Cad,
    Model3D,
    Backup,
    Email,
    DiskImage,
    Compressed,
    Virtual,
    Certificate,
    Miscellaneous,
}

impl SignatureCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Image => "Image",
            Self::Document => "Document",
            Self::Audio => "Audio",
            Self::Video => "Video",
            Self::Archive => "Archive",
            Self::Database => "Database",
            Self::Executable => "Executable",
            Self::Font => "Font",
            Self::Cad => "CAD",
            Self::Model3D => "3D",
            Self::Backup => "Backup",
            Self::Email => "Email",
            Self::DiskImage => "DiskImage",
            Self::Compressed => "Compressed",
            Self::Virtual => "Virtual",
            Self::Certificate => "Certificate",
            Self::Miscellaneous => "Miscellaneous",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "image" => Self::Image,
            "document" => Self::Document,
            "audio" => Self::Audio,
            "video" => Self::Video,
            "archive" => Self::Archive,
            "database" => Self::Database,
            "executable" => Self::Executable,
            "font" => Self::Font,
            "cad" => Self::Cad,
            "3d" | "model" => Self::Model3D,
            "backup" => Self::Backup,
            "email" => Self::Email,
            "diskimage" | "disk" => Self::DiskImage,
            "compressed" => Self::Compressed,
            "virtual" => Self::Virtual,
            "certificate" => Self::Certificate,
            _ => Self::Miscellaneous,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub extension: String,
    pub magic_bytes: Vec<u8>,
    pub offset: usize,
    pub description: String,
    pub category: SignatureCategory,
}

pub struct SignatureDatabase {
    entries: Vec<SignatureEntry>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        let mut db = Self { entries: Vec::new() };
        db.load_all_signatures();
        db
    }

    pub fn entries(&self) -> &[SignatureEntry] {
        &self.entries
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn by_category(&self, category: &SignatureCategory) -> Vec<&SignatureEntry> {
        self.entries.iter().filter(|e| e.category == *category).collect()
    }

    pub fn by_category_name(&self, name: &str) -> Vec<&SignatureEntry> {
        let cat = SignatureCategory::from_str(name);
        self.by_category(&cat)
    }

    pub fn identify(&self, data: &[u8]) -> Option<&SignatureEntry> {
        for entry in &self.entries {
            if entry.offset + entry.magic_bytes.len() <= data.len() {
                let slice = &data[entry.offset..entry.offset + entry.magic_bytes.len()];
                if slice == entry.magic_bytes.as_slice() {
                    return Some(entry);
                }
            }
        }
        None
    }

    pub fn identify_all(&self, data: &[u8]) -> Vec<&SignatureEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.offset + entry.magic_bytes.len() <= data.len()
                    && &data[entry.offset..entry.offset + entry.magic_bytes.len()] == entry.magic_bytes.as_slice()
            })
            .collect()
    }

    pub fn to_file_signatures(&self) -> Vec<FileSignature> {
        self.entries
            .iter()
            .map(|e| FileSignature {
                extension: e.extension.clone(),
                magic_bytes: e.magic_bytes.clone(),
                offset: e.offset,
                description: e.description.clone(),
                category: e.category.as_str().to_string(),
            })
            .collect()
    }

    pub fn find_by_extension(&self, ext: &str) -> Vec<&SignatureEntry> {
        let lower = ext.to_lowercase();
        self.entries.iter().filter(|e| e.extension.to_lowercase() == lower).collect()
    }

    fn load_all_signatures(&mut self) {
        self.load_image_signatures();
        self.load_document_signatures();
        self.load_audio_signatures();
        self.load_video_signatures();
        self.load_archive_signatures();
        self.load_compressed_signatures();
        self.load_database_signatures();
        self.load_executable_signatures();
        self.load_font_signatures();
        self.load_cad_signatures();
        self.load_3d_signatures();
        self.load_backup_signatures();
        self.load_email_signatures();
        self.load_disk_image_signatures();
        self.load_virtual_signatures();
        self.load_certificate_signatures();
        self.load_misc_signatures();
    }

    fn add(&mut self, ext: &str, magic: &[u8], offset: usize, desc: &str, cat: SignatureCategory) {
        self.entries.push(SignatureEntry {
            extension: ext.to_string(),
            magic_bytes: magic.to_vec(),
            offset,
            description: desc.to_string(),
            category: cat,
        });
    }

    fn load_image_signatures(&mut self) {
        let c = SignatureCategory::Image;
        self.add("jpg", &[0xFF, 0xD8, 0xFF], 0, "JPEG Image", c.clone());
        self.add("jpeg", &[0xFF, 0xD8, 0xFF], 0, "JPEG Image", c.clone());
        self.add("jfif", &[0xFF, 0xD8, 0xFF, 0xE0], 0, "JPEG/JFIF Image", c.clone());
        self.add("png", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], 0, "PNG Image", c.clone());
        self.add("gif87", &[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], 0, "GIF87a Image", c.clone());
        self.add("gif89", &[0x47, 0x49, 0x46, 0x38, 0x39, 0x61], 0, "GIF89a Image", c.clone());
        self.add("bmp", &[0x42, 0x4D], 0, "BMP Image", c.clone());
        self.add("tiff_le", &[0x49, 0x49, 0x2A, 0x00], 0, "TIFF Image (Little Endian)", c.clone());
        self.add("tiff_be", &[0x4D, 0x4D, 0x00, 0x2A], 0, "TIFF Image (Big Endian)", c.clone());
        self.add("psd", &[0x38, 0x42, 0x50, 0x53], 0, "Adobe Photoshop Document", c.clone());
        self.add("ai", &[0x25, 0x21, 0x50, 0x53, 0x2D, 0x41, 0x64, 0x6F, 0x62, 0x65], 0, "Adobe Illustrator", c.clone());
        self.add("eps", &[0x25, 0x21, 0x50, 0x53], 0, "Encapsulated PostScript", c.clone());
        self.add("webp", &[0x52, 0x49, 0x46, 0x46], 0, "WebP Image (RIFF container)", c.clone());
        self.add("ico", &[0x00, 0x00, 0x01, 0x00], 0, "ICO Icon", c.clone());
        self.add("cur", &[0x00, 0x00, 0x02, 0x00], 0, "CUR Cursor", c.clone());
        self.add("jp2", &[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20], 0, "JPEG 2000", c.clone());
        self.add("jpx", &[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x32, 0x20], 0, "JPEG 2000 Part 2", c.clone());
        self.add("jxr", &[0x49, 0x49, 0xBC, 0x01], 0, "JPEG XR", c.clone());
        self.add("xcf", &[0x67, 0x69, 0x6D, 0x70, 0x20, 0x78, 0x63, 0x66], 0, "GIMP XCF Image", c.clone());
        self.add("pcx", &[0x0A, 0x05, 0x01], 0, "PCX Image", c.clone());
        self.add("wmf", &[0xD7, 0xCD, 0xC6, 0x9A], 0, "Windows Metafile", c.clone());
        self.add("emf", &[0x01, 0x00, 0x00, 0x00], 0, "Enhanced Metafile", c.clone());
        self.add("cr2", &[0x49, 0x49, 0x2A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x43, 0x52], 0, "Canon RAW2", c.clone());
        self.add("cr3", &[0x00, 0x00, 0x00], 0, "Canon RAW3 (ISO BMFF)", c.clone());
        self.add("nef", &[0x49, 0x49, 0x2A, 0x00], 0, "Nikon RAW (TIFF-based)", c.clone());
        self.add("orf_1", &[0x49, 0x49, 0x52, 0x4F], 0, "Olympus RAW (type 1)", c.clone());
        self.add("orf_2", &[0x49, 0x49, 0x52, 0x53], 0, "Olympus RAW (type 2)", c.clone());
        self.add("rw2", &[0x49, 0x49, 0x55, 0x00], 0, "Panasonic RAW", c.clone());
        self.add("dng", &[0x49, 0x49, 0x2A, 0x00], 0, "Adobe DNG RAW", c.clone());
        self.add("raf", &[0x46, 0x55, 0x4A, 0x49, 0x46, 0x49, 0x4C, 0x4D], 0, "Fujifilm RAW", c.clone());
        self.add("arw", &[0x49, 0x49, 0x2A, 0x00], 0, "Sony RAW (TIFF-based)", c.clone());
        self.add("srw", &[0x49, 0x49, 0x2A, 0x00], 0, "Samsung RAW (TIFF-based)", c.clone());
        self.add("pef", &[0x49, 0x49, 0x2A, 0x00], 0, "Pentax RAW (TIFF-based)", c.clone());
        self.add("tga_1", &[0x00, 0x00, 0x02, 0x00], 0, "TGA Image (uncompressed)", c.clone());
        self.add("tga_2", &[0x00, 0x00, 0x10, 0x00], 0, "TGA Image (RLE)", c.clone());
        self.add("hdr", &[0x23, 0x3F, 0x52, 0x41, 0x44, 0x49, 0x41, 0x4E], 0, "Radiance HDR", c.clone());
        self.add("exr", &[0x76, 0x2F, 0x31, 0x01], 0, "OpenEXR", c.clone());
        self.add("pgm", &[0x50, 0x35], 0, "PGM Image (binary)", c.clone());
        self.add("ppm", &[0x50, 0x36], 0, "PPM Image (binary)", c.clone());
        self.add("pbm", &[0x50, 0x31], 0, "PBM Image (ASCII)", c.clone());
        self.add("heif_hevc", &[0x00, 0x00, 0x00], 0, "HEIF/HEIC Image (ftyp at offset 4)", c.clone());
        self.add("avif", &[0x00, 0x00, 0x00], 0, "AVIF Image (ftyp at offset 4)", c.clone());
    }

    fn load_document_signatures(&mut self) {
        let c = SignatureCategory::Document;
        self.add("pdf", &[0x25, 0x50, 0x44, 0x46], 0, "PDF Document", c.clone());
        self.add("doc", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Microsoft Word (OLE2)", c.clone());
        self.add("xls", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Microsoft Excel (OLE2)", c.clone());
        self.add("ppt", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Microsoft PowerPoint (OLE2)", c.clone());
        self.add("msi", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Windows Installer (OLE2)", c.clone());
        self.add("msg", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Outlook Message (OLE2)", c.clone());
        self.add("docx", &[0x50, 0x4B, 0x03, 0x04], 0, "Microsoft Word (OOXML)", c.clone());
        self.add("xlsx", &[0x50, 0x4B, 0x03, 0x04], 0, "Microsoft Excel (OOXML)", c.clone());
        self.add("pptx", &[0x50, 0x4B, 0x03, 0x04], 0, "Microsoft PowerPoint (OOXML)", c.clone());
        self.add("odt", &[0x50, 0x4B, 0x03, 0x04], 0, "OpenDocument Text", c.clone());
        self.add("ods", &[0x50, 0x4B, 0x03, 0x04], 0, "OpenDocument Spreadsheet", c.clone());
        self.add("odp", &[0x50, 0x4B, 0x03, 0x04], 0, "OpenDocument Presentation", c.clone());
        self.add("odg", &[0x50, 0x4B, 0x03, 0x04], 0, "OpenDocument Graphics", c.clone());
        self.add("epub", &[0x50, 0x4B, 0x03, 0x04], 0, "EPUB eBook", c.clone());
        self.add("rtf", &[0x7B, 0x5C, 0x72, 0x74, 0x66], 0, "Rich Text Format", c.clone());
        self.add("wpd", &[0xFF, 0x57, 0x50, 0x43], 0, "WordPerfect Document", c.clone());
        self.add("wps", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Microsoft Works", c.clone());
        self.add("wks", &[0x0E, 0x04, 0x01, 0x02], 0, "Microsoft Works Spreadsheet", c.clone());
        self.add("qxp", &[0x00, 0x00, 0x49, 0x49, 0x58, 0x50, 0x52], 0, "QuarkXPress", c.clone());
        self.add("key", &[0x50, 0x4B, 0x03, 0x04], 0, "Apple Keynote (iWork)", c.clone());
        self.add("numbers", &[0x50, 0x4B, 0x03, 0x04], 0, "Apple Numbers (iWork)", c.clone());
        self.add("pages", &[0x50, 0x4B, 0x03, 0x04], 0, "Apple Pages (iWork)", c.clone());
        self.add("mobi", &[0x42, 0x4F, 0x4F, 0x4B, 0x4D, 0x4F, 0x42, 0x49], 0, "Mobipocket eBook", c.clone());
        self.add("chm", &[0x49, 0x54, 0x53, 0x46, 0x03, 0x00, 0x00, 0x00], 0, "Compiled HTML Help", c.clone());
        self.add("sxw", &[0x50, 0x4B, 0x03, 0x04], 0, "StarOffice Writer", c.clone());
        self.add("sxc", &[0x50, 0x4B, 0x03, 0x04], 0, "StarOffice Calc", c.clone());
        self.add("latex", &[0x5C, 0x62, 0x65, 0x67, 0x69, 0x6E], 0, "LaTeX Document", c.clone());
        self.add("tex", &[0x25, 0x21, 0x54, 0x45, 0x58], 0, "TeX Document", c.clone());
    }

    fn load_audio_signatures(&mut self) {
        let c = SignatureCategory::Audio;
        self.add("mp3_id3", &[0x49, 0x44, 0x33], 0, "MP3 with ID3v2 tag", c.clone());
        self.add("mp3_sync", &[0xFF, 0xFB], 0, "MP3 Frame Sync", c.clone());
        self.add("mp3_sync2", &[0xFF, 0xF3], 0, "MP3 Frame Sync (v2)", c.clone());
        self.add("mp3_sync3", &[0xFF, 0xF2], 0, "MP3 Frame Sync (v2.5)", c.clone());
        self.add("wav", &[0x52, 0x49, 0x46, 0x46], 0, "WAV Audio (RIFF)", c.clone());
        self.add("flac", &[0x66, 0x4C, 0x61, 0x43], 0, "FLAC Audio", c.clone());
        self.add("ogg", &[0x4F, 0x67, 0x67, 0x53], 0, "Ogg Vorbis/Opus", c.clone());
        self.add("aac_adts", &[0xFF, 0xF1], 0, "AAC ADTS Frame", c.clone());
        self.add("aac_adts2", &[0xFF, 0xF9], 0, "AAC ADTS Frame (MPEG-2)", c.clone());
        self.add("wma", &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11], 0, "Windows Media Audio (ASF)", c.clone());
        self.add("aiff", &[0x46, 0x4F, 0x52, 0x4D], 0, "AIFF Audio", c.clone());
        self.add("midi", &[0x4D, 0x54, 0x68, 0x64], 0, "MIDI", c.clone());
        self.add("m4a", &[0x00, 0x00, 0x00], 0, "M4A Audio (ftyp at offset 4)", c.clone());
        self.add("au", &[0x2E, 0x73, 0x6E, 0x64], 0, "Sun/NeXT AU Audio", c.clone());
        self.add("vox", &[0x44, 0x61, 0x74, 0x61], 0, "VoxWare Audio", c.clone());
        self.add("amr", &[0x23, 0x21, 0x41, 0x4D, 0x52], 0, "Adaptive Multi-Rate Audio", c.clone());
        self.add("aac_adif", &[0x41, 0x44, 0x49, 0x46], 0, "AAC ADIF", c.clone());
        self.add("dsf", &[0x44, 0x53, 0x44, 0x20], 0, "DSD Stream File", c.clone());
        self.add("dff", &[0x46, 0x52, 0x4D, 0x38], 0, "DSD Interchange File", c.clone());
    }

    fn load_video_signatures(&mut self) {
        let c = SignatureCategory::Video;
        self.add("mp4", &[0x00, 0x00, 0x00], 0, "MP4 Video (ftyp at offset 4)", c.clone());
        self.add("avi", &[0x52, 0x49, 0x46, 0x46], 0, "AVI Video (RIFF)", c.clone());
        self.add("mkv", &[0x1A, 0x45, 0xDF, 0xA3], 0, "Matroska/WebM Video", c.clone());
        self.add("webm", &[0x1A, 0x45, 0xDF, 0xA3], 0, "WebM Video", c.clone());
        self.add("flv", &[0x46, 0x4C, 0x56, 0x01], 0, "Flash Video", c.clone());
        self.add("wmv", &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11], 0, "Windows Media Video (ASF)", c.clone());
        self.add("mpg_ps", &[0x00, 0x00, 0x01, 0xBA], 0, "MPEG Program Stream", c.clone());
        self.add("mpg_ves", &[0x00, 0x00, 0x01, 0xB3], 0, "MPEG Video Element Stream", c.clone());
        self.add("ts", &[0x47], 0, "MPEG Transport Stream", c.clone());
        self.add("m2ts", &[0x47], 4, "MPEG-2 Transport Stream (BDAV)", c.clone());
        self.add("mov", &[0x00, 0x00, 0x00], 0, "QuickTime MOV (ftyp at offset 4)", c.clone());
        self.add("3gp", &[0x00, 0x00, 0x00], 0, "3GP Video (ftyp at offset 4)", c.clone());
        self.add("ogv", &[0x4F, 0x67, 0x67, 0x53], 0, "Ogg Theora Video", c.clone());
        self.add("divx", &[0x52, 0x49, 0x46, 0x46], 0, "DivX Video (RIFF)", c.clone());
        self.add("rm", &[0x2E, 0x52, 0x4D, 0x46], 0, "RealMedia", c.clone());
        self.add("asf", &[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11], 0, "Advanced Systems Format", c.clone());
    }

    fn load_archive_signatures(&mut self) {
        let c = SignatureCategory::Archive;
        self.add("zip", &[0x50, 0x4B, 0x03, 0x04], 0, "ZIP Archive", c.clone());
        self.add("zip_empty", &[0x50, 0x4B, 0x05, 0x06], 0, "ZIP Empty Archive", c.clone());
        self.add("zip_spanned", &[0x50, 0x4B, 0x07, 0x08], 0, "ZIP Spanned Archive", c.clone());
        self.add("rar4", &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00], 0, "RAR 4.x Archive", c.clone());
        self.add("rar5", &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00], 0, "RAR 5.x Archive", c.clone());
        self.add("7z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], 0, "7-Zip Archive", c.clone());
        self.add("tar", &[0x75, 0x73, 0x74, 0x61, 0x72], 257, "TAR Archive (ustar)", c.clone());
        self.add("cab", &[0x4D, 0x53, 0x43, 0x46], 0, "Microsoft Cabinet", c.clone());
        self.add("iso", &[0x43, 0x44, 0x30, 0x30, 0x31], 0x8001, "ISO 9660 Disk Image", c.clone());
        self.add("rpm", &[0xED, 0xAB, 0xEE, 0xDB], 0, "RPM Package", c.clone());
        self.add("deb", &[0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A], 0, "Debian Package", c.clone());
        self.add("ace", &[0x2A, 0x2A, 0x41, 0x43, 0x45, 0x2A, 0x2A], 7, "ACE Archive", c.clone());
        self.add("arj", &[0x60, 0xEA], 0, "ARJ Archive", c.clone());
        self.add("lzh", &[0x2D, 0x6C, 0x68], 2, "LHA/LZH Archive", c.clone());
        self.add("zoo", &[0x5A, 0x4F, 0x4F, 0x20], 0, "Zoo Archive", c.clone());
        self.add("dmg", &[0x6B, 0x6F, 0x6C, 0x79], 0, "Apple Disk Image (koly trailer)", c.clone());
        self.add("xz", &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], 0, "XZ Compressed", c.clone());
        self.add("lz", &[0x4C, 0x5A, 0x49, 0x50], 0, "LZIP Compressed", c.clone());
        self.add("lzo", &[0x89, 0x4C, 0x5A, 0x4F], 0, "LZO Compressed (deprecated magic)", c.clone());
        self.add("sit", &[0x53, 0x49, 0x54, 0x21], 0, "StuffIt Archive", c.clone());
        self.add("sitx", &[0x53, 0x74, 0x75, 0x66, 0x66, 0x49, 0x74, 0x21], 0, "StuffIt X Archive", c.clone());
        self.add("alz", &[0x41, 0x4C, 0x5A], 0, "ALZ Archive", c.clone());
    }

    fn load_compressed_signatures(&mut self) {
        let c = SignatureCategory::Compressed;
        self.add("gz", &[0x1F, 0x8B], 0, "GZIP Compressed", c.clone());
        self.add("bz2", &[0x42, 0x5A, 0x68], 0, "BZIP2 Compressed", c.clone());
        self.add("xz", &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], 0, "XZ Compressed", c.clone());
        self.add("lz", &[0x4C, 0x5A, 0x49, 0x50], 0, "LZIP Compressed", c.clone());
        self.add("zstd", &[0x28, 0xB5, 0x2F, 0xFD], 0, "Zstandard Compressed", c.clone());
        self.add("lz4", &[0x04, 0x22, 0x4D, 0x18], 0, "LZ4 Compressed", c.clone());
        self.add("lzma", &[0x5D, 0x00, 0x00], 0, "LZMA Compressed", c.clone());
        self.add("snappy", &[0xFF, 0x06, 0x00, 0x00, 0x73, 0x4E, 0x61, 0x50], 0, "Snappy Frame Format", c.clone());
        self.add("brotli", &[0xCE, 0xB2], 0, "Brotli Compressed (not unique)", c.clone());
        self.add("compress", &[0x1F, 0x9D], 0, "Unix Compress", c.clone());
        self.add("lrz", &[0x4C, 0x52, 0x5A, 0x49], 0, "LRZIP Compressed", c.clone());
    }

    fn load_database_signatures(&mut self) {
        let c = SignatureCategory::Database;
        self.add("sqlite", &[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00], 0, "SQLite Database", c.clone());
        self.add("mdb", &[0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x45, 0x74], 0, "Microsoft Access (Jet)", c.clone());
        self.add("accdb", &[0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x41, 0x43, 0x45], 0, "Microsoft Access (ACE)", c.clone());
        self.add("dbf", &[0x03], 0, "dBASE Database (v3)", c.clone());
        self.add("dbf_v4", &[0x04], 0, "dBASE Database (v4)", c.clone());
        self.add("dbf_v5", &[0x05], 0, "dBASE Database (v5)", c.clone());
        self.add("fdb", &[0x00, 0x00, 0x00, 0x01], 0, "Firebird/InterBase Database", c.clone());
        self.add("gdb", &[0x03, 0x00, 0x00, 0x00], 0, "InterBase Database", c.clone());
        self.add("ldf", &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0, "SQL Server Transaction Log", c.clone());
        self.add("mdf", &[0x01, 0x0F, 0x00, 0x00], 0, "SQL Server Database", c.clone());
        self.add("nsf", &[0x1A, 0x00, 0x00, 0x04, 0x00, 0x00], 0, "Lotus Notes Database", c.clone());
    }

    fn load_executable_signatures(&mut self) {
        let c = SignatureCategory::Executable;
        self.add("pe", &[0x4D, 0x5A], 0, "Windows PE Executable (MZ)", c.clone());
        self.add("elf", &[0x7F, 0x45, 0x4C, 0x46], 0, "Linux ELF Executable", c.clone());
        self.add("macho_32", &[0xFE, 0xED, 0xFA, 0xCE], 0, "Mach-O 32-bit (32-bit)", c.clone());
        self.add("macho_64", &[0xFE, 0xED, 0xFA, 0xCF], 0, "Mach-O 64-bit (64-bit)", c.clone());
        self.add("macho_32r", &[0xCE, 0xFA, 0xED, 0xFE], 0, "Mach-O 32-bit (reversed)", c.clone());
        self.add("macho_64r", &[0xCF, 0xFA, 0xED, 0xFE], 0, "Mach-O 64-bit (reversed)", c.clone());
        self.add("macho_fat", &[0xCA, 0xFE, 0xBA, 0xBE], 0, "Mach-O Universal Binary", c.clone());
        self.add("dex", &[0x64, 0x65, 0x78, 0x0A], 0, "Android DEX", c.clone());
        self.add("dex_odex", &[0x64, 0x65, 0x79, 0x0A], 0, "Android ODEX", c.clone());
        self.add("class", &[0xCA, 0xFE, 0xBA, 0xBE], 0, "Java Class File", c.clone());
        self.add("swf", &[0x46, 0x57, 0x53], 0, "Flash SWF (uncompressed)", c.clone());
        self.add("swf_z", &[0x43, 0x57, 0x53], 0, "Flash SWF (zlib)", c.clone());
        self.add("swf_lzma", &[0x5A, 0x57, 0x53], 0, "Flash SWF (LZMA)", c.clone());
        self.add("com", &[0xE9], 0, "DOS COM (JMP)", c.clone());
        self.add("com_2", &[0xEB], 0, "DOS COM (JMP short)", c.clone());
        self.add("dll", &[0x4D, 0x5A], 0, "Windows DLL (MZ)", c.clone());
        self.add("sys", &[0x4D, 0x5A], 0, "Windows Driver (MZ)", c.clone());
        self.add("vxd", &[0x4D, 0x5A], 0, "Windows VXD (MZ)", c.clone());
        self.add("pyc3", &[0x55, 0x0D, 0x0D, 0x0A], 0, "Python 3.x Bytecode", c.clone());
        self.add("pyc2", &[0x43, 0x0D, 0x0D, 0x0A], 0, "Python 2.x Bytecode", c.clone());
        self.add("wasm", &[0x00, 0x61, 0x73, 0x6D], 0, "WebAssembly", c.clone());
        self.add("lua", &[0x1B, 0x4C, 0x75, 0x61], 0, "Lua Bytecode", c.clone());
    }

    fn load_font_signatures(&mut self) {
        let c = SignatureCategory::Font;
        self.add("ttf", &[0x00, 0x01, 0x00, 0x00], 0, "TrueType Font", c.clone());
        self.add("otf", &[0x4F, 0x54, 0x54, 0x4F], 0, "OpenType Font", c.clone());
        self.add("woff", &[0x77, 0x4F, 0x46, 0x46], 0, "WOFF Font", c.clone());
        self.add("woff2", &[0x77, 0x4F, 0x46, 0x32], 0, "WOFF2 Font", c.clone());
        self.add("eot_1", &[0x00, 0x00, 0x01, 0x00], 0, "Embedded OpenType (type 1)", c.clone());
        self.add("eot_2", &[0x4C, 0x50], 34, "Embedded OpenType (LP signature)", c.clone());
        self.add("pcf", &[0x01, 0x66, 0x63, 0x70], 0, "Portable Compiled Format Font", c.clone());
        self.add("bdf", &[0x53, 0x54, 0x41, 0x52], 0, "Bitmap Distribution Format", c.clone());
        self.add("snf", &[0xF0, 0x07, 0x04, 0x70], 0, "Server Normal Form Font", c.clone());
        self.add("ttc", &[0x74, 0x74, 0x63, 0x66], 0, "TrueType Collection", c.clone());
    }

    fn load_cad_signatures(&mut self) {
        let c = SignatureCategory::Cad;
        self.add("dwg_ac1032", &[0x41, 0x43, 0x31, 0x30, 0x33, 0x32], 0, "AutoCAD DWG (2018-2023)", c.clone());
        self.add("dwg_ac1027", &[0x41, 0x43, 0x31, 0x30, 0x32, 0x37], 0, "AutoCAD DWG (2013-2017)", c.clone());
        self.add("dwg_ac1024", &[0x41, 0x43, 0x31, 0x30, 0x32, 0x34], 0, "AutoCAD DWG (2010-2012)", c.clone());
        self.add("dwg_ac1021", &[0x41, 0x43, 0x31, 0x30, 0x32, 0x31], 0, "AutoCAD DWG (2007-2009)", c.clone());
        self.add("dwg_ac1018", &[0x41, 0x43, 0x31, 0x30, 0x31, 0x38], 0, "AutoCAD DWG (2004-2006)", c.clone());
        self.add("dwg_ac1015", &[0x41, 0x43, 0x31, 0x30, 0x31, 0x35], 0, "AutoCAD DWG (2000-2002)", c.clone());
        self.add("dwg_ac1014", &[0x41, 0x43, 0x31, 0x30, 0x31, 0x34], 0, "AutoCAD DWG (R14)", c.clone());
        self.add("dwg_ac1012", &[0x41, 0x43, 0x31, 0x30, 0x31, 0x32], 0, "AutoCAD DWG (R13)", c.clone());
        self.add("dxf", &[0x20, 0x20, 0x30, 0x0A, 0x53, 0x45, 0x43, 0x54], 0, "AutoCAD DXF (ASCII)", c.clone());
        self.add("cgr", &[0x07, 0x04, 0x00, 0x00], 0, "CATIA Model", c.clone());
        self.add("catpart", &[0x07, 0x04, 0x00, 0x00], 0, "CATIA Part", c.clone());
        self.add("skp", &[0x53, 0x4B, 0x45, 0x54, 0x43, 0x48, 0x55, 0x50], 0, "SketchUp Model", c.clone());
        self.add("vsd", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Microsoft Visio (OLE2)", c.clone());
    }

    fn load_3d_signatures(&mut self) {
        let c = SignatureCategory::Model3D;
        self.add("stl_ascii", &[0x73, 0x6F, 0x6C, 0x69, 0x64], 0, "STL 3D Model (ASCII)", c.clone());
        self.add("stl_binary", &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0, "STL 3D Model (Binary - heuristic)", c.clone());
        self.add("obj", &[0x23, 0x20], 0, "Wavefront OBJ (heuristic: comment)", c.clone());
        self.add("3ds", &[0x4D, 0x4D, 0x02, 0x00], 0, "3DS Max 3DS", c.clone());
        self.add("blend", &[0x42, 0x4C, 0x45, 0x4E, 0x44, 0x45, 0x52], 0, "Blender 3D", c.clone());
        self.add("ply_ascii", &[0x70, 0x6C, 0x79, 0x0A], 0, "PLY 3D Model (ASCII)", c.clone());
        self.add("ply_binary", &[0x70, 0x6C, 0x79, 0x0D, 0x0A], 0, "PLY 3D Model (binary)", c.clone());
        self.add("fbx_bin", &[0x4B, 0x61, 0x79, 0x64, 0x61, 0x72, 0x61, 0x20], 0, "FBX 3D Model (Kaydara)", c.clone());
        self.add("gltf_bin", &[0x67, 0x6C, 0x54, 0x46], 0, "glTF 2.0 Binary", c.clone());
    }

    fn load_backup_signatures(&mut self) {
        let c = SignatureCategory::Backup;
        self.add("vmdk_sparse", &[0x4B, 0x44, 0x4D, 0x56], 0, "VMware VMDK (Sparse)", c.clone());
        self.add("vmdk_flat", &[0x23, 0x20, 0x44, 0x69, 0x73, 0x6B], 0, "VMware VMDK (Flat Descriptor)", c.clone());
        self.add("vhd", &[0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78], 0, "Virtual PC VHD (footer)", c.clone());
        self.add("vhdx", &[0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65], 0, "Hyper-V VHDX", c.clone());
        self.add("vdi", &[0x3C, 0x3C, 0x3C, 0x20, 0x4F, 0x72, 0x61, 0x63], 0, "VirtualBox VDI", c.clone());
        self.add("qcow", &[0x51, 0x46, 0x49], 0, "QEMU QCOW Image", c.clone());
        self.add("qcow2", &[0x51, 0x46, 0x49, 0xFB, 0x00, 0x00, 0x00, 0x02], 0, "QEMU QCOW2 Image", c.clone());
        self.add("qcow2_v3", &[0x51, 0x46, 0x49, 0xFB, 0x00, 0x00, 0x00, 0x03], 0, "QEMU QCOW2 Image v3", c.clone());
        self.add("bak_ole", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "Backup File (OLE2)", c.clone());
        self.add("tib", &[0xCE, 0x24, 0xB9, 0xA9, 0x54, 0x69, 0x94, 0xA5], 0, "Acronis True Image Backup", c.clone());
    }

    fn load_email_signatures(&mut self) {
        let c = SignatureCategory::Email;
        self.add("pst", &[0x21, 0x42, 0x44, 0x4E], 0, "Outlook PST", c.clone());
        self.add("ost", &[0x21, 0x42, 0x44, 0x4E], 0, "Outlook OST", c.clone());
        self.add("eml", &[0x46, 0x72, 0x6F, 0x6D, 0x20], 0, "Email Message (From header)", c.clone());
        self.add("mbox", &[0x46, 0x72, 0x6F, 0x6D, 0x20], 0, "MBOX Mail Archive", c.clone());
        self.add("dbx", &[0xCF, 0xAD, 0x12, 0xFE], 0, "Outlook Express DBX", c.clone());
        self.add("nsf", &[0x1A, 0x00, 0x00], 0, "Lotus Notes NSF", c.clone());
        self.add("wab", &[0x81, 0x32, 0x84, 0xC1, 0x85, 0x05, 0xD0, 0x11], 0, "Windows Address Book", c.clone());
        self.add("ldif", &[0x64, 0x6E, 0x3A, 0x20], 0, "LDAP Data Interchange Format", c.clone());
    }

    fn load_disk_image_signatures(&mut self) {
        let c = SignatureCategory::DiskImage;
        self.add("iso_9660", &[0x43, 0x44, 0x30, 0x30, 0x31], 0x8001, "ISO 9660", c.clone());
        self.add("udf", &[0x00, 0x4E, 0x53, 0x52, 0x30, 0x30, 0x31], 0x8001, "UDF File System", c.clone());
        self.add("fat12_16", &[0xEB], 0, "FAT12/16 Boot Sector", c.clone());
        self.add("fat32", &[0xEB, 0x58, 0x90], 0, "FAT32 Boot Sector", c.clone());
        self.add("ntfs", &[0xEB, 0x52, 0x90, 0x4E, 0x54, 0x46, 0x53], 0, "NTFS Boot Sector", c.clone());
        self.add("ext2_3", &[0xEF, 0x53], 0x438, "ext2/ext3 Superblock", c.clone());
        self.add("ext4", &[0xEF, 0x53], 0x438, "ext4 Superblock", c.clone());
        self.add("hfs_plus", &[0x48, 0x2B, 0x00, 0x04], 0, "HFS+ Volume Header", c.clone());
        self.add("hfsx", &[0x48, 0x58, 0x00, 0x05], 0, "HFSX Volume Header", c.clone());
        self.add("apfs", &[0x4E, 0x58, 0x53, 0x42], 0, "APFS Superblock (NXSB)", c.clone());
        self.add("btrfs", &[0x5F, 0x42, 0x48, 0x52, 0x66, 0x53, 0x5F, 0x4D], 0x10040, "Btrfs File System", c.clone());
        self.add("zfs", &[0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x1D, 0x11, 0xD0], 0, "ZFS vdev Label", c.clone());
        self.add("xfs", &[0x58, 0x46, 0x53, 0x42], 0, "XFS Superblock", c.clone());
        self.add("ufs", &[0x54, 0x19, 0x01, 0x00], 0x8008, "UFS Superblock", c.clone());
        self.add("jfs", &[0x4A, 0x46, 0x53, 0x31], 0x8000, "JFS Superblock", c.clone());
        self.add("reiserfs", &[0x52, 0x65, 0x49, 0x73, 0x45, 0x72], 0x8228, "ReiserFS", c.clone());
        self.add("gpt", &[0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54], 512, "GPT Partition Header", c.clone());
        self.add("mbr", &[0x55, 0xAA], 510, "MBR Boot Signature", c.clone());
    }

    fn load_virtual_signatures(&mut self) {
        let c = SignatureCategory::Virtual;
        self.add("ova", &[0x50, 0x4B, 0x03, 0x04], 0, "OVA Virtual Appliance (TAR-based)", c.clone());
        self.add("ovf", &[0x3C, 0x3F, 0x78, 0x6D, 0x6C], 0, "OVF Descriptor (XML)", c.clone());
    }

    fn load_certificate_signatures(&mut self) {
        let c = SignatureCategory::Certificate;
        self.add("pem", &[0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E], 0, "PEM Certificate", c.clone());
        self.add("der", &[0x30, 0x82], 0, "DER/ASN.1 Certificate", c.clone());
        self.add("p12", &[0x30, 0x82], 0, "PKCS#12 Keystore", c.clone());
        self.add("p7b", &[0x30, 0x82], 0, "PKCS#7 Certificate Chain", c.clone());
        self.add("pfx", &[0x30, 0x82], 0, "Personal Information Exchange", c.clone());
        self.add("cer", &[0x30, 0x82], 0, "X.509 Certificate (DER)", c.clone());
        self.add("crl", &[0x30, 0x82], 0, "Certificate Revocation List", c.clone());
        self.add("csr", &[0x30, 0x82], 0, "Certificate Signing Request", c.clone());
        self.add("kdbx", &[0x03, 0xD9, 0xA2, 0x9A], 0, "KeePass Database", c.clone());
        self.add("key", &[0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E], 0, "Private Key (PEM)", c.clone());
    }

    fn load_misc_signatures(&mut self) {
        let c = SignatureCategory::Miscellaneous;
        self.add("torrent", &[0x64, 0x38, 0x3A, 0x61, 0x6E, 0x6E, 0x6F, 0x75, 0x6E, 0x63, 0x65], 0, "BitTorrent File", c.clone());
        self.add("lnk", &[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00], 0, "Windows Shortcut", c.clone());
        self.add("reg", &[0xFF, 0xFE], 0, "Windows Registry File (UTF-16)", c.clone());
        self.add("dat_ntfs", &[0x00, 0x00, 0x00, 0x00], 0, "NTFS $DATA (heuristic)", c.clone());
        self.add("pcap", &[0xD4, 0xC3, 0xB2, 0xA1], 0, "PCAP Capture (little endian)", c.clone());
        self.add("pcap_be", &[0xA1, 0xB2, 0xC3, 0xD4], 0, "PCAP Capture (big endian)", c.clone());
        self.add("pcapng", &[0x0A, 0x0D, 0x0D, 0x0A], 0, "PCAPNG Capture", c.clone());
        self.add("sqlite_wal", &[0x37, 0x7A, 0xBC, 0xAF], 0, "SQLite WAL (coincidence with 7z - check context)", c.clone());
        self.add("bitcoin_wallet", &[0x00, 0x00, 0x00, 0x00], 0, "Bitcoin Wallet (heuristic)", c.clone());
        self.add("gnucash", &[0x3C, 0x3F, 0x78, 0x6D, 0x6C], 0, "GnuCash Data (XML)", c.clone());
        self.add("qfx", &[0x4F, 0x46, 0x58, 0x20], 0, "Quicken QFX", c.clone());
        self.add("qdb", &[0x51, 0x45, 0x4C, 0x20], 0, "Quicken QDB", c.clone());
        self.add("wps_office", &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], 0, "WPS Office Document", c.clone());
        self.add("sdf", &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0, "SQL CE Database", c.clone());
        self.add("ntfs_mft", &[0x46, 0x49, 0x4C, 0x45], 0, "NTFS MFT Record", c.clone());
        self.add("vmware_snap", &[0x20, 0x00, 0x00, 0x00], 0, "VMware Snapshot", c.clone());
        self.add("time_machine", &[0x4B, 0x65, 0x79, 0x53, 0x74, 0x6F], 0, "Apple Keychain (heuristic)", c.clone());
        self.add("keychain", &[0xFA, 0xDE, 0x11, 0x07], 0, "Apple Keychain (blob)", c.clone());
        self.add("ntfs_idx", &[0x49, 0x4E, 0x44, 0x58], 0, "NTFS INDEX Record", c.clone());
        self.add("gpg", &[0x99], 0, "GPG Public Key (old format)", c.clone());
        self.add("gpg_new", &[0xC6], 0, "GPG Public Key (new format)", c.clone());
        self.add("ssh_rsa", &[0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47, 0x49, 0x4E, 0x20, 0x4F, 0x50, 0x45, 0x4E, 0x53, 0x53, 0x48], 0, "OpenSSH Private Key", c.clone());
        self.add("git_pack", &[0x50, 0x41, 0x43, 0x4B], 0, "Git Pack File", c.clone());
        self.add("git_idx", &[0xFF, 0x74, 0x4F, 0x63], 0, "Git Pack Index v2", c.clone());
        self.add("docker_layer", &[0x50, 0x4B, 0x03, 0x04], 0, "Docker Layer (tar.gz - heuristic)", c.clone());
    }
}

impl Default for SignatureDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_database_creation() {
        let db = SignatureDatabase::new();
        assert!(db.count() >= 200, "Expected 200+ signatures, got {}", db.count());
    }

    #[test]
    fn test_default() {
        let db = SignatureDatabase::default();
        assert!(db.count() >= 200);
    }

    #[test]
    fn test_by_category_image() {
        let db = SignatureDatabase::new();
        let images = db.by_category(&SignatureCategory::Image);
        assert!(images.len() >= 20, "Expected 20+ image signatures, got {}", images.len());
    }

    #[test]
    fn test_by_category_document() {
        let db = SignatureDatabase::new();
        let docs = db.by_category(&SignatureCategory::Document);
        assert!(docs.len() >= 10);
    }

    #[test]
    fn test_by_category_audio() {
        let db = SignatureDatabase::new();
        let audio = db.by_category(&SignatureCategory::Audio);
        assert!(audio.len() >= 10);
    }

    #[test]
    fn test_by_category_video() {
        let db = SignatureDatabase::new();
        let video = db.by_category(&SignatureCategory::Video);
        assert!(video.len() >= 8);
    }

    #[test]
    fn test_by_category_archive() {
        let db = SignatureDatabase::new();
        let archives = db.by_category(&SignatureCategory::Archive);
        assert!(archives.len() >= 10);
    }

    #[test]
    fn test_by_category_executable() {
        let db = SignatureDatabase::new();
        let execs = db.by_category(&SignatureCategory::Executable);
        assert!(execs.len() >= 10);
    }

    #[test]
    fn test_by_category_database() {
        let db = SignatureDatabase::new();
        let dbs = db.by_category(&SignatureCategory::Database);
        assert!(dbs.len() >= 5);
    }

    #[test]
    fn test_by_category_name() {
        let db = SignatureDatabase::new();
        let images = db.by_category_name("image");
        assert!(!images.is_empty());
        let images2 = db.by_category_name("Image");
        assert_eq!(images.len(), images2.len());
    }

    #[test]
    fn test_identify_jpeg() {
        let db = SignatureDatabase::new();
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "jpg");
    }

    #[test]
    fn test_identify_png() {
        let db = SignatureDatabase::new();
        let data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "png");
    }

    #[test]
    fn test_identify_pdf() {
        let db = SignatureDatabase::new();
        let data = vec![0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "pdf");
    }

    #[test]
    fn test_identify_zip() {
        let db = SignatureDatabase::new();
        let data = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        let results = db.identify_all(&data);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.extension == "zip"));
    }

    #[test]
    fn test_identify_elf() {
        let db = SignatureDatabase::new();
        let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "elf");
    }

    #[test]
    fn test_identify_pe() {
        let db = SignatureDatabase::new();
        let data = vec![0x4D, 0x5A, 0x90, 0x00];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "pe");
    }

    #[test]
    fn test_identify_rar() {
        let db = SignatureDatabase::new();
        let data = vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "rar4");
    }

    #[test]
    fn test_identify_7z() {
        let db = SignatureDatabase::new();
        let data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "7z");
    }

    #[test]
    fn test_identify_unknown() {
        let db = SignatureDatabase::new();
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let result = db.identify(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_identify_all_zip() {
        let db = SignatureDatabase::new();
        let data = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00];
        let results = db.identify_all(&data);
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_find_by_extension() {
        let db = SignatureDatabase::new();
        let results = db.find_by_extension("jpg");
        assert!(!results.is_empty());
        assert_eq!(results[0].extension, "jpg");
    }

    #[test]
    fn test_to_file_signatures() {
        let db = SignatureDatabase::new();
        let sigs = db.to_file_signatures();
        assert!(sigs.len() >= 200);
        assert!(sigs.iter().any(|s| s.extension == "jpg"));
        assert!(sigs.iter().any(|s| s.extension == "png"));
    }

    #[test]
    fn test_category_enum() {
        assert_eq!(SignatureCategory::Image.as_str(), "Image");
        assert_eq!(SignatureCategory::Document.as_str(), "Document");
        assert_eq!(SignatureCategory::Audio.as_str(), "Audio");
        assert_eq!(SignatureCategory::Video.as_str(), "Video");
        assert_eq!(SignatureCategory::Archive.as_str(), "Archive");
        assert_eq!(SignatureCategory::Database.as_str(), "Database");
        assert_eq!(SignatureCategory::Executable.as_str(), "Executable");
        assert_eq!(SignatureCategory::Font.as_str(), "Font");
        assert_eq!(SignatureCategory::Cad.as_str(), "CAD");
        assert_eq!(SignatureCategory::Model3D.as_str(), "3D");
        assert_eq!(SignatureCategory::Backup.as_str(), "Backup");
        assert_eq!(SignatureCategory::Email.as_str(), "Email");
        assert_eq!(SignatureCategory::DiskImage.as_str(), "DiskImage");
        assert_eq!(SignatureCategory::Compressed.as_str(), "Compressed");
        assert_eq!(SignatureCategory::Virtual.as_str(), "Virtual");
        assert_eq!(SignatureCategory::Certificate.as_str(), "Certificate");
        assert_eq!(SignatureCategory::Miscellaneous.as_str(), "Miscellaneous");
    }

    #[test]
    fn test_category_from_str() {
        assert_eq!(SignatureCategory::from_str("image"), SignatureCategory::Image);
        assert_eq!(SignatureCategory::from_str("IMAGE"), SignatureCategory::Image);
        assert_eq!(SignatureCategory::from_str("3d"), SignatureCategory::Model3D);
        assert_eq!(SignatureCategory::from_str("unknown"), SignatureCategory::Miscellaneous);
    }

    #[test]
    fn test_identify_empty_data() {
        let db = SignatureDatabase::new();
        let result = db.identify(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_identify_flac() {
        let db = SignatureDatabase::new();
        let data = vec![0x66, 0x4C, 0x61, 0x43, 0x00, 0x00];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "flac");
    }

    #[test]
    fn test_identify_mkv() {
        let db = SignatureDatabase::new();
        let data = vec![0x1A, 0x45, 0xDF, 0xA3, 0x00];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "mkv");
    }

    #[test]
    fn test_identify_sqlite() {
        let db = SignatureDatabase::new();
        let data = b"SQLite format 3\0";
        let result = db.identify(data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "sqlite");
    }

    #[test]
    fn test_identify_pst() {
        let db = SignatureDatabase::new();
        let data = vec![0x21, 0x42, 0x44, 0x4E, 0x00];
        let result = db.identify(&data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().extension, "pst");
    }

    #[test]
    fn test_all_categories_have_entries() {
        let db = SignatureDatabase::new();
        let categories = [
            SignatureCategory::Image,
            SignatureCategory::Document,
            SignatureCategory::Audio,
            SignatureCategory::Video,
            SignatureCategory::Archive,
            SignatureCategory::Database,
            SignatureCategory::Executable,
            SignatureCategory::Font,
            SignatureCategory::Cad,
            SignatureCategory::Model3D,
            SignatureCategory::Backup,
            SignatureCategory::Email,
            SignatureCategory::DiskImage,
            SignatureCategory::Compressed,
            SignatureCategory::Certificate,
            SignatureCategory::Miscellaneous,
        ];
        for cat in &categories {
            let entries = db.by_category(cat);
            assert!(!entries.is_empty(), "Category {:?} has no entries", cat);
        }
    }
}
