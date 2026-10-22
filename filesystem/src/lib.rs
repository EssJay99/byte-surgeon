pub mod ntfs;
pub mod fat32;
pub mod ext4;
pub mod apfs;
pub mod common;

pub use common::{FileSystem, FileEntry, DirectoryEntry};
pub use ntfs::NTFSParser;
pub use fat32::FAT32Parser;
pub use ext4::EXT4Parser;
pub use apfs::APFSParser;

use bytesurgeon_core::{FileSystemType, Result};

pub fn create_parser(fs_type: FileSystemType, device_path: &str) -> Result<Box<dyn FileSystem>> {
    match fs_type {
        FileSystemType::NTFS => Ok(Box::new(NTFSParser::new(device_path)?)),
        FileSystemType::FAT32 => Ok(Box::new(FAT32Parser::new(device_path)?)),
        FileSystemType::EXT4 | FileSystemType::EXT3 => Ok(Box::new(EXT4Parser::new(device_path)?)),
        FileSystemType::APFS => Ok(Box::new(APFSParser::new(device_path)?)),
        _ => Err(bytesurgeon_core::Error::UnsupportedFileSystem(format!("{:?}", fs_type))),
    }
}

pub fn detect_filesystem(device_path: &str) -> Result<FileSystemType> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = File::open(device_path)?;
    let mut buffer = [0u8; 512];
    
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buffer)?;

    if buffer[0] == 0xEB && buffer[1] == 0x52 && buffer[2] == 0x90
        && &buffer[3..11] == b"NTFS    " {
            return Ok(FileSystemType::NTFS);
        }

    if buffer.len() >= 82 {
        let oem_id = &buffer[3..11];
        if oem_id == b"FAT32   " || oem_id == b"MSDOS5.0" || oem_id == b"MSWIN" {
            return Ok(FileSystemType::FAT32);
        }
    }

    file.seek(SeekFrom::Start(1024))?;
    file.read_exact(&mut buffer)?;
    
    if buffer[0] == 0x53 && buffer[1] == 0xEF {
        return Ok(FileSystemType::EXT4);
    }

    if buffer.len() >= 32 {
        let magic = u32::from_le_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]);
        if magic == 0x41504653 {
            return Ok(FileSystemType::APFS);
        }
    }

    Ok(FileSystemType::Unknown)
}
