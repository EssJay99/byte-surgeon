use bytesurgeon_core::{Result, FileMetadata};
use chrono::{DateTime, Utc};

pub trait FileSystem {
    fn read_superblock(&self) -> Result<SuperblockInfo>;
    fn list_root_directory(&self) -> Result<Vec<DirectoryEntry>>;
    fn list_directory(&self, inode: u64) -> Result<Vec<DirectoryEntry>>;
    fn read_file(&self, inode: u64) -> Result<Vec<u8>>;
    fn find_deleted_files(&self) -> Result<Vec<FileEntry>>;
    fn get_file_metadata(&self, inode: u64) -> Result<FileMetadata>;
}

#[derive(Debug, Clone)]
pub struct SuperblockInfo {
    pub volume_name: Option<String>,
    pub total_size: u64,
    pub free_space: u64,
    pub block_size: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub file_system_type: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub name: String,
    pub inode: u64,
    pub is_directory: bool,
    pub size: u64,
    pub metadata: Option<FileMetadata>,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub inode: u64,
    pub name: Option<String>,
    pub size: u64,
    pub data_offset: u64,
    pub is_deleted: bool,
    pub metadata: Option<FileMetadata>,
}
