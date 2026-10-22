#![allow(dead_code)]
use crate::common::{FileSystem, SuperblockInfo, DirectoryEntry, FileEntry};
use datadoctor_core::{Result, Error, FileMetadata};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use tracing::{debug, warn};
use chrono::{DateTime, Utc, TimeZone};

const EXT4_MAGIC: u16 = 0xEF53;
const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_ROOT_INODE: u64 = 2;
const EXT4_S_IFREG: u16 = 0x8000;
const EXT4_S_IFDIR: u16 = 0x4000;
const EXT4_S_IFLNK: u16 = 0xA000;
const EXT4_EXTENTS_FLAG: u32 = 0x00080000;
const EXT4_DIR_ENTRY_FILE: u8 = 1;
const EXT4_DIR_ENTRY_DIR: u8 = 2;
const EXT4_INODE_DELETED: u16 = 0x0000;
const EXT4_MAX_BLOCKS: u32 = 12;
const EXT4_INDIRECT_BLOCK: usize = 12;
const EXT4_DINDIRECT_BLOCK: usize = 13;
const EXT4_TINDIRECT_BLOCK: usize = 14;
const EXT4_EXT_MAGIC: u16 = 0xF30A;
const MAX_EXT_DEPTH: usize = 5;
const MAX_EXT4_INODE_SCAN: u64 = 10_000_000;

pub struct EXT4Parser {
    device_path: String,
    block_size: u32,
    total_blocks: u64,
    free_blocks: u64,
    total_inodes: u64,
    free_inodes: u64,
    inodes_per_group: u32,
    blocks_per_group: u32,
    inode_size: u16,
    block_group_count: u32,
    first_data_block: u32,
    inode_table_offset: u64,
    volume_name: String,
    created_time: u32,
    compat_features: u32,
    incompat_features: u32,
    ro_compat_features: u32,
    descriptor_size: u16,
}

#[derive(Debug)]
struct Ext4Inode {
    mode: u16,
    uid: u16,
    size_lo: u32,
    size_hi: u32,
    links_count: u16,
    blocks_lo: u32,
    blocks_hi: u32,
    flags: u32,
    atime: u32,
    atime_extra: u32,
    ctime: u32,
    ctime_extra: u32,
    mtime: u32,
    mtime_extra: u32,
    crtime: u32,
    crtime_extra: u32,
    block: [u32; 15],
    generation: u32,
    uid_hi: u16,
    gid_hi: u16,
}

#[derive(Debug)]
struct BlockGroupDescriptor {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    free_blocks_count: u16,
    free_inodes_count: u16,
    used_dirs_count: u16,
}

impl EXT4Parser {
    pub fn new(device_path: &str) -> Result<Self> {
        let mut parser = Self {
            device_path: device_path.to_string(),
            block_size: 4096,
            total_blocks: 0,
            free_blocks: 0,
            total_inodes: 0,
            free_inodes: 0,
            inodes_per_group: 0,
            blocks_per_group: 0,
            inode_size: 256,
            block_group_count: 0,
            first_data_block: 0,
            inode_table_offset: 0,
            volume_name: String::new(),
            created_time: 0,
            compat_features: 0,
            incompat_features: 0,
            ro_compat_features: 0,
            descriptor_size: 32,
        };

        parser.read_superblock_fields()?;
        Ok(parser)
    }

    fn read_superblock_fields(&mut self) -> Result<()> {
        let mut file = File::open(&self.device_path)?;
        let mut buffer = [0u8; 1024];

        file.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))?;
        file.read_exact(&mut buffer)?;

        let magic = u16::from_le_bytes([buffer[56], buffer[57]]);
        if magic != EXT4_MAGIC {
            return Err(Error::InvalidDevice("Not an ext4 volume".to_string()));
        }

        let log_block_size = u32::from_le_bytes([buffer[24], buffer[25], buffer[26], buffer[27]]);
        self.block_size = 1024u32 << log_block_size;
        self.first_data_block = u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);

        self.total_blocks = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as u64;
        let total_blocks_hi = u32::from_le_bytes([buffer[336], buffer[337], buffer[338], buffer[339]]);
        if total_blocks_hi != 0 {
            self.total_blocks = (total_blocks_hi as u64) << 32 | self.total_blocks;
        }

        self.free_blocks = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]) as u64;
        let free_blocks_hi = u32::from_le_bytes([buffer[340], buffer[341], buffer[342], buffer[343]]);
        if free_blocks_hi != 0 {
            self.free_blocks = (free_blocks_hi as u64) << 32 | self.free_blocks;
        }

        self.inodes_per_group = u32::from_le_bytes([buffer[40], buffer[41], buffer[42], buffer[43]]);
        self.blocks_per_group = u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]);

        self.total_inodes = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as u64;
        self.free_inodes = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]) as u64;

        self.inode_size = u16::from_le_bytes([buffer[88], buffer[89]]);
        self.compat_features = u32::from_le_bytes([buffer[92], buffer[93], buffer[94], buffer[95]]);
        self.incompat_features = u32::from_le_bytes([buffer[96], buffer[97], buffer[98], buffer[99]]);
        self.ro_compat_features = u32::from_le_bytes([buffer[100], buffer[101], buffer[102], buffer[103]]);

        self.descriptor_size = if self.incompat_features & 0x0080 != 0 {
            u16::from_le_bytes([buffer[254], buffer[255]])
        } else {
            32
        };

        self.block_group_count = ((self.total_blocks + self.blocks_per_group as u64 - 1) / self.blocks_per_group as u64) as u32;

        let mut vol_name_bytes = [0u8; 16];
        vol_name_bytes.copy_from_slice(&buffer[120..136]);
        self.volume_name = String::from_utf8_lossy(&vol_name_bytes)
            .trim_end_matches('\0')
            .to_string();

        self.created_time = u32::from_le_bytes([buffer[108], buffer[109], buffer[110], buffer[111]]);

        debug!(
            "ext4 Superblock - Block size: {}, Total blocks: {}, Free blocks: {}, Volume: '{}', Groups: {}",
            self.block_size, self.total_blocks, self.free_blocks, self.volume_name, self.block_group_count
        );

        Ok(())
    }

    fn block_offset(&self, block: u64) -> u64 {
        block * self.block_size as u64
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>> {
        let mut file = File::open(&self.device_path)?;
        let mut buffer = vec![0u8; self.block_size as usize];
        file.seek(SeekFrom::Start(self.block_offset(block)))?;
        file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn read_block_group_descriptors(&self) -> Result<Vec<BlockGroupDescriptor>> {
        let descriptor_table_block = if self.first_data_block > 0 {
            self.first_data_block as u64 + 1
        } else {
            1
        };

        let block_data = self.read_block(descriptor_table_block)?;
        let mut descriptors = Vec::new();
        let desc_size = self.descriptor_size.max(32) as usize;

        for i in 0..self.block_group_count as usize {
            let offset = i * desc_size;
            if offset + desc_size > block_data.len() {
                break;
            }
            let d = &block_data[offset..offset + desc_size];

            let inode_table = if desc_size >= 32 {
                u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as u64
            } else {
                0
            };

            let inode_table_hi = if desc_size > 32 {
                u32::from_le_bytes([d[36], d[37], d[38], d[39]]) as u64
            } else {
                0
            };

            let full_inode_table = if inode_table_hi != 0 {
                (inode_table_hi << 32) | inode_table
            } else {
                inode_table
            };

            descriptors.push(BlockGroupDescriptor {
                block_bitmap: u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as u64,
                inode_bitmap: u32::from_le_bytes([d[4], d[5], d[6], d[7]]) as u64,
                inode_table: full_inode_table,
                free_blocks_count: u16::from_le_bytes([d[12], d[13]]),
                free_inodes_count: u16::from_le_bytes([d[14], d[15]]),
                used_dirs_count: u16::from_le_bytes([d[16], d[17]]),
            });
        }

        Ok(descriptors)
    }

    fn read_inode(&self, inode_number: u64) -> Result<Ext4Inode> {
        if inode_number == 0 {
            return Err(Error::InvalidDevice("Inode 0 is invalid".to_string()));
        }

        let descriptors = self.read_block_group_descriptors()?;
        let group = ((inode_number - 1) / self.inodes_per_group as u64) as usize;

        if group >= descriptors.len() {
            return Err(Error::InvalidDevice("Inode number out of range".to_string()));
        }

        let inode_table_block = descriptors[group].inode_table;
        let inode_index = (inode_number - 1) % self.inodes_per_group as u64;
        let inode_offset = self.block_offset(inode_table_block) + inode_index * self.inode_size as u64;

        let mut file = File::open(&self.device_path)?;
        file.seek(SeekFrom::Start(inode_offset))?;
        let mut buffer = vec![0u8; self.inode_size as usize];
        file.read_exact(&mut buffer)?;

        let mode = u16::from_le_bytes([buffer[0], buffer[1]]);
        let uid = u16::from_le_bytes([buffer[2], buffer[3]]);
        let size_lo = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let size_hi = u32::from_le_bytes([buffer[108], buffer[109], buffer[110], buffer[111]]);
        let links_count = u16::from_le_bytes([buffer[26], buffer[27]]);
        let blocks_lo = u32::from_le_bytes([buffer[28], buffer[29], buffer[30], buffer[31]]);
        let blocks_hi = u32::from_le_bytes([buffer[112], buffer[113], buffer[114], buffer[115]]);
        let flags = u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]);

        let atime = u32::from_le_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
        let atime_extra = u32::from_le_bytes([buffer[116], buffer[117], buffer[118], buffer[119]]);
        let ctime = u32::from_le_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);
        let ctime_extra = u32::from_le_bytes([buffer[120], buffer[121], buffer[122], buffer[123]]);
        let mtime = u32::from_le_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);
        let mtime_extra = u32::from_le_bytes([buffer[124], buffer[125], buffer[126], buffer[127]]);
        let crtime = u32::from_le_bytes([buffer[152], buffer[153], buffer[154], buffer[155]]);
        let crtime_extra = u32::from_le_bytes([buffer[156], buffer[157], buffer[158], buffer[159]]);

        let mut block = [0u32; 15];
        for i in 0..15 {
            let off = 40 + i * 4;
            block[i] = u32::from_le_bytes([buffer[off], buffer[off + 1], buffer[off + 2], buffer[off + 3]]);
        }

        let generation = u32::from_le_bytes([buffer[100], buffer[101], buffer[102], buffer[103]]);
        let uid_hi = u16::from_le_bytes([buffer[128], buffer[129]]);
        let gid_hi = u16::from_le_bytes([buffer[130], buffer[131]]);

        Ok(Ext4Inode {
            mode,
            uid,
            size_lo,
            size_hi,
            links_count,
            blocks_lo,
            blocks_hi,
            flags,
            atime,
            atime_extra,
            ctime,
            ctime_extra,
            mtime,
            mtime_extra,
            crtime,
            crtime_extra,
            block,
            generation,
            uid_hi,
            gid_hi,
        })
    }

    fn ext4_time_to_datetime(secs: u32, extra: u32) -> Option<DateTime<Utc>> {
        if secs == 0 {
            return None;
        }
        let extra_ns = (extra & 0x3) as u32;
        let extended_secs = if extra & 0x4 != 0 {
            (secs as u64) | ((extra as u64 & 0xFFFFFFFC) << 30)
        } else {
            secs as u64
        };
        let _ = extra_ns;
        Utc.timestamp_opt(extended_secs as i64, 0).single()
    }

    fn inode_file_size(inode: &Ext4Inode) -> u64 {
        let file_type = inode.mode & 0xF000;
        if file_type == EXT4_S_IFLNK && inode.blocks_lo == 0 && inode.blocks_hi == 0 {
            let size = inode.size_lo as u64 | ((inode.size_hi as u64) << 32);
            if size <= 60 {
                return size;
            }
        }
        (inode.size_lo as u64) | ((inode.size_hi as u64) << 32)
    }

    fn read_extent_tree_data(&self, inode: &Ext4Inode, file_size: u64) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(file_size as usize);
        let raw = &inode.block;
        let eh_magic = u16::from_le_bytes([raw[0] as u8, (raw[0] >> 8) as u8]);

        if eh_magic != EXT4_EXT_MAGIC {
            return self.read_indirect_data(inode, file_size);
        }

        let eh_depth = u16::from_le_bytes([raw[1] as u8, (raw[1] >> 8) as u8]);
        let eh_entries = u16::from_le_bytes([raw[2] as u8, (raw[2] >> 8) as u8]);

        let mut extents_to_read = Vec::new();

        if eh_depth == 0 {
            for i in 0..eh_entries as usize {
                let entry_offset = 12 + i * 12;
                if entry_offset + 12 > 60 {
                    break;
                }
                let ee_block = u32::from_le_bytes([
                    raw[entry_offset / 4] as u8,
                    (raw[entry_offset / 4] >> 8) as u8,
                    (raw[entry_offset / 4] >> 16) as u8,
                    (raw[entry_offset / 4] >> 24) as u8,
                ]);
                let ee_len_raw = u32::from_le_bytes([
                    raw[(entry_offset + 8) / 4] as u8,
                    (raw[(entry_offset + 8) / 4] >> 8) as u8,
                    (raw[(entry_offset + 8) / 4] >> 16) as u8,
                    (raw[(entry_offset + 8) / 4] >> 24) as u8,
                ]);
                let ee_start_lo = u32::from_le_bytes([
                    raw[(entry_offset + 4) / 4] as u8,
                    (raw[(entry_offset + 4) / 4] >> 8) as u8,
                    (raw[(entry_offset + 4) / 4] >> 16) as u8,
                    (raw[(entry_offset + 4) / 4] >> 24) as u8,
                ]);
                let ee_start_hi = u16::from_le_bytes([
                    raw[(entry_offset + 6) / 4] as u8,
                    (raw[(entry_offset + 6) / 4] >> 8) as u8,
                ]);
                let ee_start = (ee_start_hi as u64) << 32 | ee_start_lo as u64;
                let is_uninit = ee_len_raw & 0x80000000 != 0;
                let ee_len = (ee_len_raw & 0x7FFFFFFF) as u64;

                if !is_uninit {
                    extents_to_read.push((ee_block, ee_start, ee_len));
                }
            }
        } else {
            self.collect_extents_from_index(raw, eh_entries, eh_depth, &mut extents_to_read, 0)?;
        }

        for (ee_block, ee_start, ee_len) in extents_to_read {
            let start_offset = ee_block as u64 * self.block_size as u64;
            let end_len = ee_len * self.block_size as u64;

            let mut file = File::open(&self.device_path)?;
            for blk_offset in (0..end_len).step_by(self.block_size as usize) {
                let blk = ee_start + blk_offset / self.block_size as u64;
                let mut buf = vec![0u8; self.block_size as usize];
                file.seek(SeekFrom::Start(self.block_offset(blk)))?;
                if file.read_exact(&mut buf).is_err() {
                    break;
                }
                result.extend_from_slice(&buf);
            }

            if result.len() > file_size as usize {
                result.truncate(file_size as usize);
                break;
            }

            let _ = start_offset;
        }

        Ok(result)
    }

    fn collect_extents_from_index(
        &self,
        raw: &[u32; 15],
        entries: u16,
        depth: u16,
        extents: &mut Vec<(u32, u64, u64)>,
        current_depth: u16,
    ) -> Result<()> {
        for i in 0..entries as usize {
            let byte_offset = 12 + i * 12;
            let idx = byte_offset / 4;
            if idx + 2 >= 15 {
                break;
            }

            let ee_block_bytes: [u8; 4] = [
                (raw[idx] & 0xFF) as u8,
                ((raw[idx] >> 8) & 0xFF) as u8,
                ((raw[idx] >> 16) & 0xFF) as u8,
                ((raw[idx] >> 24) & 0xFF) as u8,
            ];
            let ee_block = u32::from_le_bytes(ee_block_bytes);

            let leaf_bytes: [u8; 4] = [
                (raw[idx + 1] & 0xFF) as u8,
                ((raw[idx + 1] >> 8) & 0xFF) as u8,
                ((raw[idx + 1] >> 16) & 0xFF) as u8,
                ((raw[idx + 1] >> 24) & 0xFF) as u8,
            ];
            let leaf_lo = u32::from_le_bytes(leaf_bytes);

            let hi_bytes: [u8; 2] = [
                (raw[idx + 1] & 0xFF) as u8,
                ((raw[idx + 1] >> 8) & 0xFF) as u8,
            ];
            let leaf_hi = u16::from_le_bytes(hi_bytes);
            let leaf = (leaf_hi as u64) << 32 | leaf_lo as u64;

            if current_depth + 1 == depth {
                let idx_byte = 12 + i * 12;
                if idx_byte + 12 > 60 {
                    break;
                }
                let ee_len_bytes: [u8; 4] = [
                    (raw[(idx_byte + 8) / 4] & 0xFF) as u8,
                    ((raw[(idx_byte + 8) / 4] >> 8) & 0xFF) as u8,
                    ((raw[(idx_byte + 8) / 4] >> 16) & 0xFF) as u8,
                    ((raw[(idx_byte + 8) / 4] >> 24) & 0xFF) as u8,
                ];
                let ee_len = u32::from_le_bytes(ee_len_bytes);
                let is_uninit = ee_len & 0x80000000 != 0;
                let len = (ee_len & 0x7FFFFFFF) as u64;
                if !is_uninit {
                    extents.push((ee_block, leaf, len));
                }
            } else {
                let child_block_data = self.read_block(leaf)?;
                let child_raw_u32: Vec<u32> = child_block_data
                    .chunks(4)
                    .map(|c| {
                        let mut arr = [0u8; 4];
                        arr[..c.len()].copy_from_slice(c);
                        u32::from_le_bytes(arr)
                    })
                    .collect();

                let child_magic = u16::from_le_bytes([
                    (child_raw_u32[0] & 0xFF) as u8,
                    ((child_raw_u32[0] >> 8) & 0xFF) as u8,
                ]);

                if child_magic == EXT4_EXT_MAGIC {
                    let child_depth_val = u16::from_le_bytes([
                        (child_raw_u32[1] & 0xFF) as u8,
                        ((child_raw_u32[1] >> 8) & 0xFF) as u8,
                    ]);
                    let child_entries = u16::from_le_bytes([
                        (child_raw_u32[2] & 0xFF) as u8,
                        ((child_raw_u32[2] >> 8) & 0xFF) as u8,
                    ]);

                    let as_array: [u32; 15] = {
                        let mut arr = [0u32; 15];
                        for j in 0..15.min(child_raw_u32.len()) {
                            arr[j] = child_raw_u32[j];
                        }
                        arr
                    };

                    if child_depth_val == 0 {
                        for k in 0..child_entries as usize {
                            let entry_byte = 12 + k * 12;
                            let ei = entry_byte / 4;
                            if ei + 2 >= child_raw_u32.len() {
                                break;
                            }
                            let eb: [u8; 4] = [
                                (child_raw_u32[ei] & 0xFF) as u8,
                                ((child_raw_u32[ei] >> 8) & 0xFF) as u8,
                                ((child_raw_u32[ei] >> 16) & 0xFF) as u8,
                                ((child_raw_u32[ei] >> 24) & 0xFF) as u8,
                            ];
                            let e_block = u32::from_le_bytes(eb);

                            let lb: [u8; 4] = [
                                (child_raw_u32[ei + 1] & 0xFF) as u8,
                                ((child_raw_u32[ei + 1] >> 8) & 0xFF) as u8,
                                ((child_raw_u32[ei + 1] >> 16) & 0xFF) as u8,
                                ((child_raw_u32[ei + 1] >> 24) & 0xFF) as u8,
                            ];
                            let e_start_lo = u32::from_le_bytes(lb);

                            let hb: [u8; 2] = [
                                (child_raw_u32[ei + 1] & 0xFF) as u8,
                                ((child_raw_u32[ei + 1] >> 8) & 0xFF) as u8,
                            ];
                            let e_start_hi = u16::from_le_bytes(hb);
                            let e_start = (e_start_hi as u64) << 32 | e_start_lo as u64;

                            let ln: [u8; 4] = [
                                (child_raw_u32[ei + 2] & 0xFF) as u8,
                                ((child_raw_u32[ei + 2] >> 8) & 0xFF) as u8,
                                ((child_raw_u32[ei + 2] >> 16) & 0xFF) as u8,
                                ((child_raw_u32[ei + 2] >> 24) & 0xFF) as u8,
                            ];
                            let e_len_raw = u32::from_le_bytes(ln);
                            let is_uninit = e_len_raw & 0x80000000 != 0;
                            let e_len = (e_len_raw & 0x7FFFFFFF) as u64;

                            if !is_uninit {
                                extents.push((e_block, e_start, e_len));
                            }
                        }
                    } else {
                        self.collect_extents_from_index(&as_array, child_entries, child_depth_val, extents, child_depth_val)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn read_indirect_data(&self, inode: &Ext4Inode, file_size: u64) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(file_size as usize);
        let mut file = File::open(&self.device_path)?;
        let blocks_per_block = self.block_size as usize / 4;

        for i in 0..EXT4_MAX_BLOCKS as usize {
            if result.len() >= file_size as usize {
                break;
            }
            let block_num = inode.block[i] as u64;
            if block_num == 0 {
                let zeros = vec![0u8; self.block_size as usize];
                result.extend_from_slice(&zeros);
                continue;
            }
            let mut buf = vec![0u8; self.block_size as usize];
            file.seek(SeekFrom::Start(self.block_offset(block_num)))?;
            file.read_exact(&mut buf)?;
            result.extend_from_slice(&buf);
        }

        let indirect_block = inode.block[EXT4_INDIRECT_BLOCK];
        if indirect_block != 0 && result.len() < file_size as usize {
            let mut indirect_buf = vec![0u8; self.block_size as usize];
            file.seek(SeekFrom::Start(self.block_offset(indirect_block as u64)))?;
            file.read_exact(&mut indirect_buf)?;

            for j in 0..blocks_per_block {
                if result.len() >= file_size as usize {
                    break;
                }
                let off = j * 4;
                let ptr = u32::from_le_bytes([
                    indirect_buf[off],
                    indirect_buf[off + 1],
                    indirect_buf[off + 2],
                    indirect_buf[off + 3],
                ]);
                if ptr == 0 {
                    continue;
                }
                let mut buf = vec![0u8; self.block_size as usize];
                file.seek(SeekFrom::Start(self.block_offset(ptr as u64)))?;
                file.read_exact(&mut buf)?;
                result.extend_from_slice(&buf);
            }
        }

        let dindirect_block = inode.block[EXT4_DINDIRECT_BLOCK];
        if dindirect_block != 0 && result.len() < file_size as usize {
            let mut dindirect_buf = vec![0u8; self.block_size as usize];
            file.seek(SeekFrom::Start(self.block_offset(dindirect_block as u64)))?;
            file.read_exact(&mut dindirect_buf)?;

            for j in 0..blocks_per_block {
                if result.len() >= file_size as usize {
                    break;
                }
                let off = j * 4;
                let ptr = u32::from_le_bytes([
                    dindirect_buf[off],
                    dindirect_buf[off + 1],
                    dindirect_buf[off + 2],
                    dindirect_buf[off + 3],
                ]);
                if ptr == 0 {
                    continue;
                }
                let mut indirect_buf = vec![0u8; self.block_size as usize];
                file.seek(SeekFrom::Start(self.block_offset(ptr as u64)))?;
                file.read_exact(&mut indirect_buf)?;

                for k in 0..blocks_per_block {
                    if result.len() >= file_size as usize {
                        break;
                    }
                    let koff = k * 4;
                    let kptr = u32::from_le_bytes([
                        indirect_buf[koff],
                        indirect_buf[koff + 1],
                        indirect_buf[koff + 2],
                        indirect_buf[koff + 3],
                    ]);
                    if kptr == 0 {
                        continue;
                    }
                    let mut buf = vec![0u8; self.block_size as usize];
                    file.seek(SeekFrom::Start(self.block_offset(kptr as u64)))?;
                    file.read_exact(&mut buf)?;
                    result.extend_from_slice(&buf);
                }
            }
        }

        if result.len() > file_size as usize {
            result.truncate(file_size as usize);
        }

        Ok(result)
    }

    fn read_inode_data(&self, inode: &Ext4Inode) -> Result<Vec<u8>> {
        let file_size = Self::inode_file_size(inode);
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let file_type = inode.mode & 0xF000;
        if file_type == EXT4_S_IFLNK {
            if inode.blocks_lo == 0 && inode.blocks_hi == 0 && file_size <= 60 {
                let mut data = Vec::with_capacity(file_size as usize);
                for i in 0..15u32 {
                    let bytes = inode.block[i as usize].to_le_bytes();
                    data.extend_from_slice(&bytes);
                }
                data.truncate(file_size as usize);
                return Ok(data);
            }
        }

        if inode.flags & EXT4_EXTENTS_FLAG != 0 {
            self.read_extent_tree_data(inode, file_size)
        } else {
            self.read_indirect_data(inode, file_size)
        }
    }

    fn parse_directory_entries(&self, inode: &Ext4Inode) -> Result<Vec<DirectoryEntry>> {
        let data = self.read_inode_data(inode)?;
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + 8 <= data.len() {
            let inode_num = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
            let name_len = data[offset + 6];
            let file_type = data[offset + 7];

            if rec_len == 0 {
                break;
            }

            if inode_num != 0 && name_len > 0 && offset + 8 + name_len as usize <= data.len() {
                let name_bytes = &data[offset + 8..offset + 8 + name_len as usize];
                let name = String::from_utf8_lossy(name_bytes).to_string();

                if name == "." || name == ".." {
                    offset += rec_len as usize;
                    continue;
                }

                let is_dir = file_type == EXT4_DIR_ENTRY_DIR;

                let child_inode = self.read_inode(inode_num as u64).ok();
                let (size, metadata) = if let Some(ref child) = child_inode {
                    let sz = Self::inode_file_size(child);
                    let md = self.inode_to_metadata(child);
                    (sz, Some(md))
                } else {
                    (0u64, None)
                };

                entries.push(DirectoryEntry {
                    name,
                    inode: inode_num as u64,
                    is_directory: is_dir,
                    size,
                    metadata,
                });
            }

            offset += rec_len as usize;
        }

        Ok(entries)
    }

    fn inode_to_metadata(&self, inode: &Ext4Inode) -> FileMetadata {
        let created = Self::ext4_time_to_datetime(inode.crtime, inode.crtime_extra);
        let modified = Self::ext4_time_to_datetime(inode.mtime, inode.mtime_extra);
        let accessed = Self::ext4_time_to_datetime(inode.atime, inode.atime_extra);

        let permissions = (inode.mode & 0xFFF) as u32;

        let uid = (inode.uid_hi as u32) << 16 | inode.uid as u32;
        let owner = Some(uid.to_string());

        let mut attributes = Vec::new();
        if inode.flags & EXT4_EXTENTS_FLAG != 0 {
            attributes.push("extents".to_string());
        }
        if inode.flags & 0x00000001 != 0 {
            attributes.push("secrm".to_string());
        }
        if inode.flags & 0x00000002 != 0 {
            attributes.push("unrm".to_string());
        }
        if inode.flags & 0x00000004 != 0 {
            attributes.push("compr".to_string());
        }
        if inode.flags & 0x00000008 != 0 {
            attributes.push("sync".to_string());
        }
        if inode.flags & 0x00000010 != 0 {
            attributes.push("immutable".to_string());
        }
        if inode.flags & 0x00000020 != 0 {
            attributes.push("append".to_string());
        }
        if inode.flags & 0x00000040 != 0 {
            attributes.push("nodump".to_string());
        }
        if inode.flags & 0x00010000 != 0 {
            attributes.push("journal_data".to_string());
        }
        if inode.links_count == 0 {
            attributes.push("deleted".to_string());
        }

        FileMetadata {
            created,
            modified,
            accessed,
            permissions: Some(permissions),
            owner,
            attributes,
        }
    }

    fn scan_deleted_inodes(&self) -> Result<Vec<FileEntry>> {
        let mut deleted = Vec::new();
        let descriptors = self.read_block_group_descriptors()?;

        for (group_idx, desc) in descriptors.iter().enumerate() {
            if desc.inode_table == 0 {
                continue;
            }

            let table_start = self.block_offset(desc.inode_table);
            let table_size = self.inodes_per_group as u64 * self.inode_size as u64;
            let mut file = File::open(&self.device_path)?;
            let mut table_buf = vec![0u8; table_size as usize];
            file.seek(SeekFrom::Start(table_start))?;
            if file.read_exact(&mut table_buf).is_err() {
                warn!("Failed to read inode table for group {}", group_idx);
                continue;
            }

            for i in 0..self.inodes_per_group as usize {
                let off = i * self.inode_size as usize;
                if off + self.inode_size as usize > table_buf.len() {
                    break;
                }
                let raw = &table_buf[off..off + self.inode_size as usize];

                let mode = u16::from_le_bytes([raw[0], raw[1]]);
                let links_count = u16::from_le_bytes([raw[26], raw[27]]);

                if mode != 0 && links_count == 0 {
                    let global_inode = group_idx as u64 * self.inodes_per_group as u64 + i as u64 + 1;
                    if global_inode <= EXT4_ROOT_INODE {
                        continue;
                    }

                    let file_size = (u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as u64)
                        | ((u32::from_le_bytes([raw[108], raw[109], raw[110], raw[111]]) as u64) << 32);

                    let mtime = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
                    let mtime_extra = u32::from_le_bytes([raw[124], raw[125], raw[126], raw[127]]);
                    let modified = Self::ext4_time_to_datetime(mtime, mtime_extra);

                    let is_dir = (mode & 0xF000) == EXT4_S_IFDIR;

                    let start_block_lo = u32::from_le_bytes([raw[40], raw[41], raw[42], raw[43]]);
                    let data_offset = self.block_offset(start_block_lo as u64);

                    let md = FileMetadata {
                        created: None,
                        modified,
                        accessed: None,
                        permissions: Some((mode & 0xFFF) as u32),
                        owner: None,
                        attributes: vec![
                            "deleted".to_string(),
                            if is_dir { "directory".to_string() } else { "file".to_string() },
                        ],
                    };

                    deleted.push(FileEntry {
                        inode: global_inode,
                        name: None,
                        size: file_size,
                        data_offset,
                        is_deleted: true,
                        metadata: Some(md),
                    });

                    if deleted.len() >= 10_000 {
                        return Ok(deleted);
                    }
                }
            }
        }

        Ok(deleted)
    }
}

impl FileSystem for EXT4Parser {
    fn read_superblock(&self) -> Result<SuperblockInfo> {
        let file = File::open(&self.device_path)?;
        let total_size = file.metadata()?.len();

        let created = Self::ext4_time_to_datetime(self.created_time, 0);

        let vol = if self.volume_name.is_empty() {
            None
        } else {
            Some(self.volume_name.clone())
        };

        Ok(SuperblockInfo {
            volume_name: vol,
            total_size,
            free_space: self.free_blocks * self.block_size as u64,
            block_size: self.block_size as u64,
            total_blocks: self.total_blocks,
            free_blocks: self.free_blocks,
            file_system_type: "ext4".to_string(),
            created_at: created,
        })
    }

    fn list_root_directory(&self) -> Result<Vec<DirectoryEntry>> {
        self.list_directory(EXT4_ROOT_INODE)
    }

    fn list_directory(&self, inode: u64) -> Result<Vec<DirectoryEntry>> {
        let dir_inode = self.read_inode(inode)?;
        if (dir_inode.mode & 0xF000) != EXT4_S_IFDIR {
            return Err(Error::InvalidDevice(format!("Inode {} is not a directory", inode)));
        }
        self.parse_directory_entries(&dir_inode)
    }

    fn read_file(&self, inode: u64) -> Result<Vec<u8>> {
        let file_inode = self.read_inode(inode)?;
        self.read_inode_data(&file_inode)
    }

    fn find_deleted_files(&self) -> Result<Vec<FileEntry>> {
        self.scan_deleted_inodes()
    }

    fn get_file_metadata(&self, inode: u64) -> Result<FileMetadata> {
        let file_inode = self.read_inode(inode)?;
        Ok(self.inode_to_metadata(&file_inode))
    }
}
