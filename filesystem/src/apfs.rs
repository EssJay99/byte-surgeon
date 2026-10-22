#![allow(dead_code)]
use crate::common::{FileSystem, SuperblockInfo, DirectoryEntry, FileEntry};
use bytesurgeon_core::{Result, Error, FileMetadata};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use tracing::{debug, warn};
use chrono::{DateTime, Utc, TimeZone};

const NX_MAGIC: u32 = 0x41504653;
const APFS_BLOCK_SIZE: u64 = 4096;
const APFS_MAX_BLOCK_SIZE: u64 = 65536;
const BNODE_TYPE_ROOT: u16 = 0x0000;
const BNODE_TYPE_LEAF: u16 = 0x0001;
const BNODE_META: u32 = 0x00000002;
const OBJECT_TYPE_BTREE_NODE: u32 = 3;
const OBJECT_TYPE_SPACEMAN: u32 = 17;
const OBJECT_TYPE_FSTREE: u32 = 4;
const OBJECT_TYPE_BLOCKREFTREE: u32 = 5;
const INUM_TRANS_TREE: u32 = 7;
const APFS_INVALID_OID: u64 = 0;
const DIR_REC_TYPE_DIR: u8 = 1;
const DIR_REC_TYPE_FILE: u8 = 2;
const DIR_REC_TYPE_SYMLINK: u8 = 3;
const DIR_REC_TYPE_SNAPSHOT: u8 = 4;
const FILE_FLAG_COMPRESSED: u64 = 0x00000001;
const FILE_FLAG_SPARSE: u64 = 0x00000010;
const FILE_FLAG_CLONE: u64 = 0x00000020;
const XATTR_FLAG_COMPRESSED: u64 = 0x0001;
const MAX_BTREE_DEPTH: usize = 8;
const MAX_SCAN_ENTRIES: usize = 10_000;

#[derive(Debug)]
enum FoundEntry {
    Leaf { value_data: Vec<u8> },
    Index { child_oid: u64 },
}

pub struct APFSParser {
    device_path: String,
    block_size: u64,
    total_blocks: u64,
    free_blocks: u64,
    nx_oid: u64,
    nx_xid: u64,
    nx_checksum: u64,
    volume_oids: Vec<u64>,
    volume_blocks: Vec<u64>,
    volume_superblock_oid: u64,
    container_block_count: u64,
    spaceman_oid: u64,
    root_tree_oid: u64,
    snap_meta_tree_oid: u64,
}

#[derive(Debug, Clone)]
struct APFSNode {
    node_type: u32,
    level: u16,
    key_count: u32,
    keys_offset: u32,
    values_offset: u32,
    free_space_offset: u32,
}

#[derive(Debug, Clone)]
struct APFSVolumeSuperblock {
    oid: u64,
    create_time: i64,
    modified_time: i64,
    volume_name: String,
    root_tree_oid: u64,
    extent_ref_tree_oid: u64,
    snap_meta_tree_oid: u64,
    total_blocks: u64,
    free_blocks: u64,
    block_size: u64,
    flags: u64,
}

#[derive(Debug, Clone)]
struct APFSBtreeKey {
    offset: u16,
    length: u16,
}

#[derive(Debug, Clone)]
struct APFSBtreeValue {
    offset: u16,
    length: u16,
}

#[derive(Debug, Clone)]
struct APFSInodeKey {
    inode_id: u64,
    obj_type: u32,
}

#[derive(Debug, Clone)]
struct APFSInodeValue {
    inode_id: u64,
    flags: u64,
    size: u64,
    create_time: i64,
    modified_time: i64,
    accessed_time: i64,
    mode: u16,
    uid: u32,
    gid: u32,
    parent_id: u64,
    clone_id: u64,
    xattr_count: u32,
    compression_algorithm: u16,
}

#[derive(Debug, Clone)]
struct APFSDirEntry {
    name: String,
    file_id: u64,
    entry_type: u8,
}

#[derive(Debug, Clone)]
struct APFSExtentKey {
    inode_id: u64,
    logical_addr: u64,
}

#[derive(Debug, Clone)]
struct APFSExtentValue {
    phys_addr: u64,
    length: u64,
    flags: u64,
}

impl APFSParser {
    pub fn new(device_path: &str) -> Result<Self> {
        let mut parser = Self {
            device_path: device_path.to_string(),
            block_size: APFS_BLOCK_SIZE,
            total_blocks: 0,
            free_blocks: 0,
            nx_oid: 0,
            nx_xid: 0,
            nx_checksum: 0,
            volume_oids: Vec::new(),
            volume_blocks: Vec::new(),
            volume_superblock_oid: 0,
            container_block_count: 0,
            spaceman_oid: 0,
            root_tree_oid: 0,
            snap_meta_tree_oid: 0,
        };

        parser.read_nx_superblock()?;
        Ok(parser)
    }

    fn read_nx_superblock(&mut self) -> Result<()> {
        let mut file = File::open(&self.device_path)?;
        let mut buffer = [0u8; 4096];

        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut buffer)?;

        let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        if magic != NX_MAGIC {
            return Err(Error::InvalidDevice("Not an APFS volume".to_string()));
        }

        self.nx_checksum = u64::from_le_bytes([
            buffer[8], buffer[9], buffer[10], buffer[11],
            buffer[12], buffer[13], buffer[14], buffer[15],
        ]);

        self.nx_oid = u64::from_le_bytes([
            buffer[16], buffer[17], buffer[18], buffer[19],
            buffer[20], buffer[21], buffer[22], buffer[23],
        ]);

        self.nx_xid = u64::from_le_bytes([
            buffer[24], buffer[25], buffer[26], buffer[27],
            buffer[28], buffer[29], buffer[30], buffer[31],
        ]);

        self.block_size = u32::from_le_bytes([buffer[32], buffer[33], buffer[34], buffer[35]]) as u64;
        if self.block_size == 0 || (self.block_size & (self.block_size - 1)) != 0 {
            self.block_size = APFS_BLOCK_SIZE;
        }

        self.container_block_count = u64::from_le_bytes([
            buffer[40], buffer[41], buffer[42], buffer[43],
            buffer[44], buffer[45], buffer[46], buffer[47],
        ]);

        self.total_blocks = self.container_block_count;

        let block_count_offset = u32::from_le_bytes([buffer[56], buffer[57], buffer[58], buffer[59]]);
        if block_count_offset != 0 {
            self.free_blocks = u64::from_le_bytes([
                buffer[64], buffer[65], buffer[66], buffer[67],
                buffer[68], buffer[69], buffer[70], buffer[71],
            ]);
        }

        self.spaceman_oid = u64::from_le_bytes([
            buffer[80], buffer[81], buffer[82], buffer[83],
            buffer[84], buffer[85], buffer[86], buffer[87],
        ]);

        self.root_tree_oid = u64::from_le_bytes([
            buffer[144], buffer[145], buffer[146], buffer[147],
            buffer[148], buffer[149], buffer[150], buffer[151],
        ]);

        let num_volumes = u32::from_le_bytes([buffer[152], buffer[153], buffer[154], buffer[155]]);

        self.volume_oids.clear();
        self.volume_blocks.clear();
        for i in 0..num_volumes.min(4) as usize {
            let base = 160 + i * 16;
            let v_oid = u64::from_le_bytes([
                buffer[base], buffer[base + 1], buffer[base + 2], buffer[base + 3],
                buffer[base + 4], buffer[base + 5], buffer[base + 6], buffer[base + 7],
            ]);
            let v_blocks = u64::from_le_bytes([
                buffer[base + 8], buffer[base + 9], buffer[base + 10], buffer[base + 11],
                buffer[base + 12], buffer[base + 13], buffer[base + 14], buffer[base + 15],
            ]);
            self.volume_oids.push(v_oid);
            self.volume_blocks.push(v_blocks);
        }

        self.snap_meta_tree_oid = u64::from_le_bytes([
            buffer[208], buffer[209], buffer[210], buffer[211],
            buffer[212], buffer[213], buffer[214], buffer[215],
        ]);

        if !self.volume_oids.is_empty() {
            self.volume_superblock_oid = self.volume_oids[0];
        }

        debug!(
            "APFS NX Superblock - Block size: {}, Total blocks: {}, Free blocks: {}, Volumes: {}",
            self.block_size, self.total_blocks, self.free_blocks, num_volumes
        );

        Ok(())
    }

    fn block_offset(&self, block: u64) -> u64 {
        block * self.block_size
    }

    fn read_block(&self, block: u64) -> Result<Vec<u8>> {
        let mut file = File::open(&self.device_path)?;
        let mut buffer = vec![0u8; self.block_size as usize];
        file.seek(SeekFrom::Start(self.block_offset(block)))?;
        file.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn apfs_time_to_datetime(apfs_ns: i64) -> Option<DateTime<Utc>> {
        if apfs_ns == 0 {
            return None;
        }
        let secs = apfs_ns / 1_000_000_000;
        let nsecs = (apfs_ns % 1_000_000_000) as u32;
        Utc.timestamp_opt(secs, nsecs).single()
    }

    fn read_volume_superblock(&self) -> Result<APFSVolumeSuperblock> {
        let block = self.read_block(self.volume_superblock_oid)?;

        let magic = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        if magic != NX_MAGIC {
            let alt_block = self.read_block(self.volume_superblock_oid + 1)?;
            let alt_magic = u32::from_le_bytes([alt_block[0], alt_block[1], alt_block[2], alt_block[3]]);
            if alt_magic != NX_MAGIC {
                return self.synthesize_volume_superblock();
            }
            return self.parse_volume_superblock_from_block(&alt_block);
        }

        self.parse_volume_superblock_from_block(&block)
    }

    fn synthesize_volume_superblock(&self) -> Result<APFSVolumeSuperblock> {
        Ok(APFSVolumeSuperblock {
            oid: self.volume_superblock_oid,
            create_time: 0,
            modified_time: 0,
            volume_name: String::new(),
            root_tree_oid: self.root_tree_oid,
            extent_ref_tree_oid: 0,
            snap_meta_tree_oid: self.snap_meta_tree_oid,
            total_blocks: self.total_blocks,
            free_blocks: self.free_blocks,
            block_size: self.block_size,
            flags: 0,
        })
    }

    fn parse_volume_superblock_from_block(&self, block: &[u8]) -> Result<APFSVolumeSuperblock> {
        let oid = u64::from_le_bytes([
            block[16], block[17], block[18], block[19],
            block[20], block[21], block[22], block[23],
        ]);

        let create_time = i64::from_le_bytes([
            block[24], block[25], block[26], block[27],
            block[28], block[29], block[30], block[31],
        ]);
        let modified_time = i64::from_le_bytes([
            block[32], block[33], block[34], block[35],
            block[36], block[37], block[38], block[39],
        ]);

        let mut vol_name_bytes = [0u8; 256];
        let name_len = u16::from_le_bytes([block[40], block[41]]);
        let copy_len = (name_len as usize).min(255).min(block.len().saturating_sub(42));
        vol_name_bytes[..copy_len].copy_from_slice(&block[42..42 + copy_len]);
        let volume_name = String::from_utf8_lossy(&vol_name_bytes[..copy_len])
            .trim_end_matches('\0')
            .to_string();

        let root_tree_oid = u64::from_le_bytes([
            block[300], block[301], block[302], block[303],
            block[304], block[305], block[306], block[307],
        ]);
        let extent_ref_tree_oid = u64::from_le_bytes([
            block[308], block[309], block[310], block[311],
            block[312], block[313], block[314], block[315],
        ]);
        let snap_meta_tree_oid = u64::from_le_bytes([
            block[316], block[317], block[318], block[319],
            block[320], block[321], block[322], block[323],
        ]);

        let total_blocks = u64::from_le_bytes([
            block[324], block[325], block[326], block[327],
            block[328], block[329], block[330], block[331],
        ]);
        let free_blocks = u64::from_le_bytes([
            block[332], block[333], block[334], block[335],
            block[336], block[337], block[338], block[339],
        ]);

        let flags = u64::from_le_bytes([
            block[340], block[341], block[342], block[343],
            block[344], block[345], block[346], block[347],
        ]);

        Ok(APFSVolumeSuperblock {
            oid,
            create_time,
            modified_time,
            volume_name,
            root_tree_oid,
            extent_ref_tree_oid,
            snap_meta_tree_oid,
            total_blocks,
            free_blocks,
            block_size: self.block_size,
            flags,
        })
    }

    fn parse_btree_node(&self, block_data: &[u8]) -> Result<APFSNode> {
        if block_data.len() < 56 {
            return Err(Error::InvalidDevice("Block too small for B-tree node".to_string()));
        }

        let obj_type = u32::from_le_bytes([
            block_data[8], block_data[9], block_data[10], block_data[11],
        ]);

        let subtype = u32::from_le_bytes([
            block_data[12], block_data[13], block_data[14], block_data[15],
        ]);

        let _ = subtype;
        let level = u16::from_le_bytes([block_data[16], block_data[17]]);
        let key_count = u32::from_le_bytes([
            block_data[18], block_data[19], block_data[20], block_data[21],
        ]);
        let keys_offset = u32::from_le_bytes([
            block_data[22], block_data[23], block_data[24], block_data[25],
        ]);
        let values_offset = u32::from_le_bytes([
            block_data[26], block_data[27], block_data[28], block_data[29],
        ]);
        let free_space_offset = u32::from_le_bytes([
            block_data[30], block_data[31], block_data[32], block_data[33],
        ]);

        let _ = obj_type;

        Ok(APFSNode {
            node_type: obj_type,
            level,
            key_count,
            keys_offset,
            values_offset,
            free_space_offset,
        })
    }

    fn read_btree_node(&self, oid: u64) -> Result<Vec<u8>> {
        if oid == 0 || oid >= self.total_blocks {
            return Ok(Vec::new());
        }
        self.read_block(oid)
    }

    fn btree_lookup_inode(&self, root_oid: u64, target_inode: u64) -> Result<Option<APFSInodeValue>> {
        if root_oid == 0 {
            return Ok(None);
        }

        let mut current_oid = root_oid;
        let mut depth = 0;

        loop {
            if depth > MAX_BTREE_DEPTH {
                break;
            }

            let block_data = self.read_btree_node(current_oid)?;
            if block_data.is_empty() {
                break;
            }

            let node = self.parse_btree_node(&block_data)?;
            if node.key_count == 0 {
                break;
            }

            let found = self.search_node_for_inode(&block_data, &node, target_inode)?;

            match found {
                Some(FoundEntry::Leaf { value_data }) => {
                    let inode_val = self.parse_inode_value(&value_data, target_inode)?;
                    return Ok(Some(inode_val));
                }
                Some(FoundEntry::Index { child_oid }) => {
                    current_oid = child_oid;
                    depth += 1;
                }
                None => {
                    break;
                }
            }
        }

        Ok(None)
    }

    fn search_node_for_inode(&self, block_data: &[u8], node: &APFSNode, target_inode: u64) -> Result<Option<FoundEntry>> {
        let header_size = 56;
        if header_size as usize > block_data.len() {
            return Ok(None);
        }

        let mut best_match: Option<(u64, usize)> = None;

        for i in 0..node.key_count as usize {
            let key_header_offset = node.keys_offset as usize + i * 4;
            if key_header_offset + 4 > block_data.len() {
                break;
            }

            let key_off = u16::from_le_bytes([
                block_data[key_header_offset],
                block_data[key_header_offset + 1],
            ]);
            let _key_len = u16::from_le_bytes([
                block_data[key_header_offset + 2],
                block_data[key_header_offset + 3],
            ]);

            let key_data_start = key_off as usize;
            if key_data_start + 12 > block_data.len() {
                continue;
            }

            let key_inode = u64::from_le_bytes([
                block_data[key_data_start],
                block_data[key_data_start + 1],
                block_data[key_data_start + 2],
                block_data[key_data_start + 3],
                block_data[key_data_start + 4],
                block_data[key_data_start + 5],
                block_data[key_data_start + 6],
                block_data[key_data_start + 7],
            ]);

            let key_obj_type = u32::from_le_bytes([
                block_data[key_data_start + 8],
                block_data[key_data_start + 9],
                block_data[key_data_start + 10],
                block_data[key_data_start + 11],
            ]);

            if key_inode == target_inode && (key_obj_type == 1 || key_obj_type == 0) {
                let val_header_offset = node.values_offset as usize + i * 4;
                if val_header_offset + 4 > block_data.len() {
                    continue;
                }

                let val_off = u16::from_le_bytes([
                    block_data[val_header_offset],
                    block_data[val_header_offset + 1],
                ]);
                let val_len = u16::from_le_bytes([
                    block_data[val_header_offset + 2],
                    block_data[val_header_offset + 3],
                ]);

                let val_data_start = val_off as usize;
                let val_data_end = val_data_start + val_len as usize;

                if val_data_end <= block_data.len() {
                    if node.level == 0 {
                        return Ok(Some(FoundEntry::Leaf {
                            value_data: block_data[val_data_start..val_data_end].to_vec(),
                        }));
                    } else {
                        let child_oid = u64::from_le_bytes([
                            block_data[val_data_start],
                            block_data[val_data_start + 1],
                            block_data[val_data_start + 2],
                            block_data[val_data_start + 3],
                            block_data[val_data_start + 4],
                            block_data[val_data_start + 5],
                            block_data[val_data_start + 6],
                            block_data[val_data_start + 7],
                        ]);
                        return Ok(Some(FoundEntry::Index { child_oid }));
                    }
                }
            }

            if key_inode <= target_inode {
                let current = best_match.map(|(id, _)| id).unwrap_or(0);
                if key_inode > current || best_match.is_none() {
                    let val_header_offset = node.values_offset as usize + i * 4;
                    if val_header_offset + 4 <= block_data.len() {
                        best_match = Some((key_inode, i));
                    }
                }
            }
        }

        if let Some((_, idx)) = best_match {
            if node.level > 0 {
                let val_header_offset = node.values_offset as usize + idx * 4;
                if val_header_offset + 4 <= block_data.len() {
                    let val_off = u16::from_le_bytes([
                        block_data[val_header_offset],
                        block_data[val_header_offset + 1],
                    ]);
                    let val_len = u16::from_le_bytes([
                        block_data[val_header_offset + 2],
                        block_data[val_header_offset + 3],
                    ]);

                    let val_data_start = val_off as usize;
                    let val_data_end = val_data_start + val_len as usize;

                    if val_data_end <= block_data.len() {
                        let child_oid = u64::from_le_bytes([
                            block_data[val_data_start],
                            block_data[val_data_start + 1],
                            block_data[val_data_start + 2],
                            block_data[val_data_start + 3],
                            block_data[val_data_start + 4],
                            block_data[val_data_start + 5],
                            block_data[val_data_start + 6],
                            block_data[val_data_start + 7],
                        ]);
                        if child_oid != 0 {
                            return Ok(Some(FoundEntry::Index { child_oid }));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn parse_inode_value(&self, data: &[u8], inode_id: u64) -> Result<APFSInodeValue> {
        if data.len() < 56 {
            return Ok(APFSInodeValue {
                inode_id,
                flags: 0,
                size: 0,
                create_time: 0,
                modified_time: 0,
                accessed_time: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                parent_id: 0,
                clone_id: 0,
                xattr_count: 0,
                compression_algorithm: 0,
            });
        }

        let flags = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        let size = u64::from_le_bytes([
            data[8], data[9], data[10], data[11],
            data[12], data[13], data[14], data[15],
        ]);
        let create_time = i64::from_le_bytes([
            data[16], data[17], data[18], data[19],
            data[20], data[21], data[22], data[23],
        ]);
        let modified_time = i64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]);
        let accessed_time = i64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39],
        ]);
        let mode = u16::from_le_bytes([data[40], data[41]]);
        let uid = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let gid = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);

        let parent_id = if data.len() >= 64 {
            u64::from_le_bytes([
                data[56], data[57], data[58], data[59],
                data[60], data[61], data[62], data[63],
            ])
        } else {
            0
        };

        let clone_id = if data.len() >= 72 {
            u64::from_le_bytes([
                data[64], data[65], data[66], data[67],
                data[68], data[69], data[70], data[71],
            ])
        } else {
            0
        };

        let xattr_count = if data.len() >= 80 {
            u32::from_le_bytes([data[76], data[77], data[78], data[79]])
        } else {
            0
        };

        let compression_algorithm = if data.len() >= 82 {
            u16::from_le_bytes([data[80], data[81]])
        } else {
            0
        };

        Ok(APFSInodeValue {
            inode_id,
            flags,
            size,
            create_time,
            modified_time,
            accessed_time,
            mode,
            uid,
            gid,
            parent_id,
            clone_id,
            xattr_count,
            compression_algorithm,
        })
    }

    fn btree_list_directory_entries(&self, root_oid: u64, parent_inode: u64) -> Result<Vec<APFSDirEntry>> {
        if root_oid == 0 {
            return Ok(Vec::new());
        }

        let mut dir_entries = Vec::new();
        let mut current_oid = root_oid;
        let mut depth = 0;
        let mut leaf_nodes = Vec::new();

        loop {
            if depth > MAX_BTREE_DEPTH {
                break;
            }

            let block_data = self.read_btree_node(current_oid)?;
            if block_data.is_empty() {
                break;
            }

            let node = self.parse_btree_node(&block_data)?;
            if node.key_count == 0 {
                break;
            }

            if node.level == 0 {
                leaf_nodes.push(block_data);
                break;
            } else {
                let mut found_child = false;
                for i in 0..node.key_count as usize {
                    let key_header_offset = node.keys_offset as usize + i * 4;
                    if key_header_offset + 4 > block_data.len() {
                        break;
                    }

                    let key_off = u16::from_le_bytes([
                        block_data[key_header_offset],
                        block_data[key_header_offset + 1],
                    ]);

                    let key_data_start = key_off as usize;
                    if key_data_start + 8 > block_data.len() {
                        continue;
                    }

                    let key_parent = u64::from_le_bytes([
                        block_data[key_data_start],
                        block_data[key_data_start + 1],
                        block_data[key_data_start + 2],
                        block_data[key_data_start + 3],
                        block_data[key_data_start + 4],
                        block_data[key_data_start + 5],
                        block_data[key_data_start + 6],
                        block_data[key_data_start + 7],
                    ]);

                    if key_parent == parent_inode {
                        let val_header_offset = node.values_offset as usize + i * 4;
                        if val_header_offset + 4 <= block_data.len() {
                            let val_off = u16::from_le_bytes([
                                block_data[val_header_offset],
                                block_data[val_header_offset + 1],
                            ]);
                            let val_data_start = val_off as usize;
                            if val_data_start + 8 <= block_data.len() {
                                let child_oid = u64::from_le_bytes([
                                    block_data[val_data_start],
                                    block_data[val_data_start + 1],
                                    block_data[val_data_start + 2],
                                    block_data[val_data_start + 3],
                                    block_data[val_data_start + 4],
                                    block_data[val_data_start + 5],
                                    block_data[val_data_start + 6],
                                    block_data[val_data_start + 7],
                                ]);
                                if child_oid != 0 {
                                    current_oid = child_oid;
                                    found_child = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if !found_child {
                    break;
                }
                depth += 1;
            }
        }

        for block_data in &leaf_nodes {
            let node = self.parse_btree_node(block_data)?;

            for i in 0..node.key_count as usize {
                let key_header_offset = node.keys_offset as usize + i * 4;
                if key_header_offset + 4 > block_data.len() {
                    break;
                }

                let key_off = u16::from_le_bytes([
                    block_data[key_header_offset],
                    block_data[key_header_offset + 1],
                ]);
                let key_len = u16::from_le_bytes([
                    block_data[key_header_offset + 2],
                    block_data[key_header_offset + 3],
                ]);

                let key_data_start = key_off as usize;
                if key_data_start + key_len as usize > block_data.len() || key_len < 8 {
                    continue;
                }

                let key_parent = u64::from_le_bytes([
                    block_data[key_data_start],
                    block_data[key_data_start + 1],
                    block_data[key_data_start + 2],
                    block_data[key_data_start + 3],
                    block_data[key_data_start + 4],
                    block_data[key_data_start + 5],
                    block_data[key_data_start + 6],
                    block_data[key_data_start + 7],
                ]);

                if key_parent != parent_inode {
                    continue;
                }

                let val_header_offset = node.values_offset as usize + i * 4;
                if val_header_offset + 4 > block_data.len() {
                    continue;
                }

                let val_off = u16::from_le_bytes([
                    block_data[val_header_offset],
                    block_data[val_header_offset + 1],
                ]);
                let val_len = u16::from_le_bytes([
                    block_data[val_header_offset + 2],
                    block_data[val_header_offset + 3],
                ]);

                let val_data_start = val_off as usize;
                let val_data_end = val_data_start + val_len as usize;
                if val_data_end > block_data.len() || val_len < 10 {
                    continue;
                }

                let val_data = &block_data[val_data_start..val_data_end];
                let file_id = u64::from_le_bytes([
                    val_data[0], val_data[1], val_data[2], val_data[3],
                    val_data[4], val_data[5], val_data[6], val_data[7],
                ]);
                let entry_type = val_data[8];

                let name_len = u16::from_le_bytes([val_data[9], val_data[10]]);
                let name_start = 11;
                let name_end = name_start + name_len as usize;
                let name = if name_end <= val_data.len() {
                    String::from_utf8_lossy(&val_data[name_start..name_end])
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::from_utf8_lossy(&val_data[name_start..])
                        .trim_end_matches('\0')
                        .to_string()
                };

                dir_entries.push(APFSDirEntry {
                    name,
                    file_id,
                    entry_type,
                });

                if dir_entries.len() >= MAX_SCAN_ENTRIES {
                    break;
                }
            }
        }

        Ok(dir_entries)
    }

    fn btree_lookup_extents(&self, root_oid: u64, inode_id: u64) -> Result<Vec<APFSExtentValue>> {
        if root_oid == 0 {
            return Ok(Vec::new());
        }

        let mut extents = Vec::new();
        let mut current_oid = root_oid;
        let mut depth = 0;
        let mut visited_leaves = Vec::new();

        loop {
            if depth > MAX_BTREE_DEPTH {
                break;
            }

            let block_data = self.read_btree_node(current_oid)?;
            if block_data.is_empty() {
                break;
            }

            let node = self.parse_btree_node(&block_data)?;
            if node.key_count == 0 {
                break;
            }

            if node.level == 0 {
                visited_leaves.push(block_data);
                break;
            } else {
                let mut found_child = false;
                for i in 0..node.key_count as usize {
                    let key_header_offset = node.keys_offset as usize + i * 4;
                    if key_header_offset + 4 > block_data.len() {
                        break;
                    }

                    let key_off = u16::from_le_bytes([
                        block_data[key_header_offset],
                        block_data[key_header_offset + 1],
                    ]);

                    let key_data_start = key_off as usize;
                    if key_data_start + 16 > block_data.len() {
                        continue;
                    }

                    let key_inode = u64::from_le_bytes([
                        block_data[key_data_start],
                        block_data[key_data_start + 1],
                        block_data[key_data_start + 2],
                        block_data[key_data_start + 3],
                        block_data[key_data_start + 4],
                        block_data[key_data_start + 5],
                        block_data[key_data_start + 6],
                        block_data[key_data_start + 7],
                    ]);

                    if key_inode <= inode_id {
                        let val_header_offset = node.values_offset as usize + i * 4;
                        if val_header_offset + 4 <= block_data.len() {
                            let val_off = u16::from_le_bytes([
                                block_data[val_header_offset],
                                block_data[val_header_offset + 1],
                            ]);
                            let val_data_start = val_off as usize;
                            if val_data_start + 8 <= block_data.len() {
                                let child_oid = u64::from_le_bytes([
                                    block_data[val_data_start],
                                    block_data[val_data_start + 1],
                                    block_data[val_data_start + 2],
                                    block_data[val_data_start + 3],
                                    block_data[val_data_start + 4],
                                    block_data[val_data_start + 5],
                                    block_data[val_data_start + 6],
                                    block_data[val_data_start + 7],
                                ]);
                                if child_oid != 0 {
                                    current_oid = child_oid;
                                    found_child = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if !found_child {
                    break;
                }
                depth += 1;
            }
        }

        for block_data in &visited_leaves {
            let node = self.parse_btree_node(block_data)?;

            for i in 0..node.key_count as usize {
                let key_header_offset = node.keys_offset as usize + i * 4;
                if key_header_offset + 4 > block_data.len() {
                    break;
                }

                let key_off = u16::from_le_bytes([
                    block_data[key_header_offset],
                    block_data[key_header_offset + 1],
                ]);
                let key_len = u16::from_le_bytes([
                    block_data[key_header_offset + 2],
                    block_data[key_header_offset + 3],
                ]);

                let key_data_start = key_off as usize;
                if key_data_start + 16 > block_data.len() || key_len < 16 {
                    continue;
                }

                let key_inode = u64::from_le_bytes([
                    block_data[key_data_start],
                    block_data[key_data_start + 1],
                    block_data[key_data_start + 2],
                    block_data[key_data_start + 3],
                    block_data[key_data_start + 4],
                    block_data[key_data_start + 5],
                    block_data[key_data_start + 6],
                    block_data[key_data_start + 7],
                ]);

                if key_inode != inode_id {
                    continue;
                }

                let val_header_offset = node.values_offset as usize + i * 4;
                if val_header_offset + 4 > block_data.len() {
                    continue;
                }

                let val_off = u16::from_le_bytes([
                    block_data[val_header_offset],
                    block_data[val_header_offset + 1],
                ]);
                let val_len = u16::from_le_bytes([
                    block_data[val_header_offset + 2],
                    block_data[val_header_offset + 3],
                ]);

                let val_data_start = val_off as usize;
                let val_data_end = val_data_start + val_len as usize;
                if val_data_end > block_data.len() || val_len < 24 {
                    continue;
                }

                let val_data = &block_data[val_data_start..val_data_end];
                let phys_addr = u64::from_le_bytes([
                    val_data[0], val_data[1], val_data[2], val_data[3],
                    val_data[4], val_data[5], val_data[6], val_data[7],
                ]);
                let length = u64::from_le_bytes([
                    val_data[8], val_data[9], val_data[10], val_data[11],
                    val_data[12], val_data[13], val_data[14], val_data[15],
                ]);
                let flags = u64::from_le_bytes([
                    val_data[16], val_data[17], val_data[18], val_data[19],
                    val_data[20], val_data[21], val_data[22], val_data[23],
                ]);

                extents.push(APFSExtentValue {
                    phys_addr,
                    length,
                    flags,
                });
            }
        }

        Ok(extents)
    }

    fn scan_for_deleted_files(&self) -> Result<Vec<FileEntry>> {
        let mut deleted = Vec::new();
        let vol_sb = self.read_volume_superblock()?;

        if vol_sb.snap_meta_tree_oid != 0 {
            let snap_entries = self.scan_snapshot_metadata(vol_sb.snap_meta_tree_oid)?;
            deleted.extend(snap_entries);
        }

        if deleted.is_empty() && self.root_tree_oid != 0 {
            deleted = self.scan_btree_for_deleted(self.root_tree_oid, vol_sb.root_tree_oid)?;
        }

        Ok(deleted)
    }

    fn scan_snapshot_metadata(&self, snap_tree_oid: u64) -> Result<Vec<FileEntry>> {
        let mut deleted = Vec::new();
        let mut current_oid = snap_tree_oid;
        let mut depth = 0;

        loop {
            if depth > MAX_BTREE_DEPTH {
                break;
            }

            let block_data = self.read_btree_node(current_oid)?;
            if block_data.is_empty() {
                break;
            }

            let node = self.parse_btree_node(&block_data)?;
            if node.key_count == 0 {
                break;
            }

            if node.level == 0 {
                for i in 0..node.key_count as usize {
                    let key_header_offset = node.keys_offset as usize + i * 4;
                    if key_header_offset + 4 > block_data.len() {
                        break;
                    }

                    let val_header_offset = node.values_offset as usize + i * 4;
                    if val_header_offset + 4 > block_data.len() {
                        continue;
                    }

                    let val_off = u16::from_le_bytes([
                        block_data[val_header_offset],
                        block_data[val_header_offset + 1],
                    ]);
                    let val_len = u16::from_le_bytes([
                        block_data[val_header_offset + 2],
                        block_data[val_header_offset + 3],
                    ]);

                    let val_data_start = val_off as usize;
                    let val_data_end = val_data_start + val_len as usize;
                    if val_data_end > block_data.len() || val_len < 32 {
                        continue;
                    }

                    let val_data = &block_data[val_data_start..val_data_end];
                    let snap_xid = u64::from_le_bytes([
                        val_data[0], val_data[1], val_data[2], val_data[3],
                        val_data[4], val_data[5], val_data[6], val_data[7],
                    ]);
                    let snap_flags = u64::from_le_bytes([
                        val_data[8], val_data[9], val_data[10], val_data[11],
                        val_data[12], val_data[13], val_data[14], val_data[15],
                    ]);
                    let tree_oid = u64::from_le_bytes([
                        val_data[16], val_data[17], val_data[18], val_data[19],
                        val_data[20], val_data[21], val_data[22], val_data[23],
                    ]);
                    let create_time = i64::from_le_bytes([
                        val_data[24], val_data[25], val_data[26], val_data[27],
                        val_data[28], val_data[29], val_data[30], val_data[31],
                    ]);

                    let _ = snap_xid;
                    let _ = snap_flags;
                    let _ = tree_oid;

                    let created = Self::apfs_time_to_datetime(create_time);

                    let name_start = 32;
                    let name = if name_start < val_data.len() {
                        let name_bytes = &val_data[name_start..];
                        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                        String::from_utf8_lossy(&name_bytes[..end]).to_string()
                    } else {
                        format!("snapshot_{}", i)
                    };

                    let md = FileMetadata {
                        created,
                        modified: None,
                        accessed: None,
                        permissions: None,
                        owner: None,
                        attributes: vec!["snapshot_deleted".to_string()],
                    };

                    deleted.push(FileEntry {
                        inode: i as u64 + 1_000_000,
                        name: Some(name),
                        size: 0,
                        data_offset: 0,
                        is_deleted: true,
                        metadata: Some(md),
                    });

                    if deleted.len() >= MAX_SCAN_ENTRIES {
                        return Ok(deleted);
                    }
                }
                break;
            } else {
                let val_header_offset = node.values_offset as usize;
                if val_header_offset + 4 > block_data.len() {
                    break;
                }
                let val_off = u16::from_le_bytes([
                    block_data[val_header_offset],
                    block_data[val_header_offset + 1],
                ]);
                let val_data_start = val_off as usize;
                if val_data_start + 8 > block_data.len() {
                    break;
                }
                let child_oid = u64::from_le_bytes([
                    block_data[val_data_start],
                    block_data[val_data_start + 1],
                    block_data[val_data_start + 2],
                    block_data[val_data_start + 3],
                    block_data[val_data_start + 4],
                    block_data[val_data_start + 5],
                    block_data[val_data_start + 6],
                    block_data[val_data_start + 7],
                ]);
                if child_oid == 0 {
                    break;
                }
                current_oid = child_oid;
                depth += 1;
            }
        }

        Ok(deleted)
    }

    fn scan_btree_for_deleted(&self, _fs_tree_oid: u64, root_tree_oid: u64) -> Result<Vec<FileEntry>> {
        let mut deleted = Vec::new();
        let mut current_oid = root_tree_oid;
        let mut depth = 0;
        let mut leaf_nodes = Vec::new();

        loop {
            if depth > MAX_BTREE_DEPTH {
                break;
            }

            let block_data = self.read_btree_node(current_oid)?;
            if block_data.is_empty() {
                break;
            }

            let node = self.parse_btree_node(&block_data)?;
            if node.key_count == 0 {
                break;
            }

            if node.level == 0 {
                leaf_nodes.push(block_data);
                break;
            }

            let val_header_offset = node.values_offset as usize;
            if val_header_offset + 4 > block_data.len() {
                break;
            }
            let val_off = u16::from_le_bytes([
                block_data[val_header_offset],
                block_data[val_header_offset + 1],
            ]);
            let val_data_start = val_off as usize;
            if val_data_start + 8 > block_data.len() {
                break;
            }
            let child_oid = u64::from_le_bytes([
                block_data[val_data_start],
                block_data[val_data_start + 1],
                block_data[val_data_start + 2],
                block_data[val_data_start + 3],
                block_data[val_data_start + 4],
                block_data[val_data_start + 5],
                block_data[val_data_start + 6],
                block_data[val_data_start + 7],
            ]);
            if child_oid == 0 {
                break;
            }
            current_oid = child_oid;
            depth += 1;
        }

        for block_data in &leaf_nodes {
            let node = self.parse_btree_node(block_data)?;

            for i in 0..node.key_count as usize {
                let key_header_offset = node.keys_offset as usize + i * 4;
                if key_header_offset + 4 > block_data.len() {
                    break;
                }

                let key_off = u16::from_le_bytes([
                    block_data[key_header_offset],
                    block_data[key_header_offset + 1],
                ]);
                let key_len = u16::from_le_bytes([
                    block_data[key_header_offset + 2],
                    block_data[key_header_offset + 3],
                ]);

                let key_data_start = key_off as usize;
                if key_data_start + 12 > block_data.len() || key_len < 12 {
                    continue;
                }

                let inode_id = u64::from_le_bytes([
                    block_data[key_data_start],
                    block_data[key_data_start + 1],
                    block_data[key_data_start + 2],
                    block_data[key_data_start + 3],
                    block_data[key_data_start + 4],
                    block_data[key_data_start + 5],
                    block_data[key_data_start + 6],
                    block_data[key_data_start + 7],
                ]);
                let obj_type = u32::from_le_bytes([
                    block_data[key_data_start + 8],
                    block_data[key_data_start + 9],
                    block_data[key_data_start + 10],
                    block_data[key_data_start + 11],
                ]);

                if obj_type != 1 {
                    continue;
                }

                let val_header_offset = node.values_offset as usize + i * 4;
                if val_header_offset + 4 > block_data.len() {
                    continue;
                }

                let val_off = u16::from_le_bytes([
                    block_data[val_header_offset],
                    block_data[val_header_offset + 1],
                ]);
                let val_len = u16::from_le_bytes([
                    block_data[val_header_offset + 2],
                    block_data[val_header_offset + 3],
                ]);

                let val_data_start = val_off as usize;
                let val_data_end = val_data_start + val_len as usize;
                if val_data_end > block_data.len() || val_len < 48 {
                    continue;
                }

                let val_data = &block_data[val_data_start..val_data_end];
                let inode_val = self.parse_inode_value(val_data, inode_id)?;

                if inode_val.flags & 0x00000200 != 0 {
                    let md = FileMetadata {
                        created: Self::apfs_time_to_datetime(inode_val.create_time),
                        modified: Self::apfs_time_to_datetime(inode_val.modified_time),
                        accessed: Self::apfs_time_to_datetime(inode_val.accessed_time),
                        permissions: Some(inode_val.mode as u32),
                        owner: Some(inode_val.uid.to_string()),
                        attributes: vec!["deleted".to_string()],
                    };

                    deleted.push(FileEntry {
                        inode: inode_id,
                        name: None,
                        size: inode_val.size,
                        data_offset: 0,
                        is_deleted: true,
                        metadata: Some(md),
                    });

                    if deleted.len() >= MAX_SCAN_ENTRIES {
                        return Ok(deleted);
                    }
                }
            }
        }

        Ok(deleted)
    }
}

impl FileSystem for APFSParser {
    fn read_superblock(&self) -> Result<SuperblockInfo> {
        let file = File::open(&self.device_path)?;
        let total_size = file.metadata()?.len();

        let vol_sb = self.read_volume_superblock()?;
        let created = Self::apfs_time_to_datetime(vol_sb.create_time);

        let vol_name = if vol_sb.volume_name.is_empty() {
            None
        } else {
            Some(vol_sb.volume_name.clone())
        };

        Ok(SuperblockInfo {
            volume_name: vol_name,
            total_size,
            free_space: vol_sb.free_blocks * self.block_size,
            block_size: self.block_size,
            total_blocks: self.total_blocks,
            free_blocks: self.free_blocks,
            file_system_type: "APFS".to_string(),
            created_at: created,
        })
    }

    fn list_root_directory(&self) -> Result<Vec<DirectoryEntry>> {
        let vol_sb = self.read_volume_superblock()?;
        let root_inode_id = 2;

        let dir_entries = self.btree_list_directory_entries(vol_sb.root_tree_oid, root_inode_id)?;
        let mut result = Vec::new();

        for de in &dir_entries {
            let inode_val = self.btree_lookup_inode(vol_sb.root_tree_oid, de.file_id)?;

            let (size, is_dir, metadata) = if let Some(ref iv) = inode_val {
                let is_directory = (iv.mode & 0xF000) == 0x4000 || de.entry_type == DIR_REC_TYPE_DIR;
                let md = FileMetadata {
                    created: Self::apfs_time_to_datetime(iv.create_time),
                    modified: Self::apfs_time_to_datetime(iv.modified_time),
                    accessed: Self::apfs_time_to_datetime(iv.accessed_time),
                    permissions: Some(iv.mode as u32),
                    owner: Some(iv.uid.to_string()),
                    attributes: {
                        let mut attrs = Vec::new();
                        if iv.flags & FILE_FLAG_COMPRESSED != 0 {
                            attrs.push("compressed".to_string());
                        }
                        if iv.flags & FILE_FLAG_SPARSE != 0 {
                            attrs.push("sparse".to_string());
                        }
                        if iv.flags & FILE_FLAG_CLONE != 0 {
                            attrs.push("clone".to_string());
                        }
                        if iv.compression_algorithm != 0 {
                            attrs.push(format!("compression_algo_{}", iv.compression_algorithm));
                        }
                        attrs
                    },
                };
                (iv.size, is_directory, Some(md))
            } else {
                let is_directory = de.entry_type == DIR_REC_TYPE_DIR;
                (0u64, is_directory, None)
            };

            result.push(DirectoryEntry {
                name: de.name.clone(),
                inode: de.file_id,
                is_directory: is_dir,
                size,
                metadata,
            });
        }

        Ok(result)
    }

    fn list_directory(&self, inode: u64) -> Result<Vec<DirectoryEntry>> {
        let vol_sb = self.read_volume_superblock()?;
        let dir_entries = self.btree_list_directory_entries(vol_sb.root_tree_oid, inode)?;
        let mut result = Vec::new();

        for de in &dir_entries {
            let inode_val = self.btree_lookup_inode(vol_sb.root_tree_oid, de.file_id)?;

            let (size, is_dir, metadata) = if let Some(ref iv) = inode_val {
                let is_directory = (iv.mode & 0xF000) == 0x4000 || de.entry_type == DIR_REC_TYPE_DIR;
                let md = FileMetadata {
                    created: Self::apfs_time_to_datetime(iv.create_time),
                    modified: Self::apfs_time_to_datetime(iv.modified_time),
                    accessed: Self::apfs_time_to_datetime(iv.accessed_time),
                    permissions: Some(iv.mode as u32),
                    owner: Some(iv.uid.to_string()),
                    attributes: Vec::new(),
                };
                (iv.size, is_directory, Some(md))
            } else {
                let is_directory = de.entry_type == DIR_REC_TYPE_DIR;
                (0u64, is_directory, None)
            };

            result.push(DirectoryEntry {
                name: de.name.clone(),
                inode: de.file_id,
                is_directory: is_dir,
                size,
                metadata,
            });
        }

        Ok(result)
    }

    fn read_file(&self, inode: u64) -> Result<Vec<u8>> {
        let vol_sb = self.read_volume_superblock()?;
        let inode_val = self.btree_lookup_inode(vol_sb.root_tree_oid, inode)?;

        let file_size = inode_val
            .as_ref()
            .map(|iv| iv.size)
            .unwrap_or(0);

        if file_size == 0 {
            return Ok(Vec::new());
        }

        if let Some(ref iv) = inode_val {
            if iv.flags & FILE_FLAG_COMPRESSED != 0 && iv.compression_algorithm != 0 {
                warn!("Compressed file recovery not fully implemented for inode {}", inode);
                return Ok(Vec::new());
            }
        }

        let extents = self.btree_lookup_extents(vol_sb.extent_ref_tree_oid, inode)?;

        if extents.is_empty() {
            warn!("No extents found for inode {}", inode);
            return Ok(Vec::new());
        }

        let mut result = Vec::with_capacity(file_size as usize);
        let mut remaining = file_size as usize;

        for extent in &extents {
            if remaining == 0 {
                break;
            }

            if extent.flags & 0x0001 != 0 {
                let zero_len = remaining.min(extent.length as usize);
                result.extend(vec![0u8; zero_len]);
                remaining = remaining.saturating_sub(zero_len);
                continue;
            }

            let mut file = File::open(&self.device_path)?;
            let mut bytes_to_read = remaining.min(extent.length as usize);

            while bytes_to_read > 0 {
                let read_size = bytes_to_read.min(self.block_size as usize);
                let mut buf = vec![0u8; read_size];
                file.seek(SeekFrom::Start(extent.phys_addr * self.block_size))?;
                if file.read_exact(&mut buf).is_err() {
                    break;
                }
                result.extend_from_slice(&buf);
                bytes_to_read = bytes_to_read.saturating_sub(read_size);
            }

            remaining = remaining.saturating_sub(extent.length as usize);
        }

        if result.len() > file_size as usize {
            result.truncate(file_size as usize);
        }

        Ok(result)
    }

    fn find_deleted_files(&self) -> Result<Vec<FileEntry>> {
        self.scan_for_deleted_files()
    }

    fn get_file_metadata(&self, inode: u64) -> Result<FileMetadata> {
        let vol_sb = self.read_volume_superblock()?;
        let inode_val = self.btree_lookup_inode(vol_sb.root_tree_oid, inode)?;

        match inode_val {
            Some(iv) => {
                let mut attributes = Vec::new();
                if iv.flags & FILE_FLAG_COMPRESSED != 0 {
                    attributes.push("compressed".to_string());
                }
                if iv.flags & FILE_FLAG_SPARSE != 0 {
                    attributes.push("sparse".to_string());
                }
                if iv.flags & FILE_FLAG_CLONE != 0 {
                    attributes.push("clone".to_string());
                }
                if iv.clone_id != 0 {
                    attributes.push(format!("clone_id_{}", iv.clone_id));
                }
                if iv.xattr_count > 0 {
                    attributes.push(format!("xattr_count_{}", iv.xattr_count));
                }
                if iv.compression_algorithm != 0 {
                    attributes.push(format!("compression_algo_{}", iv.compression_algorithm));
                }

                Ok(FileMetadata {
                    created: Self::apfs_time_to_datetime(iv.create_time),
                    modified: Self::apfs_time_to_datetime(iv.modified_time),
                    accessed: Self::apfs_time_to_datetime(iv.accessed_time),
                    permissions: Some(iv.mode as u32),
                    owner: Some(iv.uid.to_string()),
                    attributes,
                })
            }
            None => Ok(FileMetadata {
                created: None,
                modified: None,
                accessed: None,
                permissions: None,
                owner: None,
                attributes: Vec::new(),
            }),
        }
    }
}
