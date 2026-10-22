use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use bytesurgeon_filesystem::FileSystem;
use std::io::Write;
use tempfile::NamedTempFile;

fn build_ntfs_image(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];

    data[3..11].copy_from_slice(b"NTFS    ");
    data[11] = 0x00;
    data[12] = 0x02;
    data[13] = 0x08;
    data[14] = 0x00;
    data[15] = 0x00;

    let total_sectors = (size / 512) as u64;
    data[40..48].copy_from_slice(&total_sectors.to_le_bytes());

    let mft_cluster: u64 = 0x1000;
    data[48..56].copy_from_slice(&mft_cluster.to_le_bytes());

    let mft_mirror_cluster: u64 = 0x2000;
    data[56..64].copy_from_slice(&mft_mirror_cluster.to_le_bytes());

    data[64] = 0xF6;
    data[66] = 0xFC;

    if size > 0x1000 * 4096 + 1024 {
        let mft_offset = (mft_cluster * 4096) as usize;
        if mft_offset + 1024 <= size {
            data[mft_offset..mft_offset + 4].copy_from_slice(b"FILE");
            data[mft_offset + 4] = 0x03;
            data[mft_offset + 5] = 0x00;
            data[mft_offset + 6] = 0x01;
            data[mft_offset + 7] = 0x00;

            let us_offset: u16 = 42;
            data[mft_offset + 42..mft_offset + 44].copy_from_slice(&us_offset.to_le_bytes());
            let us_count: u16 = 3;
            data[mft_offset + 44..mft_offset + 46].copy_from_slice(&us_count.to_le_bytes());

            let first_attr_offset: u16 = 56;
            data[mft_offset + 20..mft_offset + 22].copy_from_slice(&first_attr_offset.to_le_bytes());

            let flags: u16 = 0x01;
            data[mft_offset + 22..mft_offset + 24].copy_from_slice(&flags.to_le_bytes());

            let end_offset = mft_offset + first_attr_offset as usize;
            if end_offset + 4 <= size {
                data[end_offset..end_offset + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
            }
        }
    }

    data
}

fn build_fat32_image(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];

    data[0] = 0xEB;
    data[1] = 0x58;
    data[2] = 0x90;
    data[3..11].copy_from_slice(b"MSDOS5.0");

    data[11] = 0x00;
    data[12] = 0x02;
    data[13] = 0x08;
    data[14..16].copy_from_slice(&32u16.to_le_bytes());
    data[16] = 0x02;

    data[510] = 0x55;
    data[511] = 0xAA;

    let sectors_per_fat: u32 = 128;
    data[36..40].copy_from_slice(&sectors_per_fat.to_le_bytes());

    let root_cluster: u32 = 2;
    data[44..48].copy_from_slice(&root_cluster.to_le_bytes());

    data
}

fn build_ext4_image(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];

    let sb_offset = 1024;
    if size > sb_offset + 256 {
        data[sb_offset + 0x38] = 0x53;
        data[sb_offset + 0x39] = 0xEF;

        let log_block_size: u32 = 0;
        data[sb_offset + 0x18..sb_offset + 0x1C].copy_from_slice(&log_block_size.to_le_bytes());

        let blocks_per_group: u32 = 32768;
        data[sb_offset + 0x28..sb_offset + 0x2C].copy_from_slice(&blocks_per_group.to_le_bytes());

        let inodes_per_group: u32 = 8192;
        data[sb_offset + 0x28 + 8..sb_offset + 0x28 + 12].copy_from_slice(&inodes_per_group.to_le_bytes());

        let magic: u16 = 0xEF53;
        data[sb_offset + 0x38..sb_offset + 0x3A].copy_from_slice(&magic.to_le_bytes());

        let inode_size: u16 = 256;
        data[sb_offset + 0x58..sb_offset + 0x5A].copy_from_slice(&inode_size.to_le_bytes());

        let total_blocks: u64 = (size / 4096) as u64;
        data[sb_offset + 4..sb_offset + 8].copy_from_slice(&(total_blocks as u32).to_le_bytes());

        let total_inodes: u32 = 16384;
        data[sb_offset + 0..sb_offset + 4].copy_from_slice(&total_inodes.to_le_bytes());
    }

    data
}

fn bench_ntfs_superblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntfs_parsing");

    for (label, size) in &[
        ("small_1mb", 1024 * 1024),
        ("medium_16mb", 16 * 1024 * 1024),
        ("large_64mb", 64 * 1024 * 1024),
    ] {
        let data = build_ntfs_image(*size);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("ntfs_superblock", label), size, |b, _| {
            b.iter(|| {
                let parser = bytesurgeon_filesystem::NTFSParser::new(tmp.path().to_str().unwrap()).unwrap();
                parser.read_superblock().unwrap()
            })
        });
    }

    group.finish();
}

fn bench_fat32_superblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("fat32_parsing");

    for (label, size) in &[
        ("small_1mb", 1024 * 1024),
        ("medium_16mb", 16 * 1024 * 1024),
        ("large_64mb", 64 * 1024 * 1024),
    ] {
        let data = build_fat32_image(*size);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("fat32_superblock", label), size, |b, _| {
            b.iter(|| {
                let parser = bytesurgeon_filesystem::FAT32Parser::new(tmp.path().to_str().unwrap()).unwrap();
                parser.read_superblock().unwrap()
            })
        });
    }

    group.finish();
}

fn bench_ext4_superblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("ext4_parsing");

    for (label, size) in &[
        ("small_1mb", 1024 * 1024),
        ("medium_16mb", 16 * 1024 * 1024),
        ("large_64mb", 64 * 1024 * 1024),
    ] {
        let data = build_ext4_image(*size);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("ext4_superblock", label), size, |b, _| {
            b.iter(|| {
                let parser = bytesurgeon_filesystem::EXT4Parser::new(tmp.path().to_str().unwrap()).unwrap();
                parser.read_superblock().unwrap()
            })
        });
    }

    group.finish();
}

fn bench_filesystem_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("filesystem_detection");

    let ntfs_data = build_ntfs_image(1024 * 1024);
    let mut ntfs_tmp = NamedTempFile::new().unwrap();
    ntfs_tmp.write_all(&ntfs_data).unwrap();
    ntfs_tmp.flush().unwrap();

    let fat32_data = build_fat32_image(1024 * 1024);
    let mut fat32_tmp = NamedTempFile::new().unwrap();
    fat32_tmp.write_all(&fat32_data).unwrap();
    fat32_tmp.flush().unwrap();

    let ext4_data = build_ext4_image(1024 * 1024);
    let mut ext4_tmp = NamedTempFile::new().unwrap();
    ext4_tmp.write_all(&ext4_data).unwrap();
    ext4_tmp.flush().unwrap();

    group.bench_function("detect_ntfs", |b| {
        b.iter(|| bytesurgeon_filesystem::detect_filesystem(ntfs_tmp.path().to_str().unwrap()))
    });
    group.bench_function("detect_fat32", |b| {
        b.iter(|| bytesurgeon_filesystem::detect_filesystem(fat32_tmp.path().to_str().unwrap()))
    });
    group.bench_function("detect_ext4", |b| {
        b.iter(|| bytesurgeon_filesystem::detect_filesystem(ext4_tmp.path().to_str().unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ntfs_superblock,
    bench_fat32_superblock,
    bench_ext4_superblock,
    bench_filesystem_detection,
);
criterion_main!(benches);
