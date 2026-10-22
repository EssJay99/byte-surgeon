use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use bytesurgeon_core::{SignatureDatabase, scanner::MmapScanner};
use rand::Rng;
use std::io::Write;
use tempfile::NamedTempFile;

fn build_test_data(size: usize, signature_density: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);

    let signatures: Vec<&[u8]> = vec![
        &[0xFF, 0xD8, 0xFF],
        &[0x89, 0x50, 0x4E, 0x47],
        &[0x25, 0x50, 0x44, 0x46],
        &[0x50, 0x4B, 0x03, 0x04],
        &[0x7F, 0x45, 0x4C, 0x46],
    ];

    let step = if signature_density > 0 {
        size / signature_density
    } else {
        size
    };

    for (i, sig) in signatures.iter().cycle().enumerate() {
        let offset = i * step;
        if offset + sig.len() <= size {
            data[offset..offset + sig.len()].copy_from_slice(sig);
        }
    }

    data
}

fn bench_signature_database_identify(c: &mut Criterion) {
    let db = SignatureDatabase::new();

    let jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    let png_data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let pdf_data = vec![0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34];
    let unknown_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    let mut group = c.benchmark_group("signature_db_identify");

    group.bench_function("jpeg", |b| {
        b.iter(|| db.identify(&jpeg_data))
    });
    group.bench_function("png", |b| {
        b.iter(|| db.identify(&png_data))
    });
    group.bench_function("pdf", |b| {
        b.iter(|| db.identify(&pdf_data))
    });
    group.bench_function("unknown", |b| {
        b.iter(|| db.identify(&unknown_data))
    });

    group.finish();
}

fn bench_signature_database_identify_all(c: &mut Criterion) {
    let db = SignatureDatabase::new();
    let zip_data = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x08, 0x00];

    let mut group = c.benchmark_group("signature_db_identify_all");
    group.bench_function("zip_multi_match", |b| {
        b.iter(|| db.identify_all(&zip_data))
    });
    group.finish();
}

fn bench_signature_database_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_db_creation");
    group.bench_function("load_all_signatures", |b| {
        b.iter(|| SignatureDatabase::new())
    });
    group.finish();
}

fn bench_disk_signature_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("disk_signature_scanning");

    for (label, size, density) in &[
        ("small_64kb", 64 * 1024, 4),
        ("medium_1mb", 1024 * 1024, 16),
        ("large_16mb", 16 * 1024 * 1024, 64),
    ] {
        let data = build_test_data(*size, *density);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("disk_scanner", label), size, |b, _| {
            let scanner = bytesurgeon_core::DiskScanner::new(tmp.path().to_str().unwrap());
            b.iter(|| scanner.find_signatures().unwrap())
        });
    }

    group.finish();
}

fn bench_mmap_signature_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("mmap_signature_scanning");

    for (label, size, density) in &[
        ("small_128kb", 128 * 1024, 4),
        ("medium_4mb", 4 * 1024 * 1024, 32),
        ("large_32mb", 32 * 1024 * 1024, 128),
    ] {
        let data = build_test_data(*size, *density);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("mmap_scanner", label), size, |b, _| {
            let scanner = MmapScanner::new();
            b.iter(|| scanner.scan_file(tmp.path().to_str().unwrap()).unwrap())
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_signature_database_identify,
    bench_signature_database_identify_all,
    bench_signature_database_creation,
    bench_disk_signature_scanning,
    bench_mmap_signature_scanning,
);
criterion_main!(benches);
