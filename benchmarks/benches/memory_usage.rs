use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use datadoctor_core::SignatureDatabase;
use datadoctor_core::scanner::MmapScanner;
use rand::Rng;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

fn bench_signature_db_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_signature_db");

    group.bench_function("db_entries_allocation", |b| {
        b.iter(|| {
            let db = SignatureDatabase::new();
            let count = db.count();
            assert!(count > 0);
            count
        })
    });

    group.bench_function("to_file_signatures_clone", |b| {
        let db = SignatureDatabase::new();
        b.iter(|| {
            let sigs = db.to_file_signatures();
            sigs.len()
        })
    });

    group.finish();
}

fn bench_scan_memory_large_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_large_scan");

    for (label, size) in &[
        ("1mb", 1024 * 1024),
        ("8mb", 8 * 1024 * 1024),
        ("32mb", 32 * 1024 * 1024),
    ] {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; *size];
        rng.fill(&mut data[..]);

        let step = 4096;
        for i in (0..*size).step_by(step) {
            if i + 3 <= *size {
                data[i] = 0xFF;
                data[i + 1] = 0xD8;
                data[i + 2] = 0xFF;
            }
        }

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("mmap_peak_alloc", label), size, |b, _| {
            b.iter(|| {
                let scanner = MmapScanner::new();
                scanner.scan_file(tmp.path().to_str().unwrap()).unwrap()
            })
        });
    }

    group.finish();
}

fn bench_carving_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_carving");

    for (label, file_count, file_size) in &[
        ("small_10x4kb", 10, 4 * 1024),
        ("medium_50x64kb", 50, 64 * 1024),
        ("large_100x512kb", 100, 512 * 1024),
    ] {
        let mut data = Vec::new();
        let mut matches = Vec::new();
        let mut rng = rand::thread_rng();

        for _ in 0..*file_count {
            let offset = data.len() as u64;
            let mut file_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
            let mut payload = vec![0u8; *file_size];
            rng.fill(&mut payload[..]);
            file_data.extend_from_slice(&payload);
            file_data.extend_from_slice(&[0xFF, 0xD9]);
            data.extend_from_slice(&file_data);

            matches.push(datadoctor_core::scanner::SignatureMatch {
                offset,
                signature: datadoctor_core::FileSignature {
                    extension: "jpg".to_string(),
                    magic_bytes: vec![0xFF, 0xD8, 0xFF],
                    offset: 0,
                    description: "JPEG".to_string(),
                    category: "Image".to_string(),
                },
            });
        }

        let input_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("mem_test.dat");
        std::fs::write(&input_path, &data).unwrap();

        let total_bytes = data.len() as u64;
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("parallel_carve_mem", label),
            file_count,
            |b, _| {
                let output_dir = TempDir::new().unwrap();
                let carver = datadoctor_core::FileCarver::new(output_dir.path(), "mem-bench");
                b.iter(|| {
                    carver.carve_files_parallel(
                        input_path.to_str().unwrap(),
                        &matches,
                        |_, _| {},
                    ).unwrap()
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_signature_db_memory,
    bench_scan_memory_large_file,
    bench_carving_memory,
);
criterion_main!(benches);
