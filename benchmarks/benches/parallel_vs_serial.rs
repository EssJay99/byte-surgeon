use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use datadoctor_core::{DiskScanner, FileCarver, scanner::MmapScanner};
use datadoctor_core::scanner::SignatureMatch;
use datadoctor_core::FileSignature;
use rand::Rng;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

fn build_test_image(size: usize, sig_count: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);

    let step = if sig_count > 0 { size / sig_count } else { size };

    let sigs: Vec<&[u8]> = vec![
        &[0xFF, 0xD8, 0xFF],
        &[0x89, 0x50, 0x4E, 0x47],
        &[0x25, 0x50, 0x44, 0x46],
    ];

    for i in 0..sig_count {
        let sig = sigs[i % sigs.len()];
        let offset = i * step;
        if offset + sig.len() <= size {
            data[offset..offset + sig.len()].copy_from_slice(sig);
        }
    }

    data
}

fn bench_serial_vs_parallel_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_serial_vs_parallel");

    for (label, size, sigs) in &[
        ("small_256kb", 256 * 1024, 8),
        ("medium_4mb", 4 * 1024 * 1024, 32),
        ("large_32mb", 32 * 1024 * 1024, 128),
    ] {
        let data = build_test_image(*size, *sigs);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("serial_disk_scanner", label),
            size,
            |b, _| {
                let scanner = DiskScanner::new(tmp.path().to_str().unwrap());
                b.iter(|| scanner.find_signatures().unwrap())
            },
        );

        group.bench_with_input(
            BenchmarkId::new("mmap_scanner", label),
            size,
            |b, _| {
                let scanner = MmapScanner::new();
                b.iter(|| scanner.scan_file(tmp.path().to_str().unwrap()).unwrap())
            },
        );
    }

    group.finish();
}

fn bench_serial_vs_parallel_carving(c: &mut Criterion) {
    let mut group = c.benchmark_group("carve_serial_vs_parallel");

    for (label, file_count, file_size) in &[
        ("small_20x4kb", 20, 4 * 1024),
        ("medium_50x32kb", 50, 32 * 1024),
        ("large_100x128kb", 100, 128 * 1024),
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

            matches.push(SignatureMatch {
                offset,
                signature: FileSignature {
                    extension: "jpg".to_string(),
                    magic_bytes: vec![0xFF, 0xD8, 0xFF],
                    offset: 0,
                    description: "JPEG".to_string(),
                    category: "Image".to_string(),
                },
            });
        }

        let input_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("compare.dat");
        std::fs::write(&input_path, &data).unwrap();

        let total_bytes = data.len() as u64;
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("serial_carve", label),
            file_count,
            |b, _| {
                let output_dir = TempDir::new().unwrap();
                let carver = FileCarver::new(output_dir.path(), "serial");
                b.iter(|| {
                    carver.carve_files(
                        input_path.to_str().unwrap(),
                        &matches,
                        |_, _| {},
                    ).unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("parallel_carve", label),
            file_count,
            |b, _| {
                let output_dir = TempDir::new().unwrap();
                let carver = FileCarver::new(output_dir.path(), "parallel");
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
    bench_serial_vs_parallel_scanning,
    bench_serial_vs_parallel_carving,
);
criterion_main!(benches);
