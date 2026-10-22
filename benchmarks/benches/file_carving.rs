use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use datadoctor_core::{FileCarver, FileSignature};
use datadoctor_core::scanner::SignatureMatch;
use rand::Rng;
use tempfile::TempDir;

fn build_jpeg_data(payload_size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0];
    let mut payload = vec![0u8; payload_size];
    rng.fill(&mut payload[..]);
    data.extend_from_slice(&payload);
    data.extend_from_slice(&[0xFF, 0xD9]);
    data
}

fn build_multi_file_image(file_count: usize, file_size: usize) -> (Vec<u8>, Vec<SignatureMatch>) {
    let mut data = Vec::new();
    let mut matches = Vec::new();

    for _ in 0..file_count {
        let offset = data.len() as u64;
        let file_data = build_jpeg_data(file_size);
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

    (data, matches)
}

fn bench_serial_carving(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_carving_serial");

    for (label, file_count, file_size) in &[
        ("small_10x1kb", 10, 1024),
        ("medium_50x64kb", 50, 64 * 1024),
        ("large_100x256kb", 100, 256 * 1024),
    ] {
        let (data, matches) = build_multi_file_image(*file_count, *file_size);
        let total_bytes: u64 = data.len() as u64;

        let input_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("carve_input.dat");
        std::fs::write(&input_path, &data).unwrap();

        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("serial", label),
            &file_count,
            |b, _| {
                let output_dir = TempDir::new().unwrap();
                let carver = FileCarver::new(output_dir.path(), "bench-serial");
                b.iter(|| {
                    carver.carve_files(
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

fn bench_parallel_carving(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_carving_parallel");

    for (label, file_count, file_size) in &[
        ("small_10x1kb", 10, 1024),
        ("medium_50x64kb", 50, 64 * 1024),
        ("large_100x256kb", 100, 256 * 1024),
    ] {
        let (data, matches) = build_multi_file_image(*file_count, *file_size);
        let total_bytes: u64 = data.len() as u64;

        let input_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("carve_input.dat");
        std::fs::write(&input_path, &data).unwrap();

        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("parallel", label),
            &file_count,
            |b, _| {
                let output_dir = TempDir::new().unwrap();
                let carver = FileCarver::new(output_dir.path(), "bench-parallel");
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

fn bench_jpeg_boundary_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("jpeg_boundary_detection");

    for (label, size) in &[
        ("1kb", 1024),
        ("64kb", 64 * 1024),
        ("1mb", 1024 * 1024),
    ] {
        let data = build_jpeg_data(*size);
        let input_dir = TempDir::new().unwrap();
        let input_path = input_dir.path().join("jpeg.dat");
        std::fs::write(&input_path, &data).unwrap();

        group.throughput(Throughput::Bytes(data.len() as u64));

        let matches = vec![SignatureMatch {
            offset: 0,
            signature: FileSignature {
                extension: "jpg".to_string(),
                magic_bytes: vec![0xFF, 0xD8, 0xFF],
                offset: 0,
                description: "JPEG".to_string(),
                category: "Image".to_string(),
            },
        }];

        group.bench_with_input(BenchmarkId::new("carve_jpeg", label), size, |b, _| {
            let output_dir = TempDir::new().unwrap();
            let carver = FileCarver::new(output_dir.path(), "bench-jpeg");
            b.iter(|| {
                carver.carve_files(
                    input_path.to_str().unwrap(),
                    &matches,
                    |_, _| {},
                ).unwrap()
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_serial_carving,
    bench_parallel_carving,
    bench_jpeg_boundary_detection,
);
criterion_main!(benches);
