use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use datadoctor_core::SectorCache;
use rand::Rng;

fn bench_cache_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hit");

    for (label, capacity, num_entries) in &[
        ("small_10", 10 * 512, 10),
        ("medium_100", 100 * 512, 100),
        ("large_1000", 1000 * 512, 1000),
    ] {
        let cache = SectorCache::with_capacity(*capacity);
        for i in 0..*num_entries as u64 {
            cache.write_cache(i, vec![0xAA; 512]);
        }

        group.bench_with_input(
            BenchmarkId::new("read_hit", label),
            num_entries,
            |b, n| {
                b.iter(|| {
                    for i in 0..*n as u64 {
                        let _ = cache.read_cached(i);
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_cache_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_miss");

    for (label, capacity, num_reads) in &[
        ("small_100", 10 * 512, 100),
        ("medium_1000", 100 * 512, 1000),
        ("large_10000", 1000 * 512, 10000),
    ] {
        let cache = SectorCache::with_capacity(*capacity);

        group.bench_with_input(
            BenchmarkId::new("read_miss", label),
            num_reads,
            |b, n| {
                b.iter(|| {
                    for i in 0..*n as u64 {
                        let _ = cache.read_cached(i + 1_000_000);
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_cache_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_mixed");

    for (label, hit_ratio) in &[
        ("90pct_hit", 0.9_f64),
        ("50pct_hit", 0.5_f64),
        ("10pct_hit", 0.1_f64),
    ] {
        let cache = SectorCache::with_capacity(1000 * 512);
        let mut rng = rand::thread_rng();

        for i in 0..500u64 {
            cache.write_cache(i, vec![rng.gen::<u8>(); 512]);
        }

        let ratio = *hit_ratio;
        let ops_count = 1000usize;

        group.bench_function(BenchmarkId::new("mixed_workload", label), |b| {
            b.iter(|| {
                for _ in 0..ops_count {
                    let r: f64 = rng.gen();
                    if r < ratio {
                        let sector_id = rng.gen_range(0..500);
                        let _ = cache.read_cached(sector_id);
                    } else {
                        let sector_id = rng.gen_range(1000..2000);
                        if cache.read_cached(sector_id).is_none() {
                            cache.write_cache(sector_id, vec![rng.gen::<u8>(); 512]);
                        }
                    }
                }
            })
        });
    }

    group.finish();
}

fn bench_cache_write_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_write");

    for (label, sector_size) in &[
        ("512b", 512),
        ("4kb", 4096),
        ("64kb", 65536),
    ] {
        let cache = SectorCache::with_capacity(10_000 * sector_size);
        let data = vec![0xBB_u8; *sector_size];

        group.throughput(Throughput::Bytes(*sector_size as u64));

        group.bench_with_input(
            BenchmarkId::new("write_sector", label),
            &sector_size,
            |b, _| {
                let mut i = 0u64;
                b.iter(|| {
                    cache.write_cache(i, data.clone());
                    i += 1;
                })
            },
        );
    }

    group.finish();
}

fn bench_cache_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_eviction");

    for (label, max_entries) in &[
        ("small_10", 10),
        ("medium_100", 100),
        ("large_1000", 1000),
    ] {
        let capacity = max_entries * 512;
        let cache = SectorCache::with_capacity(capacity);
        let data = vec![0xCC; 512];

        group.bench_with_input(
            BenchmarkId::new("eviction_pressure", label),
            max_entries,
            |b, n| {
                let mut i = 0u64;
                b.iter(|| {
                    for _ in 0..(*n * 10) {
                        cache.write_cache(i, data.clone());
                        i += 1;
                    }
                })
            },
        );
    }

    group.finish();
}

fn bench_cache_stats_overhead(c: &mut Criterion) {
    let cache = SectorCache::with_capacity(10_000 * 512);
    for i in 0..1000u64 {
        cache.write_cache(i, vec![0xDD; 512]);
    }

    let mut group = c.benchmark_group("cache_stats");
    group.bench_function("stats_snapshot", |b| {
        b.iter(|| cache.stats())
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_cache_hit,
    bench_cache_miss,
    bench_cache_mixed_workload,
    bench_cache_write_throughput,
    bench_cache_eviction,
    bench_cache_stats_overhead,
);
criterion_main!(benches);
