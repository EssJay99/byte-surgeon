# Byte Surgeon Benchmark Suite

Performance benchmarks for the Byte Surgeon data recovery engine using the
[Criterion](https://github.com/bheisler/criterion.rs) framework.

## Prerequisites

- Rust stable (edition 2021)
- Criterion 0.5 (pulled automatically via Cargo)
- Sufficient disk space for temporary test files (up to ~200MB during runs)

## Benchmark Files

| File | Description |
|---|---|
| `benches/signature_scanning.rs` | Signature database lookups and disk/mmap scanning throughput |
| `benches/file_carving.rs` | Serial vs parallel file extraction (JPEG boundary detection) |
| `benches/filesystem_parsing.rs` | NTFS, FAT32, ext4 superblock reads and filesystem detection |
| `benches/parallel_vs_serial.rs` | Side-by-side comparison of serial and parallel scanning/carving |
| `benches/memory_usage.rs` | Peak memory measurements for scanning, carving, and signature operations |
| `benches/cache_performance.rs` | Sector cache hit/miss latency, mixed workloads, eviction pressure |

## Running

### All benchmarks
```bash
cd /Users/ted/TLE
cargo bench -p bytesurgeon-benchmarks
```

### Single benchmark
```bash
cargo bench -p bytesurgeon-benchmarks --bench signature_scanning
cargo bench -p bytesurgeon-benchmarks --bench file_carving
cargo bench -p bytesurgeon-benchmarks --bench cache_performance
```

### Specific benchmark group
```bash
cargo bench -p bytesurgeon-benchmarks --bench cache_performance -- cache_hit
```

### Automated full run
```bash
chmod +x benchmarks/run_benchmarks.sh
./benchmarks/run_benchmarks.sh
```

Results are saved to `benchmarks/results/` with timestamps.

### HTML reports

Criterion generates interactive HTML reports at:
```
target/criterion/report/index.html
```

## Input Sizes

Each benchmark tests across multiple input sizes:

| Label | Size | Purpose |
|---|---|---|
| small | 64KB - 1MB | Baseline latency, cache behavior |
| medium | 1MB - 16MB | Typical recovery workload |
| large | 16MB - 64MB | Stress test, memory pressure |

## Key Metrics

- **Throughput (MB/s)**: Data processed per second (scanning, carving)
- **Latency (ns/us/ms)**: Time per operation (cache, signature lookup)
- **Speedup ratio**: Parallel/serial comparison factor

## Baseline Results

See `results/baseline.txt` for reference measurements. Re-run benchmarks
after code changes to compare against this baseline.

### Quick comparison workflow

```bash
# Save current results
cargo bench -p bytesurgeon-benchmarks -- --save-baseline current

# After code changes
cargo bench -p bytesurgeon-benchmarks -- --baseline current
```

Criterion will report percentage changes and flag regressions.

## Directory Structure

```
benchmarks/
  Cargo.toml              # Benchmark crate configuration
  run_benchmarks.sh       # Automated run script
  README.md               # This file
  benches/
    signature_scanning.rs
    file_carving.rs
    filesystem_parsing.rs
    parallel_vs_serial.rs
    memory_usage.rs
    cache_performance.rs
  results/
    baseline.txt          # Reference measurements
```

## Adding New Benchmarks

1. Add a new `.rs` file in `benches/`
2. Register it in `Cargo.toml` under `[[bench]]` with `harness = false`
3. Use `criterion_group!` and `criterion_main!` macros
4. Run with `cargo bench -p bytesurgeon-benchmarks --bench <name>`
