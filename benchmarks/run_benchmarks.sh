#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS_DIR"

echo "============================================"
echo "  Data Defender Benchmark Suite"
echo "  $(date)"
echo "============================================"
echo ""

run_bench() {
    local name="$1"
    local output_file="$RESULTS_DIR/${name}_${TIMESTAMP}.txt"

    echo ">>> Running: $name"
    cargo bench --bench "$name" -- --noplot 2>&1 | tee "$output_file"
    echo ""
    echo "    Results saved to: $output_file"
    echo ""
}

echo "--- Benchmark: signature_scanning ---"
run_bench "signature_scanning"

echo "--- Benchmark: file_carving ---"
run_bench "file_carving"

echo "--- Benchmark: filesystem_parsing ---"
run_bench "filesystem_parsing"

echo "--- Benchmark: parallel_vs_serial ---"
run_bench "parallel_vs_serial"

echo "--- Benchmark: memory_usage ---"
run_bench "memory_usage"

echo "--- Benchmark: cache_performance ---"
run_bench "cache_performance"

echo "--- Generating HTML reports ---"
cd "$SCRIPT_DIR"
cargo bench -- --noplot 2>&1 | tee "$RESULTS_DIR/full_run_${TIMESTAMP}.txt"

echo ""
echo "============================================"
echo "  All benchmarks complete."
echo "  HTML reports: target/criterion/"
echo "  Text results: $RESULTS_DIR/"
echo "============================================"
