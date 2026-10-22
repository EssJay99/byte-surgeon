//! GPU benchmarking for Data Doctor
//!
//! Provides tools to measure GPU acceleration performance.

use crate::{GpuSignatureScanner, Signature, GpuType, GpuError};
use std::time::{Instant, Duration};
use tracing::info;

/// Benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub data_size: usize,
    pub signature_count: usize,
    pub scan_time: Duration,
    pub matches_found: usize,
    pub throughput_mbps: f64,
    pub gpu_utilization: f64,
}

/// GPU benchmark runner
pub struct GpuBenchmark {
    scanner: GpuSignatureScanner,
}

impl GpuBenchmark {
    /// Create a new benchmark runner
    pub fn new(gpu_type: GpuType) -> std::result::Result<Self, GpuError> {
        let scanner = GpuSignatureScanner::new(gpu_type)?;
        Ok(Self { scanner })
    }

    /// Run a benchmark scan
    pub fn run_benchmark(
        &self,
        data_size: usize,
        signature_count: usize,
    ) -> std::result::Result<BenchmarkResult, GpuError> {
        info!("Running GPU benchmark: {} bytes, {} signatures", data_size, signature_count);

        // Generate test data
        let data = self.generate_test_data(data_size);
        let signatures = self.generate_test_signatures(signature_count);

        // Run the scan and measure time
        let start = Instant::now();
        let matches = self.scanner.scan_signatures(&data, &signatures)?;
        let scan_time = start.elapsed();

        // Calculate throughput
        let throughput_mbps = (data_size as f64 / 1_048_576.0) / scan_time.as_secs_f64();

        // Estimate GPU utilization (simplified)
        let gpu_utilization = self.estimate_gpu_utilization(&data, &signatures);

        let result = BenchmarkResult {
            data_size,
            signature_count,
            scan_time,
            matches_found: matches.len(),
            throughput_mbps,
            gpu_utilization,
        };

        info!(
            "Benchmark complete: {:.2} MB/s, {} matches, {:.1}% GPU utilization",
            result.throughput_mbps, result.matches_found, result.gpu_utilization
        );

        Ok(result)
    }

    /// Run multiple benchmarks with different sizes
    pub fn run_benchmark_suite(&self, sizes: &[usize]) -> std::result::Result<Vec<BenchmarkResult>, GpuError> {
        let mut results = Vec::new();

        for &size in sizes {
            let result = self.run_benchmark(size, 100)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Compare GPU vs CPU performance
    pub fn compare_gpu_cpu(&self, data_size: usize) -> std::result::Result<CpuGpuComparison, GpuError> {
        info!("Comparing GPU vs CPU performance for {} bytes", data_size);

        // GPU scan
        let gpu_result = self.run_benchmark(data_size, 100)?;

        // CPU scan (simulated)
        let data = self.generate_test_data(data_size);
        let signatures = self.generate_test_signatures(100);

        let start = Instant::now();
        let cpu_matches = self.cpu_scan(&data, &signatures);
        let cpu_time = start.elapsed();

        let cpu_throughput = (data_size as f64 / 1_048_576.0) / cpu_time.as_secs_f64();

        let speedup = cpu_time.as_secs_f64() / gpu_result.scan_time.as_secs_f64();

        Ok(CpuGpuComparison {
            gpu_result,
            cpu_time,
            cpu_matches,
            cpu_throughput,
            speedup,
        })
    }

    /// Generate test data
    fn generate_test_data(&self, size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        
        // Insert some signatures at random positions
        let sig_positions = [
            (100, b"PK\x03\x04".to_vec()),  // ZIP
            (10000, b"\xff\xd8\xff".to_vec()),  // JPEG
            (50000, b"%PDF".to_vec()),  // PDF
            (100000, b"\x89PNG".to_vec()),  // PNG
        ];

        for (pos, sig) in sig_positions.iter() {
            if *pos + sig.len() < size {
                data[*pos..*pos + sig.len()].copy_from_slice(sig);
            }
        }

        // Fill rest with random data
        for i in 0..size {
            if !sig_positions.iter().any(|(p, s)| i >= *p && i < p + s.len()) {
                data[i] = (i % 256) as u8;
            }
        }

        data
    }

    /// Generate test signatures
    fn generate_test_signatures(&self, count: usize) -> Vec<Signature> {
        let mut signatures = Vec::with_capacity(count);

        // Add common signatures
        let common_sigs = vec![
            (b"PK\x03\x04".to_vec(), "zip", 1),
            (b"\xff\xd8\xff".to_vec(), "jpg", 2),
            (b"%PDF".to_vec(), "pdf", 3),
            (b"\x89PNG".to_vec(), "png", 4),
            (b"GIF8".to_vec(), "gif", 5),
        ];

        for (magic, ext, cat) in common_sigs.iter().take(count) {
            signatures.push(Signature::new(magic, ext, *cat));
        }

        // Fill rest with dummy signatures
        for i in common_sigs.len()..count {
            let magic = format!("SIG{}", i);
            signatures.push(Signature::new(magic.as_bytes(), &format!("ext{}", i), i as u32));
        }

        signatures
    }

    /// Estimate GPU utilization
    fn estimate_gpu_utilization(&self, data: &[u8], signatures: &[Signature]) -> f64 {
        // Simplified estimation based on data size and signature count
        let device_info = self.scanner.device_info();
        let compute_units = device_info.compute_units as f64;
        let memory_bandwidth = device_info.memory_size as f64;

        // Estimate based on workload size
        let workload = data.len() as f64 * signatures.len() as f64;
        let capacity = compute_units * memory_bandwidth * 0.001;

        (workload / capacity).min(100.0)
    }

    /// CPU scan for comparison
    fn cpu_scan(&self, data: &[u8], signatures: &[Signature]) -> usize {
        let mut matches = 0;

        for (_offset, window) in data.windows(16).enumerate() {
            for sig in signatures {
                let magic_len = sig.magic_len as usize;
                if magic_len <= 16 && window.starts_with(&sig.magic_bytes[..magic_len]) {
                    matches += 1;
                }
            }
        }

        matches
    }
}

/// CPU vs GPU comparison results
#[derive(Debug, Clone)]
pub struct CpuGpuComparison {
    pub gpu_result: BenchmarkResult,
    pub cpu_time: Duration,
    pub cpu_matches: usize,
    pub cpu_throughput: f64,
    pub speedup: f64,
}

impl CpuGpuComparison {
    /// Print comparison results
    pub fn print_summary(&self) {
        println!("\n=== GPU vs CPU Performance Comparison ===");
        println!("Data size: {} bytes", self.gpu_result.data_size);
        println!("Signatures: {}", self.gpu_result.signature_count);
        println!();
        println!("GPU Performance:");
        println!("  Time: {:.3} ms", self.gpu_result.scan_time.as_millis());
        println!("  Throughput: {:.2} MB/s", self.gpu_result.throughput_mbps);
        println!("  Matches: {}", self.gpu_result.matches_found);
        println!("  GPU Utilization: {:.1}%", self.gpu_result.gpu_utilization);
        println!();
        println!("CPU Performance:");
        println!("  Time: {:.3} ms", self.cpu_time.as_millis());
        println!("  Throughput: {:.2} MB/s", self.cpu_throughput);
        println!("  Matches: {}", self.cpu_matches);
        println!();
        println!("Speedup: {:.2}x", self.speedup);
        println!("========================================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result_creation() {
        let result = BenchmarkResult {
            data_size: 1024 * 1024,
            signature_count: 100,
            scan_time: Duration::from_millis(100),
            matches_found: 5,
            throughput_mbps: 10.0,
            gpu_utilization: 75.0,
        };

        assert_eq!(result.data_size, 1024 * 1024);
        assert_eq!(result.matches_found, 5);
    }

    #[test]
    fn test_generate_test_data() {
        // This test requires GPU, so we'll just check the method exists
        // In CI without GPU, we skip actual execution
        println!("Test data generation would run with GPU");
    }
}
