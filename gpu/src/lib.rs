//! GPU Acceleration for Byte Surgeon
//!
//! This module provides GPU-accelerated operations for signature scanning
//! and other compute-intensive tasks using CUDA and OpenCL.

mod cuda;
mod opencl;
mod memory;
mod benchmark;

pub use cuda::{CudaAccelerator, CudaError};
pub use opencl::{OpenClAccelerator, OpenClError};
pub use memory::{GpuMemory, GpuBuffer};
pub use benchmark::{GpuBenchmark, BenchmarkResult};

use thiserror::Error;
use std::sync::Arc;
use parking_lot::RwLock;

/// GPU acceleration errors
#[derive(Error, Debug)]
pub enum GpuError {
    #[error("CUDA error: {0}")]
    Cuda(#[from] CudaError),

    #[error("OpenCL error: {0}")]
    OpenCl(#[from] OpenClError),

    #[error("No GPU available")]
    NoGpuAvailable,

    #[error("GPU memory allocation failed: {0}")]
    MemoryAllocation(String),

    #[error("GPU kernel execution failed: {0}")]
    KernelExecution(String),

    #[error("Data transfer failed: {0}")]
    DataTransfer(String),
}

/// GPU device information
#[derive(Debug, Clone)]
pub struct GpuDeviceInfo {
    pub name: String,
    pub vendor: String,
    pub compute_capability: (i32, i32),
    pub memory_size: usize,
    pub compute_units: usize,
    pub clock_speed_mhz: u32,
    pub supports_cuda: bool,
    pub supports_opencl: bool,
}

/// GPU accelerator type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuType {
    Cuda,
    OpenCl,
    Auto,
}

/// GPU-accelerated signature scanner
pub struct GpuSignatureScanner {
    device_info: GpuDeviceInfo,
    cuda: Option<Arc<RwLock<CudaAccelerator>>>,
    opencl: Option<Arc<RwLock<OpenClAccelerator>>>,
    gpu_type: GpuType,
}

impl GpuSignatureScanner {
    /// Create a new GPU signature scanner
    pub fn new(gpu_type: GpuType) -> std::result::Result<Self, GpuError> {
        let device_info = Self::detect_gpu()?;

        let cuda = if device_info.supports_cuda {
            Some(Arc::new(RwLock::new(CudaAccelerator::new()?)))
        } else {
            None
        };

        let opencl = if device_info.supports_opencl {
            Some(Arc::new(RwLock::new(OpenClAccelerator::new()?)))
        } else {
            None
        };

        if cuda.is_none() && opencl.is_none() {
            return Err(GpuError::NoGpuAvailable);
        }

        Ok(Self {
            device_info,
            cuda,
            opencl,
            gpu_type,
        })
    }

    /// Detect available GPU
    fn detect_gpu() -> std::result::Result<GpuDeviceInfo, GpuError> {
        // Try CUDA first
        if let Ok(cuda_info) = CudaAccelerator::detect_device() {
            return Ok(cuda_info);
        }

        // Fallback to OpenCL
        if let Ok(opencl_info) = OpenClAccelerator::detect_device() {
            return Ok(opencl_info);
        }

        Err(GpuError::NoGpuAvailable)
    }

    /// Scan data for signatures using GPU
    pub fn scan_signatures(
        &self,
        data: &[u8],
        signatures: &[Signature],
    ) -> std::result::Result<Vec<SignatureMatch>, GpuError> {
        match self.gpu_type {
            GpuType::Cuda => {
                if let Some(cuda) = &self.cuda {
                    let cuda_lock = cuda.read();
                    cuda_lock.scan_signatures(data, signatures)
                } else {
                    Err(GpuError::NoGpuAvailable)
                }
            }
            GpuType::OpenCl => {
                if let Some(opencl) = &self.opencl {
                    let opencl_lock = opencl.read();
                    opencl_lock.scan_signatures(data, signatures)
                } else {
                    Err(GpuError::NoGpuAvailable)
                }
            }
            GpuType::Auto => {
                // Prefer CUDA if available
                if let Some(cuda) = &self.cuda {
                    let cuda_lock = cuda.read();
                    cuda_lock.scan_signatures(data, signatures)
                } else if let Some(opencl) = &self.opencl {
                    let opencl_lock = opencl.read();
                    opencl_lock.scan_signatures(data, signatures)
                } else {
                    Err(GpuError::NoGpuAvailable)
                }
            }
        }
    }

    /// Get device information
    pub fn device_info(&self) -> &GpuDeviceInfo {
        &self.device_info
    }

    /// Get GPU type
    pub fn gpu_type(&self) -> GpuType {
        self.gpu_type
    }
}

/// File signature for GPU scanning
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct Signature {
    pub magic_bytes: [u8; 16],
    pub magic_len: u32,
    pub extension: [u8; 16],
    pub extension_len: u32,
    pub category: u32,
    pub padding: u32,
}

impl Signature {
    /// Create a new signature
    pub fn new(magic: &[u8], extension: &str, category: u32) -> Self {
        let mut magic_bytes = [0u8; 16];
        let mut ext_bytes = [0u8; 16];

        let magic_len = magic.len().min(16);
        magic_bytes[..magic_len].copy_from_slice(&magic[..magic_len]);

        let ext_bytes_slice = extension.as_bytes();
        let ext_len = ext_bytes_slice.len().min(16);
        ext_bytes[..ext_len].copy_from_slice(&ext_bytes_slice[..ext_len]);

        Self {
            magic_bytes,
            magic_len: magic_len as u32,
            extension: ext_bytes,
            extension_len: ext_len as u32,
            category,
            padding: 0,
        }
    }
}

/// Signature match result from GPU scan
#[derive(Debug, Clone)]
pub struct SignatureMatch {
    pub offset: u64,
    pub signature_index: u32,
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_creation() {
        let sig = Signature::new(b"PK\x03\x04", "zip", 1);
        assert_eq!(sig.magic_len, 4);
        assert_eq!(sig.magic_bytes[0], b'P');
        assert_eq!(sig.magic_bytes[1], b'K');
    }

    #[test]
    fn test_gpu_device_detection() {
        // This test will fail if no GPU is available, which is expected in CI
        let result = GpuSignatureScanner::new(GpuType::Auto);
        // We don't assert success because GPU might not be available
        println!("GPU detection result: {:?}", result.is_ok());
    }
}
