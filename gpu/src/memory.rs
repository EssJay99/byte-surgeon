//! GPU memory management for Data Doctor
//!
//! Provides abstractions for GPU memory allocation and data transfer.

use crate::GpuError;
use std::sync::Arc;
use parking_lot::Mutex;
use tracing::debug;

/// GPU memory buffer
pub struct GpuBuffer<T: Copy + 'static> {
    data: Arc<Mutex<Vec<T>>>,
    size: usize,
    device_id: u64,
}

impl<T: Copy + 'static> GpuBuffer<T> {
    /// Create a new GPU buffer
    pub fn new(size: usize, device_id: u64) -> std::result::Result<Self, GpuError> {
        // In a real implementation, this would allocate GPU memory
        // For now, simulate with CPU memory
        let data = vec![unsafe { std::mem::zeroed() }; size];

        debug!("Allocated GPU buffer: {} elements on device {}", size, device_id);

        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            size,
            device_id,
        })
    }

    /// Write data to GPU buffer
    pub fn write(&self, data: &[T]) -> std::result::Result<(), GpuError> {
        if data.len() > self.size {
            return Err(GpuError::MemoryAllocation(
                "Data too large for buffer".to_string(),
            ));
        }

        let mut buffer = self.data.lock();
        buffer[..data.len()].copy_from_slice(data);
        debug!("Wrote {} elements to GPU buffer", data.len());
        Ok(())
    }

    /// Read data from GPU buffer
    pub fn read(&self) -> std::result::Result<Vec<T>, GpuError> {
        let buffer = self.data.lock();
        debug!("Read {} elements from GPU buffer", buffer.len());
        Ok(buffer.clone())
    }

    /// Get buffer size
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get device ID
    pub fn device_id(&self) -> u64 {
        self.device_id
    }
}

/// GPU memory manager
pub struct GpuMemory {
    device_id: u64,
    allocated_buffers: Vec<usize>,
    total_allocated: usize,
    max_memory: usize,
}

impl GpuMemory {
    /// Create a new GPU memory manager
    pub fn new(device_id: u64, max_memory: usize) -> Self {
        debug!(
            "Initialized GPU memory manager: device {}, max {} bytes",
            device_id, max_memory
        );

        Self {
            device_id,
            allocated_buffers: Vec::new(),
            total_allocated: 0,
            max_memory,
        }
    }

    /// Allocate a new buffer
    pub fn allocate<T: Copy + 'static>(&mut self, size: usize) -> std::result::Result<GpuBuffer<T>, GpuError> {
        let required = size * std::mem::size_of::<T>();

        if self.total_allocated + required > self.max_memory {
            return Err(GpuError::MemoryAllocation(
                "Insufficient GPU memory".to_string(),
            ));
        }

        let buffer = GpuBuffer::new(size, self.device_id)?;
        self.allocated_buffers.push(required);
        self.total_allocated += required;

        debug!("Allocated {} bytes, total: {} bytes", required, self.total_allocated);
        Ok(buffer)
    }

    /// Free memory
    pub fn free(&mut self, size: usize) {
        if let Some(pos) = self.allocated_buffers.iter().position(|&s| s == size) {
            self.allocated_buffers.remove(pos);
            self.total_allocated -= size;
            debug!("Freed {} bytes, total: {} bytes", size, self.total_allocated);
        }
    }

    /// Get total allocated memory
    pub fn total_allocated(&self) -> usize {
        self.total_allocated
    }

    /// Get available memory
    pub fn available(&self) -> usize {
        self.max_memory - self.total_allocated
    }

    /// Get memory utilization percentage
    pub fn utilization(&self) -> f64 {
        (self.total_allocated as f64 / self.max_memory as f64) * 100.0
    }

    /// Get device ID
    pub fn device_id(&self) -> u64 {
        self.device_id
    }
}

/// GPU memory statistics
#[derive(Debug, Clone)]
pub struct GpuMemoryStats {
    pub total_allocated: usize,
    pub available: usize,
    pub max_memory: usize,
    pub utilization: f64,
    pub buffer_count: usize,
}

impl GpuMemory {
    /// Get memory statistics
    pub fn stats(&self) -> GpuMemoryStats {
        GpuMemoryStats {
            total_allocated: self.total_allocated,
            available: self.available(),
            max_memory: self.max_memory,
            utilization: self.utilization(),
            buffer_count: self.allocated_buffers.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_buffer_creation() {
        let buffer = GpuBuffer::<u8>::new(1024, 1).unwrap();
        assert_eq!(buffer.size(), 1024);
        assert_eq!(buffer.device_id(), 1);
    }

    #[test]
    fn test_gpu_buffer_write_read() {
        let buffer = GpuBuffer::<u8>::new(10, 1).unwrap();
        let data = vec![1u8, 2, 3, 4, 5];
        buffer.write(&data).unwrap();
        let read_data = buffer.read().unwrap();
        assert_eq!(&read_data[..5], &data);
    }

    #[test]
    fn test_gpu_memory_manager() {
        let mut manager = GpuMemory::new(1, 1024 * 1024);
        assert_eq!(manager.total_allocated(), 0);
        assert_eq!(manager.available(), 1024 * 1024);
    }

    #[test]
    fn test_gpu_memory_allocation() {
        let mut manager = GpuMemory::new(1, 1024);
        let buffer: GpuBuffer<u8> = manager.allocate(512).unwrap();
        assert_eq!(manager.total_allocated(), 512);
        assert_eq!(manager.available(), 512);
    }

    #[test]
    fn test_gpu_memory_stats() {
        let mut manager = GpuMemory::new(1, 1024);
        let _: GpuBuffer<u8> = manager.allocate(256).unwrap();
        let stats = manager.stats();
        assert_eq!(stats.total_allocated, 256);
        assert_eq!(stats.available, 768);
        assert_eq!(stats.buffer_count, 1);
    }
}
