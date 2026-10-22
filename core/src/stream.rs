use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
const DEFAULT_CHANNEL_CAPACITY: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    pub offset: u64,
    pub data: Vec<u8>,
    pub is_final: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamProgress {
    pub bytes_read: u64,
    pub total_size: u64,
    pub percentage: f64,
    pub chunks_processed: u64,
    pub source_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamResult {
    pub total_bytes: u64,
    pub total_chunks: u64,
    pub source_path: String,
    pub cancelled: bool,
}

pub struct StreamProcessor {
    chunk_size: usize,
    channel_capacity: usize,
    cancelled: Arc<AtomicBool>,
    bytes_read: Arc<AtomicU64>,
    chunks_processed: Arc<AtomicU64>,
}

impl StreamProcessor {
    pub fn new() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            cancelled: Arc::new(AtomicBool::new(false)),
            bytes_read: Arc::new(AtomicU64::new(0)),
            chunks_processed: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity.max(1);
        self
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn get_bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::SeqCst)
    }

    pub fn get_chunks_processed(&self) -> u64 {
        self.chunks_processed.load(Ordering::SeqCst)
    }

    pub fn stream_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<StreamIterator<BufReader<File>>> {
        let path = path.as_ref();
        info!("Opening file for streaming: {}", path.display());

        let file = File::open(path).map_err(Error::Io)?;
        let metadata = file.metadata().map_err(Error::Io)?;
        let total_size = metadata.len();
        let reader = BufReader::with_capacity(self.chunk_size, file);

        Ok(StreamIterator {
            reader,
            chunk_size: self.chunk_size,
            offset: 0,
            total_size,
            source_path: path.to_path_buf(),
            cancelled: self.cancelled.clone(),
            bytes_read: self.bytes_read.clone(),
            chunks_processed: self.chunks_processed.clone(),
        })
    }

    pub fn stream_device<P: AsRef<Path>>(
        &self,
        device_path: P,
    ) -> Result<StreamIterator<BufReader<File>>> {
        let path = device_path.as_ref();
        info!("Opening device for streaming: {}", path.display());

        let file = File::open(path).map_err(Error::Io)?;
        let total_size = file
            .metadata()
            .map(|m| m.len())
            .unwrap_or(0);
        let reader = BufReader::with_capacity(self.chunk_size, file);

        Ok(StreamIterator {
            reader,
            chunk_size: self.chunk_size,
            offset: 0,
            total_size,
            source_path: path.to_path_buf(),
            cancelled: self.cancelled.clone(),
            bytes_read: self.bytes_read.clone(),
            chunks_processed: self.chunks_processed.clone(),
        })
    }

    pub async fn process_stream<P: AsRef<Path>>(
        &self,
        source: P,
    ) -> Result<StreamResult> {
        let source_path = source.as_ref().to_path_buf();
        info!("Starting async stream processing: {}", source_path.display());

        let (chunk_tx, mut chunk_rx) =
            mpsc::channel::<StreamChunk>(self.channel_capacity);
        let (progress_tx, mut progress_rx) =
            mpsc::channel::<StreamProgress>(self.channel_capacity);

        let cancelled = self.cancelled.clone();
        let bytes_read = self.bytes_read.clone();
        let chunks_processed = self.chunks_processed.clone();
        let chunk_size = self.chunk_size;
        let source_clone = source_path.clone();

        let producer = tokio::task::spawn_blocking(move || {
            let file = File::open(&source_clone).map_err(Error::Io)?;
            let total_size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut reader = BufReader::with_capacity(chunk_size, file);
            let mut offset = 0u64;
            let mut chunk_index = 0u64;
            let mut buf = vec![0u8; chunk_size];

            loop {
                if cancelled.load(Ordering::SeqCst) {
                    info!("Stream producer cancelled");
                    let _ = chunk_tx.blocking_send(StreamChunk {
                        offset,
                        data: Vec::new(),
                        is_final: true,
                    });
                    return Ok::<(), Error>(());
                }

                let bytes_read_count = reader.read(&mut buf).map_err(Error::Io)?;
                if bytes_read_count == 0 {
                    let _ = chunk_tx.blocking_send(StreamChunk {
                        offset,
                        data: Vec::new(),
                        is_final: true,
                    });
                    break;
                }

                bytes_read.fetch_add(bytes_read_count as u64, Ordering::SeqCst);
                chunk_index += 1;
                chunks_processed.store(chunk_index, Ordering::SeqCst);

                let is_final = offset + bytes_read_count as u64 >= total_size && total_size > 0;

                let chunk = StreamChunk {
                    offset,
                    data: buf[..bytes_read_count].to_vec(),
                    is_final,
                };

                if chunk_tx.blocking_send(chunk).is_err() {
                    warn!("Chunk receiver dropped, stopping producer");
                    break;
                }

                offset += bytes_read_count as u64;

                let pct = if total_size > 0 {
                    (offset as f64 / total_size as f64) * 100.0
                } else {
                    0.0
                };

                let _ = progress_tx.blocking_send(StreamProgress {
                    bytes_read: offset,
                    total_size,
                    percentage: pct,
                    chunks_processed: chunk_index,
                    source_path: source_clone.display().to_string(),
                });
            }

            Ok::<(), Error>(())
        });

        let consumer_handle = tokio::spawn({
            let cancelled = self.cancelled.clone();
            async move {
                let mut total_bytes = 0u64;
                let mut total_chunks = 0u64;

                loop {
                    tokio::select! {
                        chunk = chunk_rx.recv() => {
                            match chunk {
                                Some(c) => {
                                    if c.is_final && c.data.is_empty() {
                                        break;
                                    }
                                    total_bytes += c.data.len() as u64;
                                    total_chunks += 1;
                                    debug!(
                                        "Processed chunk {} at offset {} ({} bytes)",
                                        total_chunks, c.offset, c.data.len()
                                    );
                                    if c.is_final {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        progress = progress_rx.recv() => {
                            if let Some(p) = progress {
                                debug!(
                                    "Progress: {:.1}% ({} / {} bytes)",
                                    p.percentage,
                                    p.bytes_read,
                                    p.total_size
                                );
                            }
                        }
                    }

                    if cancelled.load(Ordering::SeqCst) {
                        break;
                    }
                }

                StreamResult {
                    total_bytes,
                    total_chunks,
                    source_path: source_path.display().to_string(),
                    cancelled: cancelled.load(Ordering::SeqCst),
                }
            }
        });

        let _ = producer.await.map_err(|e| {
            Error::Other(format!("Producer task panicked: {}", e))
        })??;

        let result = consumer_handle.await.map_err(|e| {
            Error::Other(format!("Consumer task panicked: {}", e))
        })?;

        info!(
            "Stream processing complete: {} bytes in {} chunks from {}",
            result.total_bytes, result.total_chunks, result.source_path
        );

        Ok(result)
    }

    pub async fn process_stream_with_handler<P, F, Fut>(
        &self,
        source: P,
        mut handler: F,
    ) -> Result<StreamResult>
    where
        P: AsRef<Path>,
        F: FnMut(StreamChunk) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let source_path = source.as_ref().to_path_buf();
        let (chunk_tx, mut chunk_rx) =
            mpsc::channel::<StreamChunk>(self.channel_capacity);

        let cancelled = self.cancelled.clone();
        let cancelled_producer = cancelled.clone();
        let bytes_read = self.bytes_read.clone();
        let chunks_processed = self.chunks_processed.clone();
        let chunk_size = self.chunk_size;
        let source_clone = source_path.clone();

        let producer = tokio::task::spawn_blocking(move || {
            let file = File::open(&source_clone).map_err(Error::Io)?;
            let total_size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut reader = BufReader::with_capacity(chunk_size, file);
            let mut offset = 0u64;
            let mut chunk_index = 0u64;
            let mut buf = vec![0u8; chunk_size];

            loop {
                if cancelled_producer.load(Ordering::SeqCst) {
                    let _ = chunk_tx.blocking_send(StreamChunk {
                        offset,
                        data: Vec::new(),
                        is_final: true,
                    });
                    return Ok::<(), Error>(());
                }

                let n = reader.read(&mut buf).map_err(Error::Io)?;
                if n == 0 {
                    let _ = chunk_tx.blocking_send(StreamChunk {
                        offset,
                        data: Vec::new(),
                        is_final: true,
                    });
                    break;
                }

                bytes_read.fetch_add(n as u64, Ordering::SeqCst);
                chunk_index += 1;
                chunks_processed.store(chunk_index, Ordering::SeqCst);

                let is_final =
                    total_size > 0 && offset + n as u64 >= total_size;

                let chunk = StreamChunk {
                    offset,
                    data: buf[..n].to_vec(),
                    is_final,
                };

                if chunk_tx.blocking_send(chunk).is_err() {
                    break;
                }

                offset += n as u64;
            }

            Ok(())
        });

        let consumer_cancelled = self.cancelled.clone();
        let consumer_handle = tokio::spawn(async move {
            let mut total_bytes = 0u64;
            let mut total_chunks = 0u64;

            while let Some(chunk) = chunk_rx.recv().await {
                if chunk.is_final && chunk.data.is_empty() {
                    break;
                }
                total_bytes += chunk.data.len() as u64;
                total_chunks += 1;
                let is_final = chunk.is_final;
                handler(chunk).await?;
                if is_final {
                    break;
                }
            }

            Ok::<StreamResult, Error>(StreamResult {
                total_bytes,
                total_chunks,
                source_path: source_path.display().to_string(),
                cancelled: consumer_cancelled.load(Ordering::SeqCst),
            })
        });

        producer.await.map_err(|e| {
            Error::Other(format!("Producer panicked: {}", e))
        })??;

        let result = consumer_handle.await.map_err(|e| {
            Error::Other(format!("Consumer panicked: {}", e))
        })??;

        Ok(result)
    }
}

impl Default for StreamProcessor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StreamIterator<R: Read> {
    reader: R,
    chunk_size: usize,
    offset: u64,
    total_size: u64,
    source_path: PathBuf,
    cancelled: Arc<AtomicBool>,
    bytes_read: Arc<AtomicU64>,
    chunks_processed: Arc<AtomicU64>,
}

impl<R: Read> Iterator for StreamIterator<R> {
    type Item = Result<StreamChunk>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cancelled.load(Ordering::SeqCst) {
            return None;
        }

        let mut buf = vec![0u8; self.chunk_size];
        match self.reader.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                self.bytes_read
                    .fetch_add(n as u64, Ordering::SeqCst);
                let chunk_num = self
                    .chunks_processed
                    .fetch_add(1, Ordering::SeqCst)
                    + 1;
                let is_final = self.total_size > 0
                    && self.offset + n as u64 >= self.total_size;
                self.offset += n as u64;

                debug!(
                    "Stream chunk {} from {} at offset {} ({} bytes, final={})",
                    chunk_num,
                    self.source_path.display(),
                    self.offset - n as u64,
                    n,
                    is_final
                );

                Some(Ok(StreamChunk {
                    offset: self.offset - n as u64,
                    data: buf,
                    is_final,
                }))
            }
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

impl<R: Read> StreamIterator<R> {
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file(size: usize) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        let data = vec![0xABu8; size];
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn test_stream_processor_creation() {
        let proc = StreamProcessor::new();
        assert_eq!(proc.chunk_size, DEFAULT_CHUNK_SIZE);
        assert_eq!(proc.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
        assert!(!proc.is_cancelled());
        assert_eq!(proc.get_bytes_read(), 0);
        assert_eq!(proc.get_chunks_processed(), 0);
    }

    #[test]
    fn test_with_chunk_size() {
        let proc = StreamProcessor::new().with_chunk_size(1024);
        assert_eq!(proc.chunk_size, 1024);
    }

    #[test]
    fn test_with_channel_capacity() {
        let proc = StreamProcessor::new().with_channel_capacity(32);
        assert_eq!(proc.channel_capacity, 32);
    }

    #[test]
    fn test_channel_capacity_minimum() {
        let proc = StreamProcessor::new().with_channel_capacity(0);
        assert_eq!(proc.channel_capacity, 1);
    }

    #[test]
    fn test_cancellation() {
        let proc = StreamProcessor::new();
        assert!(!proc.is_cancelled());
        proc.cancel();
        assert!(proc.is_cancelled());
    }

    #[test]
    fn test_stream_file_iterator() {
        let tmp = create_temp_file(256);
        let proc = StreamProcessor::new().with_chunk_size(64);
        let iter = proc.stream_file(tmp.path()).unwrap();

        let chunks: Vec<StreamChunk> = iter
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].data.len(), 64);
        assert_eq!(chunks[1].offset, 64);
        assert_eq!(chunks[2].offset, 128);
        assert_eq!(chunks[3].offset, 192);
        assert!(chunks[3].is_final);
    }

    #[test]
    fn test_stream_file_single_chunk() {
        let tmp = create_temp_file(32);
        let proc = StreamProcessor::new().with_chunk_size(64);
        let iter = proc.stream_file(tmp.path()).unwrap();

        let chunks: Vec<StreamChunk> = iter
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data.len(), 32);
        assert!(chunks[0].is_final);
    }

    #[test]
    fn test_stream_file_empty() {
        let tmp = NamedTempFile::new().unwrap();
        let proc = StreamProcessor::new();
        let iter = proc.stream_file(tmp.path()).unwrap();

        let chunks: Vec<StreamChunk> = iter
            .map(|r| r.unwrap())
            .collect();

        assert!(chunks.is_empty());
    }

    #[test]
    fn test_stream_file_nonexistent() {
        let proc = StreamProcessor::new();
        let result = proc.stream_file("/nonexistent/path/file.bin");
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_iterator_cancel() {
        let tmp = create_temp_file(1024);
        let proc = StreamProcessor::new().with_chunk_size(64);
        let iter = proc.stream_file(tmp.path()).unwrap();

        iter.cancel();

        let chunks: Vec<_> = iter.collect();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_stream_iterator_tracks_bytes() {
        let tmp = create_temp_file(256);
        let proc = StreamProcessor::new().with_chunk_size(64);
        let iter = proc.stream_file(tmp.path()).unwrap();

        let _chunks: Vec<_> = iter
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(proc.get_bytes_read(), 256);
        assert_eq!(proc.get_chunks_processed(), 4);
    }

    #[test]
    fn test_stream_iterator_metadata() {
        let tmp = create_temp_file(128);
        let proc = StreamProcessor::new().with_chunk_size(64);
        let iter = proc.stream_file(tmp.path()).unwrap();

        assert_eq!(iter.total_size(), 128);
        assert_eq!(iter.source_path(), tmp.path());
    }

    #[test]
    fn test_stream_device() {
        let tmp = create_temp_file(512);
        let proc = StreamProcessor::new().with_chunk_size(128);
        let iter = proc.stream_device(tmp.path()).unwrap();

        let chunks: Vec<StreamChunk> = iter
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data.len(), 128);
    }

    #[tokio::test]
    async fn test_process_stream_async() {
        let tmp = create_temp_file(1024);
        let proc = StreamProcessor::new().with_chunk_size(256);

        let result = proc.process_stream(tmp.path()).await.unwrap();

        assert_eq!(result.total_bytes, 1024);
        assert_eq!(result.total_chunks, 4);
        assert!(!result.cancelled);
    }

    #[tokio::test]
    async fn test_process_stream_small_file() {
        let tmp = create_temp_file(10);
        let proc = StreamProcessor::new().with_chunk_size(1024);

        let result = proc.process_stream(tmp.path()).await.unwrap();

        assert_eq!(result.total_bytes, 10);
        assert_eq!(result.total_chunks, 1);
    }

    #[tokio::test]
    async fn test_process_stream_empty_file() {
        let tmp = NamedTempFile::new().unwrap();
        let proc = StreamProcessor::new();

        let result = proc.process_stream(tmp.path()).await.unwrap();

        assert_eq!(result.total_bytes, 0);
        assert_eq!(result.total_chunks, 0);
    }

    #[tokio::test]
    async fn test_process_stream_cancelled() {
        let tmp = create_temp_file(1024 * 1024);
        let proc = StreamProcessor::new()
            .with_chunk_size(64)
            .with_channel_capacity(1);

        proc.cancel();

        let result = proc.process_stream(tmp.path()).await.unwrap();

        assert!(result.cancelled);
    }

    #[tokio::test]
    async fn test_process_stream_nonexistent() {
        let proc = StreamProcessor::new();
        let result = proc.process_stream("/nonexistent/file.bin").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_process_stream_with_handler() {
        let tmp = create_temp_file(512);
        let proc = StreamProcessor::new().with_chunk_size(128);

        let total = Arc::new(AtomicU64::new(0));
        let total_clone = total.clone();

        let result = proc
            .process_stream_with_handler(tmp.path(), move |chunk| {
                let total = total_clone.clone();
                async move {
                    total.fetch_add(chunk.data.len() as u64, Ordering::SeqCst);
                    Ok(())
                }
            })
            .await
            .unwrap();

        assert_eq!(result.total_bytes, 512);
        assert_eq!(result.total_chunks, 4);
        assert_eq!(total.load(Ordering::SeqCst), 512);
    }

    #[tokio::test]
    async fn test_process_stream_backpressure() {
        let tmp = create_temp_file(4096);
        let proc = StreamProcessor::new()
            .with_chunk_size(256)
            .with_channel_capacity(2);

        let result = proc.process_stream(tmp.path()).await.unwrap();

        assert_eq!(result.total_bytes, 4096);
        assert_eq!(result.total_chunks, 16);
    }

    #[tokio::test]
    async fn test_stream_progress_reporting() {
        let tmp = create_temp_file(2048);
        let proc = StreamProcessor::new().with_chunk_size(512);

        let result = proc.process_stream(tmp.path()).await.unwrap();

        assert_eq!(result.total_bytes, 2048);
        assert_eq!(result.total_chunks, 4);
        assert_eq!(proc.get_bytes_read(), 2048);
    }

    #[test]
    fn test_stream_iterator_uneven_chunks() {
        let tmp = create_temp_file(200);
        let proc = StreamProcessor::new().with_chunk_size(64);
        let iter = proc.stream_file(tmp.path()).unwrap();

        let chunks: Vec<StreamChunk> = iter
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].data.len(), 64);
        assert_eq!(chunks[1].data.len(), 64);
        assert_eq!(chunks[2].data.len(), 64);
        assert_eq!(chunks[3].data.len(), 8);
        assert!(chunks[3].is_final);
    }

    #[tokio::test]
    async fn test_default_stream_processor() {
        let proc = StreamProcessor::default();
        assert_eq!(proc.chunk_size, DEFAULT_CHUNK_SIZE);
    }
}
