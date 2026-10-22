use crate::error::{SdkError, SdkResult};
use datadoctor_core::{
    RecoveryEngine, RecoveredFile, ScanType,
    DeviceInfo, RecoveryStatus,
    RecoveryFilter,
};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

pub struct RecoveryBuilder {
    data_dir: PathBuf,
    output_dir: PathBuf,
    scan_type: ScanType,
    device_path: Option<String>,
    filter: Option<RecoveryFilter>,
    max_file_size: Option<u64>,
    on_progress: Option<Arc<dyn Fn(u64, u64, u64) + Send + Sync>>,
    on_file_recovered: Option<Arc<dyn Fn(&RecoveredFile) + Send + Sync>>,
    on_complete: Option<Arc<dyn Fn(&RecoveryReport) + Send + Sync>>,
}

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    pub session_id: String,
    pub files_found: u64,
    pub files_recovered: u64,
    pub total_bytes_recovered: u64,
}

impl RecoveryBuilder {
    pub fn new() -> Self {
        Self {
            data_dir: PathBuf::from("./datadoctor_data"),
            output_dir: PathBuf::from("./recovered"),
            scan_type: ScanType::Deep,
            device_path: None,
            filter: None,
            max_file_size: None,
            on_progress: None,
            on_file_recovered: None,
            on_complete: None,
        }
    }

    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = path.into();
        self
    }

    pub fn output_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_dir = path.into();
        self
    }

    pub fn scan_type(mut self, scan_type: ScanType) -> Self {
        self.scan_type = scan_type;
        self
    }

    pub fn quick_scan(self) -> Self {
        self.scan_type(ScanType::Quick)
    }

    pub fn deep_scan(self) -> Self {
        self.scan_type(ScanType::Deep)
    }

    pub fn signature_scan(self) -> Self {
        self.scan_type(ScanType::Signature)
    }

    pub fn filesystem_scan(self) -> Self {
        self.scan_type(ScanType::FileSystem)
    }

    pub fn raw_scan(self) -> Self {
        self.scan_type(ScanType::Raw)
    }

    pub fn device(mut self, path: impl Into<String>) -> Self {
        self.device_path = Some(path.into());
        self
    }

    pub fn filter(mut self, filter: RecoveryFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = Some(size);
        self
    }

    pub fn on_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(u64, u64, u64) + Send + Sync + 'static,
    {
        self.on_progress = Some(Arc::new(callback));
        self
    }

    pub fn on_file_recovered<F>(mut self, callback: F) -> Self
    where
        F: Fn(&RecoveredFile) + Send + Sync + 'static,
    {
        self.on_file_recovered = Some(Arc::new(callback));
        self
    }

    pub fn on_complete<F>(mut self, callback: F) -> Self
    where
        F: Fn(&RecoveryReport) + Send + Sync + 'static,
    {
        self.on_complete = Some(Arc::new(callback));
        self
    }

    pub fn build(self) -> SdkResult<RecoveryOperation> {
        let device_path = self.device_path.ok_or_else(|| {
            SdkError::Config("No device path specified. Use .device() to set the target.".into())
        })?;

        let engine = RecoveryEngine::new(&self.data_dir)
            .map_err(|e| SdkError::Core(e))?;

        Ok(RecoveryOperation {
            engine,
            device_path,
            scan_type: self.scan_type,
            output_dir: self.output_dir,
            filter: self.filter,
            max_file_size: self.max_file_size,
            on_progress: self.on_progress,
            on_file_recovered: self.on_file_recovered,
            on_complete: self.on_complete,
        })
    }
}

impl Default for RecoveryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RecoveryOperation {
    engine: RecoveryEngine,
    device_path: String,
    scan_type: ScanType,
    output_dir: PathBuf,
    #[allow(dead_code)]
    filter: Option<RecoveryFilter>,
    #[allow(dead_code)]
    max_file_size: Option<u64>,
    on_progress: Option<Arc<dyn Fn(u64, u64, u64) + Send + Sync>>,
    on_file_recovered: Option<Arc<dyn Fn(&RecoveredFile) + Send + Sync>>,
    on_complete: Option<Arc<dyn Fn(&RecoveryReport) + Send + Sync>>,
}

impl RecoveryOperation {
    pub fn execute(self) -> SdkResult<RecoveryReport> {
        info!("Starting recovery on device: {}", self.device_path);

        std::fs::create_dir_all(&self.output_dir)
            .map_err(|e| SdkError::Io(e))?;

        let device_info = DeviceInfo::new(&self.device_path, "target");
        let session_id = self.engine.start_recovery(
            &device_info,
            self.scan_type.clone(),
            &self.output_dir,
        ).map_err(|e| SdkError::Core(e))?;

        let _session = self.engine.get_session(&session_id)
            .map_err(|e| SdkError::Core(e))?;

        let recovered_files = self.engine.get_recovered_files(&session_id)
            .map_err(|e| SdkError::Core(e))?;

        let files_found = recovered_files.len() as u64;
        let files_recovered = recovered_files.iter()
            .filter(|f| f.status == RecoveryStatus::Completed)
            .count() as u64;
        let total_bytes = recovered_files.iter()
            .map(|f| f.file_size)
            .sum::<u64>();

        if let Some(ref cb) = self.on_progress {
            cb(total_bytes, total_bytes, files_recovered);
        }

        if let Some(ref cb) = self.on_file_recovered {
            for file in &recovered_files {
                cb(file);
            }
        }

        let report = RecoveryReport {
            session_id: session_id.clone(),
            files_found,
            files_recovered,
            total_bytes_recovered: total_bytes,
        };

        if let Some(ref cb) = self.on_complete {
            cb(&report);
        }

        info!(
            "Recovery complete: {} found, {} recovered, {} bytes",
            files_found, files_recovered, total_bytes
        );

        Ok(report)
    }

    pub fn cancel(&self) -> SdkResult<()> {
        self.engine.cancel_session("current")
            .map_err(|e| SdkError::Core(e))
    }
}
