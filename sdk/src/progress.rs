use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct ProgressReporter {
    total: u64,
    current: Arc<Mutex<u64>>,
    files_found: Arc<Mutex<u64>>,
    files_recovered: Arc<Mutex<u64>>,
    started_at: Instant,
    on_update: Arc<dyn Fn(ProgressSnapshot) + Send + Sync>,
}

#[derive(Debug, Clone)]
pub struct ProgressSnapshot {
    pub current: u64,
    pub total: u64,
    pub percentage: f64,
    pub files_found: u64,
    pub files_recovered: u64,
    pub elapsed_secs: f64,
    pub bytes_per_second: f64,
    pub estimated_remaining_secs: Option<f64>,
}

impl ProgressReporter {
    pub fn new(total: u64) -> Self {
        Self {
            total,
            current: Arc::new(Mutex::new(0)),
            files_found: Arc::new(Mutex::new(0)),
            files_recovered: Arc::new(Mutex::new(0)),
            started_at: Instant::now(),
            on_update: Arc::new(|_| {}),
        }
    }

    pub fn on_update<F>(mut self, callback: F) -> Self
    where
        F: Fn(ProgressSnapshot) + Send + Sync + 'static,
    {
        self.on_update = Arc::new(callback);
        self
    }

    pub fn update(&self, current: u64) {
        {
            let mut c = self.current.lock().unwrap();
            *c = current;
        }
        self.emit_snapshot();
    }

    pub fn increment(&self, amount: u64) {
        {
            let mut c = self.current.lock().unwrap();
            *c += amount;
        }
        self.emit_snapshot();
    }

    pub fn set_files_found(&self, count: u64) {
        let mut f = self.files_found.lock().unwrap();
        *f = count;
    }

    pub fn set_files_recovered(&self, count: u64) {
        let mut f = self.files_recovered.lock().unwrap();
        *f = count;
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        let current = *self.current.lock().unwrap();
        let files_found = *self.files_found.lock().unwrap();
        let files_recovered = *self.files_recovered.lock().unwrap();
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let percentage = if self.total > 0 {
            (current as f64 / self.total as f64) * 100.0
        } else {
            0.0
        };
        let bps = if elapsed > 0.0 { current as f64 / elapsed } else { 0.0 };
        let remaining = if bps > 0.0 && current < self.total {
            Some((self.total - current) as f64 / bps)
        } else {
            None
        };

        ProgressSnapshot {
            current,
            total: self.total,
            percentage,
            files_found,
            files_recovered,
            elapsed_secs: elapsed,
            bytes_per_second: bps,
            estimated_remaining_secs: remaining,
        }
    }

    fn emit_snapshot(&self) {
        let snap = self.snapshot();
        (self.on_update)(snap);
    }
}
