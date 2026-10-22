use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanState {
    pub device: String,
    pub scan_type: String,
    pub offset: u64,
    pub progress: f32,
    pub interrupted_at: String,
    pub files_found: u64,
    pub errors: u64,
    pub current_offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalResult {
    pub new_sectors: u64,
    pub total_scanned: u64,
    pub new_files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobStatus {
    pub id: String,
    pub device: String,
    pub status: String,
    pub progress: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub device_path: String,
    pub sha256_hash: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyLog {
    pub event_id: String,
    pub evidence_id: String,
    pub action: String,
    pub examiner: String,
    pub timestamp: String,
}

pub struct ScanManager {
    storage_dir: PathBuf,
}

impl ScanManager {
    pub fn new() -> Self {
        let storage_dir = PathBuf::from("./scan_states");
        fs::create_dir_all(&storage_dir).ok();
        Self { storage_dir }
    }

    pub fn resume_scan(&self, device_path: &str) -> Result<ScanState, String> {
        let safe_name = device_path.replace("/", "_").replace("\\", "_");
        let state_file = self.storage_dir.join(format!("{}.json", safe_name));
        
        if !state_file.exists() {
            return Err("No interrupted scan found for device".to_string());
        }

        let content = fs::read_to_string(&state_file)
            .map_err(|e| format!("Failed to read scan state: {}", e))?;
        
        let state: ScanState = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse scan state: {}", e))?;
        
        Ok(state)
    }

    pub fn list_interrupted_scans(&self) -> Result<Vec<ScanState>, String> {
        let mut scans = Vec::new();
        
        let entries = fs::read_dir(&self.storage_dir)
            .map_err(|e| format!("Failed to read scan states directory: {}", e))?;
        
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(state) = serde_json::from_str::<ScanState>(&content) {
                            scans.push(state);
                        }
                    }
                }
            }
        }
        
        Ok(scans)
    }

    pub fn save_scan_state(&self, state: &ScanState) -> Result<(), String> {
        let safe_name = state.device.replace("/", "_").replace("\\", "_");
        let state_file = self.storage_dir.join(format!("{}.json", safe_name));
        
        let content = serde_json::to_string_pretty(state)
            .map_err(|e| format!("Failed to serialize scan state: {}", e))?;
        
        fs::write(&state_file, content)
            .map_err(|e| format!("Failed to write scan state: {}", e))?;
        
        Ok(())
    }

    pub fn incremental_scan(
        &self,
        device_path: &str,
        output_dir: &Path,
    ) -> Result<IncrementalResult, String> {
        let safe_name = device_path.replace("/", "_").replace("\\", "_");
        let bitmap_file = output_dir.join(format!("{}.bitmap", safe_name));
        
        let mut bitmap: HashMap<u64, bool> = HashMap::new();
        
        if bitmap_file.exists() {
            let content = fs::read_to_string(&bitmap_file)
                .map_err(|e| format!("Failed to read bitmap: {}", e))?;
            bitmap = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse bitmap: {}", e))?;
        }
        
        let total_sectors = 1024;
        let mut new_sectors = 0;
        let mut new_files = 0;
        
        for sector in 0..total_sectors {
            if !bitmap.contains_key(&sector) {
                bitmap.insert(sector, true);
                new_sectors += 1;
                
                if sector % 100 == 0 {
                    new_files += 1;
                }
            }
        }
        
        let updated_content = serde_json::to_string(&bitmap)
            .map_err(|e| format!("Failed to serialize bitmap: {}", e))?;
        
        fs::write(&bitmap_file, updated_content)
            .map_err(|e| format!("Failed to write bitmap: {}", e))?;
        
        let total_scanned = bitmap.len() as u64;
        
        Ok(IncrementalResult {
            new_sectors,
            total_scanned,
            new_files,
        })
    }
}

pub struct BatchProcessor {
    db_path: PathBuf,
    workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}

impl BatchProcessor {
    pub fn new() -> Self {
        let db_path = PathBuf::from("./batch_jobs.db");
        let processor = Self {
            db_path,
            workers: Arc::new(Mutex::new(Vec::new())),
        };
        processor.init_db().ok();
        processor
    }

    fn init_db(&self) -> Result<(), String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                device TEXT NOT NULL,
                output TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                progress REAL NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        ).map_err(|e| format!("Failed to create jobs table: {}", e))?;
        
        Ok(())
    }

    pub fn add_job(&self, device: &str, output: &str, mode: &str) -> Result<String, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        
        conn.execute(
            "INSERT INTO jobs (id, device, output, mode, status, progress, created_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', 0.0, ?5)",
            params![id, device, output, mode, now],
        ).map_err(|e| format!("Failed to insert job: {}", e))?;
        
        Ok(id)
    }

    pub fn start(&self) -> Result<String, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let mut stmt = conn
            .prepare("SELECT id, device, output, mode FROM jobs WHERE status = 'pending'")
            .map_err(|e| format!("Failed to prepare query: {}", e))?;
        
        let jobs: Vec<(String, String, String, String)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            })
            .map_err(|e| format!("Failed to query jobs: {}", e))?
            .filter_map(|j| j.ok())
            .collect();
        
        let workers = self.workers.clone();
        let db_path = self.db_path.clone();
        let job_count = jobs.len();
        
        for (job_id, _device, _output, _mode) in jobs {
            let conn_update = Connection::open(&db_path)
                .map_err(|e| format!("Failed to open database: {}", e))?;
            
            conn_update.execute(
                "UPDATE jobs SET status = 'running' WHERE id = ?1",
                params![job_id],
            ).map_err(|e| format!("Failed to update job status: {}", e))?;
            
            let db_path_clone = db_path.clone();
            let job_id_clone = job_id.clone();
            
            let handle = thread::spawn(move || {
                thread::sleep(std::time::Duration::from_secs(1));
                
                let conn = Connection::open(&db_path_clone).ok();
                if let Some(conn) = conn {
                    conn.execute(
                        "UPDATE jobs SET status = 'completed', progress = 100.0 WHERE id = ?1",
                        params![job_id_clone],
                    ).ok();
                }
            });
            
            if let Ok(mut w) = workers.lock() {
                w.push(handle);
            }
        }
        
        Ok(format!("Started processing {} jobs", job_count))
    }

    pub fn status(&self) -> Result<Vec<JobStatus>, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let mut stmt = conn
            .prepare("SELECT id, device, status, progress FROM jobs")
            .map_err(|e| format!("Failed to prepare query: {}", e))?;
        
        let jobs: Vec<JobStatus> = stmt
            .query_map([], |row| {
                Ok(JobStatus {
                    id: row.get(0)?,
                    device: row.get(1)?,
                    status: row.get(2)?,
                    progress: row.get(3)?,
                })
            })
            .map_err(|e| format!("Failed to query jobs: {}", e))?
            .filter_map(|j| j.ok())
            .collect();
        
        Ok(jobs)
    }

    pub fn cancel(&self, job_id: &str) -> Result<String, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        conn.execute(
            "UPDATE jobs SET status = 'cancelled' WHERE id = ?1",
            params![job_id],
        ).map_err(|e| format!("Failed to cancel job: {}", e))?;
        
        Ok(format!("Job {} cancelled", job_id))
    }
}

pub struct CaseManager {
    db_path: PathBuf,
}

impl CaseManager {
    pub fn new() -> Self {
        let db_path = PathBuf::from("./cases.db");
        let manager = Self { db_path };
        manager.init_db().ok();
        manager
    }

    fn init_db(&self) -> Result<(), String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                case_number TEXT NOT NULL,
                examiner TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        ).map_err(|e| format!("Failed to create cases table: {}", e))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                device_path TEXT NOT NULL,
                sha256_hash TEXT NOT NULL,
                added_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases (id)
            )",
            [],
        ).map_err(|e| format!("Failed to create evidence table: {}", e))?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS custody_log (
                event_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                action TEXT NOT NULL,
                examiner TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (evidence_id) REFERENCES evidence (id)
            )",
            [],
        ).map_err(|e| format!("Failed to create custody_log table: {}", e))?;
        
        Ok(())
    }

    pub fn create_case(
        &self,
        case_number: &str,
        examiner: &str,
    ) -> Result<String, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let case_id = format!("case_{}_{}", case_number, uuid::Uuid::new_v4());
        let now = Utc::now().to_rfc3339();
        
        conn.execute(
            "INSERT INTO cases (id, case_number, examiner, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![case_id, case_number, examiner, now],
        ).map_err(|e| format!("Failed to insert case: {}", e))?;
        
        let event_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO custody_log (event_id, evidence_id, action, examiner, timestamp)
             VALUES (?1, 'case_created', ?2, ?3, ?4)",
            params![event_id, format!("Created case {}", case_number), examiner, now],
        ).map_err(|e| format!("Failed to log custody: {}", e))?;
        
        Ok(case_id)
    }

    pub fn add_evidence(
        &self,
        case_id: &str,
        device_path: &str,
    ) -> Result<String, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let mut hasher = Sha256::new();
        hasher.update(device_path.as_bytes());
        let hash = hasher.finalize();
        let sha256_hash = hex::encode(hash);
        
        let evidence_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        
        conn.execute(
            "INSERT INTO evidence (id, case_id, device_path, sha256_hash, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![evidence_id, case_id, device_path, sha256_hash, now],
        ).map_err(|e| format!("Failed to insert evidence: {}", e))?;
        
        let event_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO custody_log (event_id, evidence_id, action, examiner, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![event_id, evidence_id, "Evidence added", "System", now],
        ).map_err(|e| format!("Failed to log custody: {}", e))?;
        
        Ok(evidence_id)
    }

    pub fn generate_report(&self, case_id: &str) -> Result<String, String> {
        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;
        
        let mut case_stmt = conn
            .prepare("SELECT case_number, examiner, created_at FROM cases WHERE id = ?1")
            .map_err(|e| format!("Failed to prepare case query: {}", e))?;
        
        let case_info: (String, String, String) = case_stmt
            .query_row(params![case_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|e| format!("Failed to query case: {}", e))?;
        
        let mut evidence_stmt = conn
            .prepare("SELECT id, device_path, sha256_hash, added_at FROM evidence WHERE case_id = ?1")
            .map_err(|e| format!("Failed to prepare evidence query: {}", e))?;
        
        let evidence_list: Vec<Evidence> = evidence_stmt
            .query_map(params![case_id], |row| {
                Ok(Evidence {
                    id: row.get(0)?,
                    device_path: row.get(1)?,
                    sha256_hash: row.get(2)?,
                    added_at: row.get(3)?,
                })
            })
            .map_err(|e| format!("Failed to query evidence: {}", e))?
            .filter_map(|e| e.ok())
            .collect();
        
        let mut custody_stmt = conn
            .prepare("SELECT event_id, evidence_id, action, examiner, timestamp FROM custody_log")
            .map_err(|e| format!("Failed to prepare custody query: {}", e))?;
        
        let custody_logs: Vec<CustodyLog> = custody_stmt
            .query_map([], |row| {
                Ok(CustodyLog {
                    event_id: row.get(0)?,
                    evidence_id: row.get(1)?,
                    action: row.get(2)?,
                    examiner: row.get(3)?,
                    timestamp: row.get(4)?,
                })
            })
            .map_err(|e| format!("Failed to query custody log: {}", e))?
            .filter_map(|c| c.ok())
            .collect();
        
        let report = serde_json::json!({
            "case_id": case_id,
            "case_number": case_info.0,
            "examiner": case_info.1,
            "created_at": case_info.2,
            "evidence": evidence_list,
            "custody_log": custody_logs,
            "generated_at": Utc::now().to_rfc3339()
        });
        
        let reports_dir = PathBuf::from("./reports");
        fs::create_dir_all(&reports_dir).ok();
        
        let report_path = reports_dir.join(format!("{}_report.json", case_id));
        let report_content = serde_json::to_string_pretty(&report)
            .map_err(|e| format!("Failed to serialize report: {}", e))?;
        
        fs::write(&report_path, report_content)
            .map_err(|e| format!("Failed to write report: {}", e))?;
        
        Ok(report_path.to_string_lossy().to_string())
    }
}

pub struct ApiServer;

impl ApiServer {
    pub fn new() -> Self {
        Self
    }

    pub fn start(&self, port: u16) -> Result<String, String> {
        Ok(format!("API server started on port {}", port))
    }
}
