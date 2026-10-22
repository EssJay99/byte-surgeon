use crate::{Error, Result, RecoverySession, RecoveredFile, DeviceInfo};
use rusqlite::{Connection, params, Row};
use parking_lot::Mutex;
use std::path::Path;
use std::sync::Arc;

fn json_err(e: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

fn parse_err(e: chrono::ParseError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(e))
}

fn parse_session(row: &Row) -> rusqlite::Result<RecoverySession> {
    let device_info_str: String = row.get(2)?;
    let status_str: String = row.get(5)?;
    let scan_type_str: String = row.get(6)?;
    let started_str: String = row.get(3)?;
    let completed_str: Option<String> = row.get(4)?;

    Ok(RecoverySession {
        id: row.get(0)?,
        device_id: row.get(1)?,
        device_info: serde_json::from_str(&device_info_str).map_err(json_err)?,
        started_at: chrono::DateTime::parse_from_rfc3339(&started_str).map_err(parse_err)?.with_timezone(&chrono::Utc),
        completed_at: completed_str.and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok()).map(|dt| dt.with_timezone(&chrono::Utc)),
        status: serde_json::from_str(&status_str).map_err(json_err)?,
        scan_type: serde_json::from_str(&scan_type_str).map_err(json_err)?,
        files_found: row.get(7)?,
        files_recovered: row.get(8)?,
        total_size_recovered: row.get(9)?,
        output_path: row.get(10)?,
    })
}

fn parse_recovered_file(row: &Row) -> rusqlite::Result<RecoveredFile> {
    let status_str: String = row.get(9)?;
    let integrity_str: String = row.get(10)?;
    let threat_str: String = row.get(11)?;
    let recovered_str: String = row.get(12)?;
    let metadata_str: Option<String> = row.get(13)?;

    Ok(RecoveredFile {
        id: row.get(0)?,
        session_id: row.get(1)?,
        original_path: row.get(2)?,
        original_name: row.get(3)?,
        recovered_path: row.get(4)?,
        file_size: row.get(5)?,
        file_type: row.get(6)?,
        extension: row.get(7)?,
        signature: row.get(8)?,
        status: serde_json::from_str(&status_str).map_err(json_err)?,
        integrity_check: serde_json::from_str(&integrity_str).map_err(json_err)?,
        threat_scan: serde_json::from_str(&threat_str).map_err(json_err)?,
        recovered_at: chrono::DateTime::parse_from_rfc3339(&recovered_str).map_err(parse_err)?.with_timezone(&chrono::Utc),
        metadata: metadata_str.and_then(|s| serde_json::from_str(&s).ok()),
    })
}

fn parse_device(row: &Row) -> rusqlite::Result<DeviceInfo> {
    let device_type_str: String = row.get(2)?;
    let file_system_str: String = row.get(6)?;
    let connected_str: String = row.get(12)?;

    Ok(DeviceInfo {
        id: row.get(0)?,
        name: row.get(1)?,
        device_type: serde_json::from_str(&device_type_str).map_err(json_err)?,
        path: row.get(3)?,
        total_size: row.get(4)?,
        free_space: row.get(5)?,
        file_system: serde_json::from_str(&file_system_str).map_err(json_err)?,
        is_network_device: row.get::<_, i32>(7)? != 0,
        mount_point: row.get(8)?,
        serial_number: row.get(9)?,
        model: row.get(10)?,
        vendor: row.get(11)?,
        connected_at: chrono::DateTime::parse_from_rfc3339(&connected_str).map_err(parse_err)?.with_timezone(&chrono::Utc),
    })
}

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize()?;
        Ok(db)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.conn.lock();
        
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                device_info TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                files_found INTEGER NOT NULL DEFAULT 0,
                files_recovered INTEGER NOT NULL DEFAULT 0,
                total_size_recovered INTEGER NOT NULL DEFAULT 0,
                output_path TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovered_files (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                original_path TEXT,
                original_name TEXT,
                recovered_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_type TEXT NOT NULL,
                extension TEXT NOT NULL,
                signature TEXT NOT NULL,
                status TEXT NOT NULL,
                integrity_check TEXT NOT NULL,
                threat_scan TEXT NOT NULL,
                recovered_at TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                path TEXT NOT NULL,
                total_size INTEGER NOT NULL,
                free_space INTEGER NOT NULL,
                file_system TEXT NOT NULL,
                is_network_device INTEGER NOT NULL,
                mount_point TEXT,
                serial_number TEXT,
                model TEXT,
                vendor TEXT,
                connected_at TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_session ON recovered_files(session_id);
            CREATE INDEX IF NOT EXISTS idx_files_status ON recovered_files(status);
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
            CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);"
        )?;

        Ok(())
    }

    pub fn save_session(&self, session: &RecoverySession) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO sessions (
                id, device_id, device_info, started_at, completed_at, 
                status, scan_type, files_found, files_recovered, 
                total_size_recovered, output_path
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                session.id,
                session.device_id,
                serde_json::to_string(&session.device_info)?,
                session.started_at.to_rfc3339(),
                session.completed_at.map(|t| t.to_rfc3339()),
                serde_json::to_string(&session.status)?,
                serde_json::to_string(&session.scan_type)?,
                session.files_found,
                session.files_recovered,
                session.total_size_recovered,
                session.output_path,
            ],
        )?;
        Ok(())
    }

    pub fn update_session_progress(
        &self,
        session_id: &str,
        files_found: u64,
        files_recovered: u64,
        total_size: u64,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE sessions SET files_found = ?1, files_recovered = ?2, total_size_recovered = ?3 WHERE id = ?4",
            params![files_found, files_recovered, total_size, session_id],
        )?;
        Ok(())
    }

    pub fn save_recovered_file(&self, file: &RecoveredFile) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO recovered_files (
                id, session_id, original_path, original_name, recovered_path,
                file_size, file_type, extension, signature, status,
                integrity_check, threat_scan, recovered_at, metadata
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                file.id,
                file.session_id,
                file.original_path,
                file.original_name,
                file.recovered_path,
                file.file_size,
                file.file_type,
                file.extension,
                file.signature,
                serde_json::to_string(&file.status)?,
                serde_json::to_string(&file.integrity_check)?,
                serde_json::to_string(&file.threat_scan)?,
                file.recovered_at.to_rfc3339(),
                file.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap_or_default()),
            ],
        )?;
        Ok(())
    }

    pub fn save_device(&self, device: &DeviceInfo) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO devices (
                id, name, device_type, path, total_size, free_space,
                file_system, is_network_device, mount_point, serial_number,
                model, vendor, connected_at, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                device.id,
                device.name,
                serde_json::to_string(&device.device_type)?,
                device.path,
                device.total_size,
                device.free_space,
                serde_json::to_string(&device.file_system)?,
                device.is_network_device as i32,
                device.mount_point,
                device.serial_number,
                device.model,
                device.vendor,
                device.connected_at.to_rfc3339(),
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<RecoverySession>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, device_id, device_info, started_at, completed_at, status, scan_type, files_found, files_recovered, total_size_recovered, output_path FROM sessions WHERE id = ?1"
        )?;
        
        let result = stmt.query_row(params![session_id], parse_session);

        match result {
            Ok(session) => Ok(Some(session)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Database(e)),
        }
    }

    pub fn get_sessions_for_device(&self, device_id: &str) -> Result<Vec<RecoverySession>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, device_id, device_info, started_at, completed_at, status, scan_type, files_found, files_recovered, total_size_recovered, output_path FROM sessions WHERE device_id = ?1 ORDER BY started_at DESC"
        )?;
        
        let sessions = stmt.query_map(params![device_id], parse_session)?;

        let mut result = Vec::new();
        for session in sessions {
            result.push(session?);
        }
        Ok(result)
    }

    pub fn get_recovered_files(&self, session_id: &str) -> Result<Vec<RecoveredFile>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, original_path, original_name, recovered_path, file_size, file_type, extension, signature, status, integrity_check, threat_scan, recovered_at, metadata FROM recovered_files WHERE session_id = ?1"
        )?;
        
        let files = stmt.query_map(params![session_id], parse_recovered_file)?;

        let mut result = Vec::new();
        for file in files {
            result.push(file?);
        }
        Ok(result)
    }

    pub fn get_all_devices(&self) -> Result<Vec<DeviceInfo>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, device_type, path, total_size, free_space, file_system, is_network_device, mount_point, serial_number, model, vendor, connected_at FROM devices ORDER BY last_seen DESC"
        )?;
        
        let devices = stmt.query_map([], parse_device)?;

        let mut result = Vec::new();
        for device in devices {
            result.push(device?);
        }
        Ok(result)
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::{DeviceInfo, RecoverySession, RecoveredFile, ScanType, SessionStatus};

    fn create_test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = Database::new(&db_path).unwrap();
        (db, temp_dir)
    }

    fn create_test_device() -> DeviceInfo {
        DeviceInfo::new("/dev/sda", "TestDisk")
    }

    #[test]
    fn test_database_creation() {
        let (db, _temp) = create_test_db();
        let devices = db.get_all_devices().unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_save_and_retrieve_session() {
        let (db, _temp) = create_test_db();
        let device = create_test_device();
        let session = RecoverySession::new(device, ScanType::Deep, "/output");

        db.save_session(&session).unwrap();
        let retrieved = db.get_session(&session.id).unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, session.id);
        assert_eq!(retrieved.output_path, "/output");
        assert_eq!(retrieved.scan_type, ScanType::Deep);
        assert_eq!(retrieved.status, SessionStatus::Active);
        assert_eq!(retrieved.files_found, 0);
    }

    #[test]
    fn test_save_and_retrieve_device() {
        let (db, _temp) = create_test_db();
        let device = create_test_device();

        db.save_device(&device).unwrap();
        let devices = db.get_all_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "TestDisk");
        assert_eq!(devices[0].path, "/dev/sda");
    }

    #[test]
    fn test_save_and_retrieve_recovered_files() {
        let (db, _temp) = create_test_db();
        let device = create_test_device();
        let session = RecoverySession::new(device, ScanType::Quick, "/out");
        db.save_session(&session).unwrap();

        let mut file1 = RecoveredFile::new(&session.id, "/tmp/file1.jpg");
        file1.file_size = 1024;
        file1.extension = "jpg".to_string();
        file1.file_type = "Image".to_string();
        file1.signature = "abc123".to_string();

        let mut file2 = RecoveredFile::new(&session.id, "/tmp/file2.png");
        file2.file_size = 2048;
        file2.extension = "png".to_string();
        file2.file_type = "Image".to_string();
        file2.signature = "def456".to_string();

        db.save_recovered_file(&file1).unwrap();
        db.save_recovered_file(&file2).unwrap();

        let files = db.get_recovered_files(&session.id).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_session_progress_updates() {
        let (db, _temp) = create_test_db();
        let device = create_test_device();
        let session = RecoverySession::new(device, ScanType::Deep, "/output");
        db.save_session(&session).unwrap();

        db.update_session_progress(&session.id, 10, 8, 4096).unwrap();

        let retrieved = db.get_session(&session.id).unwrap().unwrap();
        assert_eq!(retrieved.files_found, 10);
        assert_eq!(retrieved.files_recovered, 8);
        assert_eq!(retrieved.total_size_recovered, 4096);
    }

    #[test]
    fn test_query_sessions_by_device() {
        let (db, _temp) = create_test_db();
        let device = create_test_device();

        let session1 = RecoverySession::new(device.clone(), ScanType::Quick, "/out1");
        let session2 = RecoverySession::new(device.clone(), ScanType::Deep, "/out2");
        db.save_session(&session1).unwrap();
        db.save_session(&session2).unwrap();

        let sessions = db.get_sessions_for_device(&device.id).unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_get_nonexistent_session() {
        let (db, _temp) = create_test_db();
        let result = db.get_session("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_save_device_update() {
        let (db, _temp) = create_test_db();
        let device = create_test_device();
        db.save_device(&device).unwrap();
        db.save_device(&device).unwrap();

        let devices = db.get_all_devices().unwrap();
        assert_eq!(devices.len(), 1);
    }
}
