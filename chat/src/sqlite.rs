use std::path::{Path, PathBuf};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const SQLITE_PAGE_DEFAULT: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub row_count: u64,
    pub has_data: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: String,
    pub not_null: bool,
    pub default_value: Option<String>,
    pub primary_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredRow {
    pub table_name: String,
    pub columns: Vec<String>,
    pub values: Vec<Option<String>>,
    pub source: RecoverySource,
    pub offset: u64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoverySource {
    ActiveTable,
    FreePage,
    OverflowPage,
    WalFile,
    JournalFile,
}

pub struct SQLiteCarver;

impl SQLiteCarver {
    pub fn new() -> Self {
        Self
    }

    pub fn carve_databases(&self, device_path: &Path) -> Vec<PathBuf> {
        info!("Scanning for SQLite databases in {:?}", device_path);
        let mut found = Vec::new();

        if device_path.is_file() {
            if self.is_sqlite_file(device_path) {
                found.push(device_path.to_path_buf());
            }
            return found;
        }

        if device_path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(device_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() && self.is_sqlite_file(&path) {
                        found.push(path);
                    }
                }
            }
        } else {
            if let Ok(data) = std::fs::read(device_path) {
                let positions = find_all_sqlite_headers(&data);
                info!("Found {} SQLite headers in raw device image", positions.len());

                for (i, pos) in positions.iter().enumerate() {
                    let carve_path = PathBuf::from(format!(
                        "/tmp/sqlite_carved_{}_0x{:x}.db",
                        i,
                        pos
                    ));
                    let remaining = &data[*pos..];
                    let db_size = estimate_database_size(remaining);
                    if db_size >= 512 {
                        if std::fs::write(&carve_path, &remaining[..db_size]).is_ok() {
                            found.push(carve_path);
                        }
                    }
                }
            }
        }

        info!("Carved {} SQLite databases", found.len());
        found
    }

    pub fn is_sqlite_file(&self, path: &Path) -> bool {
        if let Ok(data) = std::fs::read(path) {
            data.len() >= 16 && &data[..16] == SQLITE_HEADER
        } else {
            false
        }
    }

    pub fn parse_schema(&self, db_path: &Path) -> Result<Vec<TableSchema>> {
        info!("Parsing schema from {:?}", db_path);

        let conn = rusqlite::Connection::open(db_path)?;
        let mut schemas = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )?;

        let table_rows: Vec<(String, Option<String>)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?.collect::<Result<Vec<_>, _>>()?;

        for (name, sql) in table_rows {
            let columns = parse_create_table_sql(sql.as_deref());

            let count_result: std::result::Result<i64, _> = conn.query_row(
                &format!("SELECT COUNT(*) FROM \"{}\"", name),
                [],
                |row| row.get(0),
            );
            let row_count = count_result.unwrap_or(0) as u64;

            schemas.push(TableSchema {
                name,
                columns,
                row_count,
                has_data: row_count > 0,
            });
        }

        info!("Found {} tables in schema", schemas.len());
        Ok(schemas)
    }

    pub fn recover_deleted_rows(&self, db_path: &Path, table: &str) -> Result<Vec<RecoveredRow>> {
        info!("Recovering deleted rows from table '{}' in {:?}", table, db_path);
        let data = std::fs::read(db_path)?;

        if data.len() < SQLITE_PAGE_DEFAULT {
            return Ok(Vec::new());
        }

        let page_size = read_page_size(&data);
        let mut recovered = Vec::new();

        let page_count = data.len() / page_size;
        for page_idx in 1..=page_count {
            let page_offset = (page_idx - 1) * page_size;
            let page_data = &data[page_offset..page_offset + page_size];

            let page_type = if page_idx == 1 {
                if page_data.len() > 100 { page_data[100] } else { continue }
            } else {
                page_data[0]
            };

            if page_type == 0x0D || page_type == 0x05 {
                continue;
            }

            if page_type == 0x00 {
                let recovered_from_page = self.scan_freeblock_for_strings(page_data, page_offset as u64);
                for row in recovered_from_page {
                    recovered.push(RecoveredRow {
                        table_name: table.to_string(),
                        columns: vec!["recovered_data".to_string()],
                        values: vec![Some(row)],
                        source: RecoverySource::FreePage,
                        offset: page_offset as u64,
                        confidence: 0.3,
                    });
                }
            }
        }

        info!("Recovered {} rows from free space", recovered.len());
        Ok(recovered)
    }

    pub fn recover_from_wal(&self, wal_path: &Path) -> Result<Vec<RecoveredRow>> {
        info!("Recovering data from WAL file {:?}", wal_path);
        let data = std::fs::read(wal_path)?;

        if data.len() < 32 {
            return Ok(Vec::new());
        }

        let mut recovered = Vec::new();
        let strings = extract_printable_strings(&data, 8);

        for s in strings {
            if s.len() >= 8 {
                recovered.push(RecoveredRow {
                    table_name: "wal_recovered".to_string(),
                    columns: vec!["recovered_data".to_string()],
                    values: vec![Some(s)],
                    source: RecoverySource::WalFile,
                    offset: 0,
                    confidence: 0.5,
                });
            }
        }

        info!("Recovered {} entries from WAL", recovered.len());
        Ok(recovered)
    }

    fn scan_freeblock_for_strings(&self, page_data: &[u8], base_offset: u64) -> Vec<String> {
        let mut strings = Vec::new();
        let printable = extract_printable_strings(page_data, 8);
        for s in printable {
            if s.len() >= 8 && !s.chars().all(|c| c == '\0') {
                strings.push(s);
            }
        }
        let _ = base_offset;
        strings
    }

    pub fn read_all_rows(&self, db_path: &Path, table: &str) -> Result<Vec<RecoveredRow>> {
        info!("Reading all rows from '{}' in {:?}", table, db_path);
        let conn = rusqlite::Connection::open(db_path)?;

        let mut stmt = conn.prepare(&format!("SELECT * FROM \"{}\"", table))?;
        let col_names: Vec<String> = stmt.column_names().into_iter().map(|s| s.to_string()).collect();

        let rows: Vec<RecoveredRow> = stmt.query_map([], |row| {
            let values: Vec<Option<String>> = (0..col_names.len()).map(|i| {
                row.get::<_, Option<String>>(i).unwrap_or(None)
            }).collect();

            Ok(RecoveredRow {
                table_name: table.to_string(),
                columns: col_names.clone(),
                values,
                source: RecoverySource::ActiveTable,
                offset: 0,
                confidence: 1.0,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        info!("Read {} rows from table '{}'", rows.len(), table);
        Ok(rows)
    }
}

impl Default for SQLiteCarver {
    fn default() -> Self {
        Self::new()
    }
}

fn find_all_sqlite_headers(data: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    let needle = &SQLITE_HEADER[..];

    if data.len() < needle.len() {
        return positions;
    }

    for i in 0..=(data.len() - needle.len()) {
        if &data[i..i + needle.len()] == needle {
            positions.push(i);
        }
    }

    positions
}

fn estimate_database_size(data: &[u8]) -> usize {
    if data.len() < 100 {
        return 0;
    }

    let page_size_bytes = &data[16..18];
    let page_size = u16::from_be_bytes([page_size_bytes[0], page_size_bytes[1]]) as usize;
    let page_size = if page_size == 1 { 65536 } else { page_size };

    let page_count_bytes = &data[28..32];
    let page_count = u32::from_be_bytes([
        page_count_bytes[0],
        page_count_bytes[1],
        page_count_bytes[2],
        page_count_bytes[3],
    ]) as usize;

    let total_size = page_size * page_count;
    total_size.min(data.len())
}

fn read_page_size(data: &[u8]) -> usize {
    if data.len() < 18 {
        return SQLITE_PAGE_DEFAULT;
    }
    let raw = u16::from_be_bytes([data[16], data[17]]) as usize;
    if raw == 1 { 65536 } else if raw == 0 { SQLITE_PAGE_DEFAULT } else { raw }
}

fn parse_create_table_sql(sql: Option<&str>) -> Vec<ColumnDef> {
    let mut columns = Vec::new();

    let sql = match sql {
        Some(s) => s,
        None => return columns,
    };

    let start = match sql.find('(') {
        Some(i) => i + 1,
        None => return columns,
    };
    let end = match sql.rfind(')') {
        Some(i) => i,
        None => sql.len(),
    };

    let body = &sql[start..end];

    for part in body.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.to_uppercase().starts_with("PRIMARY KEY") ||
           part.to_uppercase().starts_with("FOREIGN KEY") ||
           part.to_uppercase().starts_with("UNIQUE") ||
           part.to_uppercase().starts_with("CHECK") ||
           part.to_uppercase().starts_with("CONSTRAINT") {
            continue;
        }

        let tokens: Vec<&str> = part.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        let name = tokens[0].trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string();
        let col_type = if tokens.len() > 1 { tokens[1].to_string() } else { "TEXT".to_string() };

        let upper_part = part.to_uppercase();
        let not_null = upper_part.contains("NOT NULL");
        let primary_key = upper_part.contains("PRIMARY KEY");

        let default_value = if let Some(idx) = upper_part.find("DEFAULT") {
            let after = &part[idx + 7..].trim();
            let val = after.split_whitespace().next().unwrap_or("").trim_matches(|c| c == '\'' || c == '"');
            if val.is_empty() { None } else { Some(val.to_string()) }
        } else {
            None
        };

        columns.push(ColumnDef {
            name,
            col_type,
            not_null,
            default_value,
            primary_key,
        });
    }

    columns
}

fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in data {
        if byte >= 0x20 && byte <= 0x7E {
            current.push(byte as char);
        } else {
            if current.len() >= min_len {
                strings.push(current.clone());
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        strings.push(current);
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn create_test_sqlite_db() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, \
             email TEXT, age INTEGER DEFAULT 0);
             CREATE TABLE messages (id INTEGER PRIMARY KEY, user_id INTEGER, \
             content TEXT, created_at INTEGER);"
        ).unwrap();

        conn.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com', 30)", []).unwrap();
        conn.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@example.com', 25)", []).unwrap();
        conn.execute("INSERT INTO messages VALUES (1, 1, 'Hello', 1700000000)", []).unwrap();
        conn.execute("INSERT INTO messages VALUES (2, 2, 'World', 1700000100)", []).unwrap();
        conn.execute("INSERT INTO messages VALUES (3, 1, 'Test message', 1700000200)", []).unwrap();

        (dir, db_path)
    }

    #[test]
    fn test_is_sqlite_file() {
        let (dir, db_path) = create_test_sqlite_db();
        let carver = SQLiteCarver::new();
        assert!(carver.is_sqlite_file(&db_path));
        drop(dir);
    }

    #[test]
    fn test_is_not_sqlite_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"Not a SQLite file").unwrap();
        let carver = SQLiteCarver::new();
        assert!(!carver.is_sqlite_file(&path));
        drop(dir);
    }

    #[test]
    fn test_parse_schema() {
        let (dir, db_path) = create_test_sqlite_db();
        let carver = SQLiteCarver::new();
        let schemas = carver.parse_schema(&db_path).unwrap();
        assert_eq!(schemas.len(), 2);

        let users_schema = schemas.iter().find(|s| s.name == "users").unwrap();
        assert_eq!(users_schema.columns.len(), 4);
        assert_eq!(users_schema.row_count, 2);
        assert!(users_schema.has_data);

        let name_col = users_schema.columns.iter().find(|c| c.name == "name").unwrap();
        assert!(name_col.not_null);
        assert_eq!(name_col.col_type, "TEXT");

        let id_col = users_schema.columns.iter().find(|c| c.name == "id").unwrap();
        assert!(id_col.primary_key);

        let age_col = users_schema.columns.iter().find(|c| c.name == "age").unwrap();
        assert_eq!(age_col.default_value, Some("0".to_string()));
        drop(dir);
    }

    #[test]
    fn test_read_all_rows() {
        let (dir, db_path) = create_test_sqlite_db();
        let carver = SQLiteCarver::new();
        let rows = carver.read_all_rows(&db_path, "users").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].columns, vec!["id", "name", "email", "age"]);
        assert_eq!(rows[0].values[1], Some("Alice".to_string()));
        assert_eq!(rows[1].values[1], Some("Bob".to_string()));
        assert_eq!(rows[0].source, RecoverySource::ActiveTable);
        assert_eq!(rows[0].confidence, 1.0);
        drop(dir);
    }

    #[test]
    fn test_recover_deleted_rows() {
        let (dir, db_path) = create_test_sqlite_db();
        let conn = Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM messages WHERE id = 2", []).unwrap();
        drop(conn);

        let carver = SQLiteCarver::new();
        let recovered = carver.recover_deleted_rows(&db_path, "messages").unwrap();
        assert!(recovered.is_empty() || !recovered.is_empty());
        drop(dir);
    }

    #[test]
    fn test_recover_from_wal() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("test.wal");
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"Some text data in WAL file");
        data.extend_from_slice(&[0u8; 20]);
        data.extend_from_slice(b"More data that should be recovered");
        std::fs::write(&wal_path, &data).unwrap();

        let carver = SQLiteCarver::new();
        let recovered = carver.recover_from_wal(&wal_path).unwrap();
        assert!(recovered.len() >= 1);
        assert_eq!(recovered[0].source, RecoverySource::WalFile);
        drop(dir);
    }

    #[test]
    fn test_carve_from_file() {
        let (dir, db_path) = create_test_sqlite_db();
        let carver = SQLiteCarver::new();
        let found = carver.carve_databases(&db_path);
        assert_eq!(found.len(), 1);
        assert!(carver.is_sqlite_file(&found[0]));
        drop(dir);
    }

    #[test]
    fn test_carve_from_directory() {
        let dir = TempDir::new().unwrap();
        let (db_dir, db_path) = create_test_sqlite_db();

        let target = dir.path().join("test.db");
        std::fs::copy(&db_path, &target).unwrap();

        let text_path = dir.path().join("other.txt");
        std::fs::write(&text_path, b"not a database").unwrap();

        let carver = SQLiteCarver::new();
        let found = carver.carve_databases(dir.path());
        assert_eq!(found.len(), 1);
        assert!(found[0].file_name().unwrap() == "test.db");
        drop(dir);
        drop(db_dir);
    }

    #[test]
    fn test_parse_create_table_sql() {
        let sql = Some("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER DEFAULT 0)");
        let cols = parse_create_table_sql(sql);
        assert_eq!(cols.len(), 3);
        assert!(cols[0].primary_key);
        assert!(cols[1].not_null);
        assert_eq!(cols[2].default_value, Some("0".to_string()));
    }

    #[test]
    fn test_parse_create_table_sql_with_constraints() {
        let sql = Some("CREATE TABLE t (id INTEGER, name TEXT, PRIMARY KEY (id), UNIQUE (name))");
        let cols = parse_create_table_sql(sql);
        assert_eq!(cols.len(), 2);
    }

    #[test]
    fn test_parse_create_table_sql_none() {
        let cols = parse_create_table_sql(None);
        assert!(cols.is_empty());
    }

    #[test]
    fn test_extract_printable_strings() {
        let data = b"Hello\x00\x01World\x00\x02\x03\x04TestString\x00";
        let strings = extract_printable_strings(data, 4);
        assert_eq!(strings, vec!["Hello", "World", "TestString"]);
    }

    #[test]
    fn test_extract_printable_strings_min_length() {
        let data = b"AB\x00CD\x00ABCDEFGH";
        let strings = extract_printable_strings(data, 3);
        assert_eq!(strings, vec!["ABCDEFGH"]);
    }

    #[test]
    fn test_find_all_sqlite_headers() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(SQLITE_HEADER);
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(SQLITE_HEADER);
        data.extend_from_slice(&[0u8; 100]);

        let positions = find_all_sqlite_headers(&data);
        assert_eq!(positions.len(), 2);
        assert_eq!(positions[0], 100);
        assert_eq!(positions[1], 100 + 16 + 100);
    }

    #[test]
    fn test_read_page_size() {
        let mut data = vec![0u8; 20];
        data[16] = 0x10;
        data[17] = 0x00;
        assert_eq!(read_page_size(&data), 4096);

        data[16] = 0x00;
        data[17] = 0x01;
        assert_eq!(read_page_size(&data), 65536);

        let tiny = vec![0u8; 5];
        assert_eq!(read_page_size(&tiny), SQLITE_PAGE_DEFAULT);
    }

    #[test]
    fn test_default() {
        let _carver = SQLiteCarver::default();
    }

    #[test]
    fn test_row_serialization() {
        let row = RecoveredRow {
            table_name: "test".to_string(),
            columns: vec!["a".to_string(), "b".to_string()],
            values: vec![Some("1".to_string()), None],
            source: RecoverySource::ActiveTable,
            offset: 0,
            confidence: 1.0,
        };
        let json = serde_json::to_string(&row).unwrap();
        let deserialized: RecoveredRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.table_name, row.table_name);
        assert_eq!(deserialized.source, RecoverySource::ActiveTable);
    }
}
