use std::path::{Path, PathBuf};
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHistoryEntry {
    pub url: String,
    pub title: Option<String>,
    pub visit_time: DateTime<Utc>,
    pub visit_count: u64,
    pub typed_count: u64,
    pub is_hidden: bool,
    pub browser: BrowserType,
    pub transition_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub title: String,
    pub url: String,
    pub folder: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub browser: BrowserType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub expires: Option<DateTime<Utc>>,
    pub is_secure: bool,
    pub is_httponly: bool,
    pub browser: BrowserType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserDownload {
    pub url: String,
    pub target_path: Option<String>,
    pub mime_type: Option<String>,
    pub total_bytes: i64,
    pub received_bytes: i64,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub state: DownloadState,
    pub browser: BrowserType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DownloadState {
    InProgress,
    Completed,
    Cancelled,
    Interrupted,
    Unknown,
}

pub struct BrowserParser;

impl BrowserParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_chrome(&self, profile_path: &Path) -> Result<Vec<BrowserHistoryEntry>> {
        info!("Parsing Chrome history from {:?}", profile_path);
        let db_path = profile_path.join("History");
        if !db_path.exists() {
            warn!("Chrome History file not found at {:?}", db_path);
            return Ok(Vec::new());
        }

        let conn = Connection::open(&db_path)?;
        let mut entries = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT u.url, u.title, v.visit_time, u.visit_count, u.typed_count, \
             u.hidden, v.transition \
             FROM urls u \
             LEFT JOIN visits v ON u.id = v.url \
             ORDER BY v.visit_time"
        )?;

        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let visit_time_raw: i64 = row.get(2)?;
            let visit_count: i64 = row.get(3)?;
            let typed_count: i64 = row.get(4)?;
            let hidden: i64 = row.get(5)?;
            let transition_raw: Option<i64> = row.get(6)?;

            let visit_time = chrome_time_to_datetime(visit_time_raw);
            let transition_type = transition_raw.map(|t| match t {
                0 => "link",
                1 => "typed",
                2 => "auto_bookmark",
                3 => "auto_subframe",
                4 => "manual_subframe",
                5 => "generated",
                6 => "start_page",
                7 => "form_submit",
                8 => "reload",
                9 => "keyword",
                10 => "keyword_generated",
                _ => "unknown",
            }.to_string());

            Ok(BrowserHistoryEntry {
                url,
                title,
                visit_time,
                visit_count: visit_count as u64,
                typed_count: typed_count as u64,
                is_hidden: hidden != 0,
                browser: BrowserType::Chrome,
                transition_type,
            })
        })?;

        for row in rows {
            entries.push(row?);
        }

        info!("Parsed {} Chrome history entries", entries.len());
        Ok(entries)
    }

    pub fn parse_firefox(&self, profile_path: &Path) -> Result<Vec<BrowserHistoryEntry>> {
        info!("Parsing Firefox history from {:?}", profile_path);
        let db_path = profile_path.join("places.sqlite");
        if !db_path.exists() {
            warn!("Firefox places.sqlite not found at {:?}", db_path);
            return Ok(Vec::new());
        }

        let conn = Connection::open(&db_path)?;
        let mut entries = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT p.url, b.title, h.visit_date, p.visit_count, p.typed, p.hidden \
             FROM moz_places p \
             LEFT JOIN moz_historyvisits h ON p.id = h.place_id \
             LEFT JOIN moz_bookmarks b ON b.fk = p.id AND b.type = 1 \
             ORDER BY h.visit_date"
        )?;

        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let visit_date_raw: i64 = row.get(2)?;
            let visit_count: i64 = row.get(3)?;
            let typed: i64 = row.get(4)?;
            let hidden: i64 = row.get(5)?;

            let visit_time = firefox_time_to_datetime(visit_date_raw);

            Ok(BrowserHistoryEntry {
                url,
                title,
                visit_time,
                visit_count: visit_count as u64,
                typed_count: if typed != 0 { 1 } else { 0 },
                is_hidden: hidden != 0,
                browser: BrowserType::Firefox,
                transition_type: None,
            })
        })?;

        for row in rows {
            entries.push(row?);
        }

        info!("Parsed {} Firefox history entries", entries.len());
        Ok(entries)
    }

    pub fn parse_safari(&self, library_path: &Path) -> Result<Vec<BrowserHistoryEntry>> {
        info!("Parsing Safari history from {:?}", library_path);
        let db_path = library_path.join("Safari").join("history.db");
        if !db_path.exists() {
            warn!("Safari history.db not found at {:?}", db_path);
            return Ok(Vec::new());
        }

        let conn = Connection::open(&db_path)?;
        let mut entries = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT hi.url, hi.title, hv.visit_time \
             FROM history_items hi \
             LEFT JOIN history_visits hv ON hi.id = hv.history_item \
             ORDER BY hv.visit_time"
        )?;

        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let title: Option<String> = row.get(1)?;
            let visit_time_raw: f64 = row.get(2)?;

            let visit_time = safari_time_to_datetime(visit_time_raw);

            Ok(BrowserHistoryEntry {
                url,
                title,
                visit_time,
                visit_count: 1,
                typed_count: 0,
                is_hidden: false,
                browser: BrowserType::Safari,
                transition_type: None,
            })
        })?;

        for row in rows {
            entries.push(row?);
        }

        info!("Parsed {} Safari history entries", entries.len());
        Ok(entries)
    }

    pub fn parse_chrome_bookmarks(&self, profile_path: &Path) -> Result<Vec<Bookmark>> {
        info!("Parsing Chrome bookmarks from {:?}", profile_path);
        let bookmarks_path = profile_path.join("Bookmarks");
        if !bookmarks_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&bookmarks_path)?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let mut bookmarks = Vec::new();
        if let Some(roots) = json.get("roots") {
            if let Some(obj) = roots.as_object() {
                for (_key, node) in obj {
                    self.extract_chrome_bookmarks(node, None, &mut bookmarks);
                }
            }
        }

        info!("Parsed {} Chrome bookmarks", bookmarks.len());
        Ok(bookmarks)
    }

    fn extract_chrome_bookmarks(&self, node: &serde_json::Value, folder: Option<&str>, bookmarks: &mut Vec<Bookmark>) {
        if let Some(node_type) = node.get("type").and_then(|v| v.as_str()) {
            if node_type == "url" {
                if let (Some(url), Some(name)) = (
                    node.get("url").and_then(|v| v.as_str()),
                    node.get("name").and_then(|v| v.as_str()),
                ) {
                    let date_added = node.get("date_added")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<i64>().ok())
                        .and_then(|ts| chrome_filetime_to_datetime(ts));

                    bookmarks.push(Bookmark {
                        title: name.to_string(),
                        url: url.to_string(),
                        folder: folder.map(|f| f.to_string()),
                        created: date_added,
                        last_used: None,
                        browser: BrowserType::Chrome,
                    });
                }
            }
        }

        if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            let current_folder = node.get("name").and_then(|v| v.as_str()).or(folder);
            for child in children {
                self.extract_chrome_bookmarks(child, current_folder, bookmarks);
            }
        }
    }

    pub fn parse_chrome_cookies(&self, profile_path: &Path) -> Result<Vec<Cookie>> {
        info!("Parsing Chrome cookies from {:?}", profile_path);
        let db_path = profile_path.join("Cookies");
        if !db_path.exists() {
            return Ok(Vec::new());
        }

        let conn = Connection::open(&db_path)?;
        let mut cookies = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT name, value, host_key, path, expires_utc, is_secure, is_httponly \
             FROM cookies"
        )?;

        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let value: String = row.get(1)?;
            let domain: String = row.get(2)?;
            let path: String = row.get(3)?;
            let expires_raw: i64 = row.get(4)?;
            let is_secure: bool = row.get::<_, i64>(5)? != 0;
            let is_httponly: bool = row.get::<_, i64>(6)? != 0;

            Ok(Cookie {
                name,
                value,
                domain,
                path,
                expires: if expires_raw > 0 { Some(chrome_time_to_datetime(expires_raw)) } else { None },
                is_secure,
                is_httponly,
                browser: BrowserType::Chrome,
            })
        })?;

        for row in rows {
            cookies.push(row?);
        }

        info!("Parsed {} Chrome cookies", cookies.len());
        Ok(cookies)
    }

    pub fn parse_chrome_downloads(&self, profile_path: &Path) -> Result<Vec<BrowserDownload>> {
        info!("Parsing Chrome downloads from {:?}", profile_path);
        let db_path = profile_path.join("History");
        if !db_path.exists() {
            return Ok(Vec::new());
        }

        let conn = Connection::open(&db_path)?;
        let mut downloads = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='downloads'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            return Ok(downloads);
        }

        let mut stmt = conn.prepare(
            "SELECT tab_url, target_path, mime_type, total_bytes, received_bytes, \
             start_time, end_time, state FROM downloads"
        )?;

        let rows = stmt.query_map([], |row| {
            let url: Option<String> = row.get(0)?;
            let target: Option<String> = row.get(1)?;
            let mime: Option<String> = row.get(2)?;
            let total: i64 = row.get(3)?;
            let received: i64 = row.get(4)?;
            let start_raw: i64 = row.get(5)?;
            let end_raw: Option<i64> = row.get(6)?;
            let state_raw: i64 = row.get(7)?;

            let start_time = chrome_time_to_datetime(start_raw);
            let end_time = end_raw.map(chrome_time_to_datetime);

            let state = match state_raw {
                0 => DownloadState::InProgress,
                1 => DownloadState::Completed,
                2 => DownloadState::Cancelled,
                3 => DownloadState::Interrupted,
                _ => DownloadState::Unknown,
            };

            Ok(BrowserDownload {
                url: url.unwrap_or_default(),
                target_path: target,
                mime_type: mime,
                total_bytes: total,
                received_bytes: received,
                start_time,
                end_time,
                state,
                browser: BrowserType::Chrome,
            })
        })?;

        for row in rows {
            downloads.push(row?);
        }

        info!("Parsed {} Chrome downloads", downloads.len());
        Ok(downloads)
    }

    pub fn fingerprint_profile(&self, profile_path: &Path) -> Result<String> {
        let mut hasher = Sha256::new();
        if let Ok(entries) = std::fs::read_dir(profile_path) {
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for file in files {
                if file.is_file() {
                    if let Ok(meta) = std::fs::metadata(&file) {
                        hasher.update(file.file_name().unwrap_or_default().to_string_lossy().as_bytes());
                        hasher.update(meta.len().to_le_bytes());
                    }
                }
            }
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}

impl Default for BrowserParser {
    fn default() -> Self {
        Self::new()
    }
}

fn chrome_time_to_datetime(chrome_time: i64) -> DateTime<Utc> {
    let chrome_epoch_offset = 11644473600_i64;
    let seconds_since_unix = (chrome_time / 1_000_000) - chrome_epoch_offset;
    let microseconds = (chrome_time % 1_000_000) as u32;
    DateTime::from_timestamp(seconds_since_unix, microseconds * 1000).unwrap_or_default()
}

fn chrome_filetime_to_datetime(filetime: i64) -> Option<DateTime<Utc>> {
    if filetime <= 0 {
        return None;
    }
    let chrome_epoch_offset = 11644473600_i64;
    let seconds_since_unix = (filetime / 1_000_000) - chrome_epoch_offset;
    DateTime::from_timestamp(seconds_since_unix, 0)
}

fn firefox_time_to_datetime(firefox_time: i64) -> DateTime<Utc> {
    if firefox_time == 0 {
        return DateTime::UNIX_EPOCH;
    }
    let seconds = firefox_time / 1_000_000;
    let micros = (firefox_time % 1_000_000) as u32;
    DateTime::from_timestamp(seconds, micros * 1000).unwrap_or_default()
}

fn safari_time_to_datetime(core_data_ts: f64) -> DateTime<Utc> {
    let core_data_epoch = 978307200.0_f64;
    let unix_ts = core_data_ts + core_data_epoch;
    DateTime::from_timestamp(unix_ts as i64, 0).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    fn create_test_chrome_profile() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let profile_path = dir.path().to_path_buf();
        let db_path = dir.path().join("History");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, typed_count INTEGER, hidden INTEGER, \
             last_visit_time INTEGER);
             CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, \
             transition INTEGER);
             CREATE TABLE visit_source (visit_id INTEGER, transition INTEGER);
             CREATE TABLE downloads (id INTEGER PRIMARY KEY, tab_url TEXT, target_path TEXT, \
             mime_type TEXT, total_bytes INTEGER, received_bytes INTEGER, \
             start_time INTEGER, end_time INTEGER, state INTEGER);"
        ).unwrap();

        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 5, 2, 0, 13350000000000000)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO visits VALUES (1, 1, 13350000000000000, 1)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO downloads VALUES (1, 'https://example.com/file.zip', '/tmp/file.zip', \
             'application/zip', 1000000, 1000000, 13350000000000000, 13350000001000000, 1)",
            [],
         ).unwrap();

        (dir, profile_path)
    }

    fn create_test_firefox_profile() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let profile_path = dir.path().to_path_buf();
        let db_path = dir.path().join("places.sqlite");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, typed INTEGER, hidden INTEGER, \
             last_visit_date INTEGER, frecency INTEGER);
             CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, \
             visit_date INTEGER, visit_type INTEGER, from_visit INTEGER, session INTEGER);
             CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, fk INTEGER, type INTEGER, \
             parent INTEGER, title TEXT, position INTEGER);"
        ).unwrap();

        conn.execute(
            "INSERT INTO moz_places VALUES (1, 'https://mozilla.org', 'Mozilla', 3, 1, 0, 1700000000000000, 100)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO moz_historyvisits VALUES (1, 1, 1700000000000000, 1, 0, 1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO moz_bookmarks VALUES (1, 1, 1, 0, 'Mozilla Bookmark', 0)",
            [],
        ).unwrap();

        (dir, profile_path)
    }

    #[test]
    fn test_parse_chrome_history() {
        let (dir, profile_path) = create_test_chrome_profile();
        let parser = BrowserParser::new();
        let entries = parser.parse_chrome(&profile_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://example.com");
        assert_eq!(entries[0].title, Some("Example".to_string()));
        assert_eq!(entries[0].visit_count, 5);
        assert_eq!(entries[0].typed_count, 2);
        assert_eq!(entries[0].transition_type, Some("typed".to_string()));
        assert_eq!(entries[0].browser, BrowserType::Chrome);
        drop(dir);
    }

    #[test]
    fn test_parse_firefox_history() {
        let (dir, profile_path) = create_test_firefox_profile();
        let parser = BrowserParser::new();
        let entries = parser.parse_firefox(&profile_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "https://mozilla.org");
        assert_eq!(entries[0].browser, BrowserType::Firefox);
        assert_eq!(entries[0].typed_count, 1);
        drop(dir);
    }

    #[test]
    fn test_parse_chrome_downloads() {
        let (dir, profile_path) = create_test_chrome_profile();
        let parser = BrowserParser::new();
        let downloads = parser.parse_chrome_downloads(&profile_path).unwrap();
        assert_eq!(downloads.len(), 1);
        assert_eq!(downloads[0].url, "https://example.com/file.zip");
        assert_eq!(downloads[0].total_bytes, 1000000);
        assert_eq!(downloads[0].state, DownloadState::Completed);
        drop(dir);
    }

    #[test]
    fn test_parse_chrome_bookmarks() {
        let dir = TempDir::new().unwrap();
        let bookmarks = r#"{
            "roots": {
                "bookmark_bar": {
                    "name": "Bookmarks bar",
                    "type": "folder",
                    "children": [
                        {"name": "Example", "type": "url", "url": "https://example.com", "date_added": "13350000000000000"},
                        {"name": "Mozilla", "type": "url", "url": "https://mozilla.org", "date_added": "13350000001000000"}
                    ]
                }
            }
        }"#;
        std::fs::write(dir.path().join("Bookmarks"), bookmarks).unwrap();

        let parser = BrowserParser::new();
        let result = parser.parse_chrome_bookmarks(dir.path()).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].title, "Example");
        assert_eq!(result[0].url, "https://example.com");
        assert_eq!(result[0].folder, Some("Bookmarks bar".to_string()));
        drop(dir);
    }

    #[test]
    fn test_chrome_time_conversion() {
        let dt = chrome_time_to_datetime(13350000000000000);
        assert!(dt.timestamp() > 1_700_000_000);
    }

    #[test]
    fn test_firefox_time_conversion() {
        let dt = firefox_time_to_datetime(1700000000000000);
        assert!(dt.timestamp() >= 1_700_000_000);
    }

    #[test]
    fn test_safari_time_conversion() {
        let dt = safari_time_to_datetime(700000000.0);
        assert!(dt.timestamp() > 1_600_000_000);
    }

    #[test]
    fn test_default() {
        let _parser = BrowserParser::default();
    }

    #[test]
    fn test_missing_profile() {
        let dir = TempDir::new().unwrap();
        let parser = BrowserParser::new();
        let entries = parser.parse_chrome(dir.path()).unwrap();
        assert!(entries.is_empty());
        drop(dir);
    }

    #[test]
    fn test_fingerprint_profile() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("History"), b"test").unwrap();
        std::fs::write(dir.path().join("Bookmarks"), b"test2").unwrap();

        let parser = BrowserParser::new();
        let fp = parser.fingerprint_profile(dir.path()).unwrap();
        assert_eq!(fp.len(), 64);
        drop(dir);
    }

    #[test]
    fn test_entry_serialization() {
        let entry = BrowserHistoryEntry {
            url: "https://example.com".to_string(),
            title: Some("Example".to_string()),
            visit_time: Utc::now(),
            visit_count: 5,
            typed_count: 2,
            is_hidden: false,
            browser: BrowserType::Chrome,
            transition_type: Some("typed".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: BrowserHistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.url, entry.url);
        assert_eq!(deserialized.browser, BrowserType::Chrome);
    }
}
