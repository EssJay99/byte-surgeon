use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub sender: String,
    pub content: String,
    pub timestamp: String,
    pub media_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub url: String,
    pub title: String,
    pub timestamp: String,
    pub visit_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub date: String,
    pub has_attachments: bool,
}

pub struct WhatsAppRecoverer;

impl WhatsAppRecoverer {
    pub fn new() -> Self {
        Self
    }

    pub fn recover(&self, db_path: &str) -> Result<Vec<ChatMessage>, String> {
        info!("Recovering WhatsApp messages from {}", db_path);

        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| format!("Failed to open WhatsApp database: {}", e))?;

        let messages;

        let table_check: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='message'")
            .map_err(|e| format!("Query error: {}", e))?
            .exists([])
            .map_err(|e| format!("Check error: {}", e))?;

        if !table_check {
            return Err("No message table found in WhatsApp database".to_string());
        }

        let query = r#"
            SELECT
                COALESCE(jid.raw_string, m.key_remote_jid, 'unknown') AS sender,
                COALESCE(m.data, m.text_data, '') AS content,
                m.timestamp,
                COALESCE(m.media_wa_type, 0) AS media_type
            FROM message m
            LEFT JOIN jid ON m.sender_jid_row_id = jid._id
            ORDER BY m.timestamp ASC
        "#;

        let fallback_query = r#"
            SELECT
                COALESCE(m.key_remote_jid, 'unknown') AS sender,
                COALESCE(m.data, '') AS content,
                m.timestamp,
                COALESCE(m.media_wa_type, 0) AS media_type
            FROM message m
            ORDER BY m.timestamp ASC
        "#;

        let result = self.query_messages(&conn, query);
        let messages_from_query = match result {
            Ok(msgs) if !msgs.is_empty() => msgs,
            _ => {
                debug!("Primary query failed or empty, trying fallback query");
                self.query_messages(&conn, fallback_query).unwrap_or_default()
            }
        };

        messages = messages_from_query;

        info!("Recovered {} WhatsApp messages", messages.len());
        Ok(messages)
    }

    fn query_messages(&self, conn: &rusqlite::Connection, query: &str) -> Result<Vec<ChatMessage>, String> {
        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let sender: String = row.get(0)?;
                let content: String = row.get(1)?;
                let timestamp: i64 = row.get(2)?;
                let media_type: i32 = row.get(3)?;

                let dt = chrono::DateTime::from_timestamp(timestamp / 1000, 0)
                    .unwrap_or_else(|| chrono::Utc::now());

                Ok(ChatMessage {
                    sender,
                    content,
                    timestamp: dt.to_rfc3339(),
                    media_count: if media_type > 0 { 1 } else { 0 },
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut messages = Vec::new();
        for row in rows {
            match row {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    warn!("Skipping row due to error: {}", e);
                }
            }
        }
        Ok(messages)
    }
}

pub struct IMessageRecoverer;

impl IMessageRecoverer {
    pub fn new() -> Self {
        Self
    }

    pub fn recover(&self, db_path: &str) -> Result<Vec<ChatMessage>, String> {
        info!("Recovering iMessage data from {}", db_path);

        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| format!("Failed to open iMessage database: {}", e))?;

        let table_check: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='message'")
            .map_err(|e| format!("Query error: {}", e))?
            .exists([])
            .map_err(|e| format!("Check error: {}", e))?;

        if !table_check {
            return Err("No message table found in iMessage database".to_string());
        }

        let query = r#"
            SELECT
                COALESCE(h.id, 'unknown') AS sender,
                COALESCE(m.text, '') AS content,
                m.date,
                m.is_from_me,
                (SELECT COUNT(*) FROM message_attachment_join maj
                 WHERE maj.message_id = m.ROWID) AS attachment_count
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            ORDER BY m.date ASC
        "#;

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("Failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let sender_raw: String = row.get(0)?;
                let content: String = row.get(1)?;
                let date_raw: i64 = row.get(2)?;
                let is_from_me: i32 = row.get(3)?;
                let attachment_count: i32 = row.get(4)?;

                let sender = if is_from_me != 0 {
                    "me".to_string()
                } else {
                    sender_raw
                };

                let dt = Self::parse_imessage_date(date_raw);

                Ok(ChatMessage {
                    sender,
                    content,
                    timestamp: dt,
                    media_count: attachment_count as u32,
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut messages = Vec::new();
        for row in rows {
            match row {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    warn!("Skipping iMessage row: {}", e);
                }
            }
        }

        info!("Recovered {} iMessage messages", messages.len());
        Ok(messages)
    }

    fn parse_imessage_date(date_raw: i64) -> String {
        let epoch_offset: i64 = 978_307_200;

        let normalized = if date_raw > 1_000_000_000_000_000_000 {
            date_raw / 1_000_000_000
        } else if date_raw > 1_000_000_000_000 {
            date_raw / 1_000_000
        } else {
            date_raw
        };

        let unix_ts = normalized + epoch_offset;

        chrono::DateTime::from_timestamp(unix_ts, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

pub struct SignalRecoverer;

impl SignalRecoverer {
    pub fn new() -> Self {
        Self
    }

    pub fn recover(&self, db_path: &str) -> Result<Vec<ChatMessage>, String> {
        info!("Recovering Signal messages from {}", db_path);

        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| format!("Failed to open Signal database: {}", e))?;

        let tables = Self::list_tables(&conn)?;

        let messages = if tables.contains(&"message".to_string()) {
            self.recover_from_message_table(&conn)?
        } else if tables.contains(&"sms".to_string()) {
            self.recover_from_sms_table(&conn)?
        } else {
            return Err(format!(
                "No recognized message table found. Available tables: {:?}",
                tables
            ));
        };

        info!("Recovered {} Signal messages", messages.len());
        Ok(messages)
    }

    fn list_tables(conn: &rusqlite::Connection) -> Result<Vec<String>, String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .map_err(|e| format!("Failed to list tables: {}", e))?;

        let tables: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| format!("Query error: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(tables)
    }

    fn recover_from_message_table(&self, conn: &rusqlite::Connection) -> Result<Vec<ChatMessage>, String> {
        let columns = Self::list_columns(conn, "message")?;
        debug!("Signal message table columns: {:?}", columns);

        let has_body = columns.iter().any(|c| c == "body");
        let has_thread = columns.iter().any(|c| c == "thread_id");
        let has_recipient = columns.iter().any(|c| c == "recipient_id" || c == "address");

        let body_col = if has_body { "body" } else { "''" };

        let query = if has_recipient && has_thread {
            format!(
                "SELECT COALESCE(m.{}, '') AS sender, COALESCE(m.{}, '') AS content, m.date, m.date_received FROM message m ORDER BY m.date ASC",
                if columns.contains(&"recipient_id".to_string()) { "recipient_id" } else { "address" },
                body_col
            )
        } else {
            format!(
                "SELECT 'unknown' AS sender, COALESCE(m.{}, '') AS content, m.date, COALESCE(m.date_received, m.date) FROM message m ORDER BY m.date ASC",
                body_col
            )
        };

        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| format!("Failed to prepare Signal query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let sender: String = row.get(0)?;
                let content: String = row.get(1)?;
                let date: i64 = row.get(2)?;
                let _date_received: i64 = row.get(3)?;

                let dt = chrono::DateTime::from_timestamp(date / 1000, 0)
                    .unwrap_or_else(|| chrono::Utc::now());

                Ok(ChatMessage {
                    sender,
                    content,
                    timestamp: dt.to_rfc3339(),
                    media_count: 0,
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut messages = Vec::new();
        for row in rows {
            match row {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    warn!("Skipping Signal row: {}", e);
                }
            }
        }
        Ok(messages)
    }

    fn recover_from_sms_table(&self, conn: &rusqlite::Connection) -> Result<Vec<ChatMessage>, String> {
        let query = r#"
            SELECT COALESCE(address, 'unknown'), COALESCE(body, ''), date, type FROM sms ORDER BY date ASC
        "#;

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("Failed to prepare SMS query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let address: String = row.get(0)?;
                let body: String = row.get(1)?;
                let date: i64 = row.get(2)?;
                let msg_type: i32 = row.get(3)?;

                let dt = chrono::DateTime::from_timestamp(date / 1000, 0)
                    .unwrap_or_else(|| chrono::Utc::now());

                let sender = if msg_type == 2 { "me".to_string() } else { address };

                Ok(ChatMessage {
                    sender,
                    content: body,
                    timestamp: dt.to_rfc3339(),
                    media_count: 0,
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut messages = Vec::new();
        for row in rows {
            match row {
                Ok(msg) => messages.push(msg),
                Err(e) => {
                    warn!("Skipping SMS row: {}", e);
                }
            }
        }
        Ok(messages)
    }

    fn list_columns(conn: &rusqlite::Connection, table: &str) -> Result<Vec<String>, String> {
        let query = format!("PRAGMA table_info({})", table);
        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| format!("Failed to get column info: {}", e))?;

        let columns: Vec<String> = stmt
            .query_map([], |row| {
                let name: String = row.get(1)?;
                Ok(name)
            })
            .map_err(|e| format!("Query error: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(columns)
    }
}

pub struct SlackParser;

impl SlackParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse(&self, export_dir: &str) -> Result<Vec<ChatMessage>, String> {
        info!("Parsing Slack export from {}", export_dir);

        let export_path = Path::new(export_dir);
        if !export_path.exists() {
            return Err(format!("Export directory does not exist: {}", export_dir));
        }

        let users = self.load_users(export_path)?;
        let channels = self.load_channels(export_path)?;

        let mut messages = Vec::new();

        for channel in &channels {
            let channel_dir = export_path.join(&channel.id);
            let channel_path = if channel_dir.exists() {
                channel_dir
            } else {
                export_path.join(&channel.name)
            };

            if !channel_path.exists() {
                debug!("No directory found for channel {}", channel.name);
                continue;
            }

            let json_files = Self::find_json_files(&channel_path)?;

            for json_file in json_files {
                let file_messages = self.parse_channel_file(&json_file, &channel.name, &users)?;
                messages.extend(file_messages);
            }
        }

        let root_json_files = Self::find_json_files(export_path)?;
        for json_file in root_json_files {
            let file_messages = self.parse_channel_file(&json_file, "general", &users)?;
            messages.extend(file_messages);
        }

        messages.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        info!("Recovered {} Slack messages", messages.len());
        Ok(messages)
    }

    fn load_users(&self, export_path: &Path) -> Result<std::collections::HashMap<String, String>, String> {
        let users_path = export_path.join("users.json");
        let mut users = std::collections::HashMap::new();

        if users_path.exists() {
            let content = std::fs::read_to_string(&users_path)
                .map_err(|e| format!("Failed to read users.json: {}", e))?;

            let user_entries: Vec<SlackUser> = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse users.json: {}", e))?;

            for user in user_entries {
                let display_name = user
                    .profile
                    .as_ref()
                    .and_then(|p| p.display_name.clone())
                    .or_else(|| user.real_name.clone())
                    .unwrap_or_else(|| user.name.clone());

                users.insert(user.id.clone(), display_name);
            }
        }

        Ok(users)
    }

    fn load_channels(&self, export_path: &Path) -> Result<Vec<SlackChannel>, String> {
        let channels_path = export_path.join("channels.json");
        if channels_path.exists() {
            let content = std::fs::read_to_string(&channels_path)
                .map_err(|e| format!("Failed to read channels.json: {}", e))?;

            let channels: Vec<SlackChannel> = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse channels.json: {}", e))?;

            return Ok(channels);
        }

        let conversations_path = export_path.join("conversations.json");
        if conversations_path.exists() {
            let content = std::fs::read_to_string(&conversations_path)
                .map_err(|e| format!("Failed to read conversations.json: {}", e))?;

            let channels: Vec<SlackChannel> = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse conversations.json: {}", e))?;

            return Ok(channels);
        }

        Ok(Vec::new())
    }

    fn find_json_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
        let mut files = Vec::new();

        if !dir.is_dir() {
            return Ok(files);
        }

        let entries = std::fs::read_dir(dir)
            .map_err(|e| format!("Failed to read directory {:?}: {}", dir, e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                files.push(path);
            }
        }

        files.sort();
        Ok(files)
    }

    fn parse_channel_file(
        &self,
        file_path: &Path,
        _channel_name: &str,
        users: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<ChatMessage>, String> {
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read {}: {}", file_path.display(), e))?;

        let slack_msgs: Vec<SlackMessage> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", file_path.display(), e))?;

        let mut messages = Vec::new();

        for msg in slack_msgs {
            let sender = msg
                .user
                .as_ref()
                .and_then(|uid| users.get(uid))
                .cloned()
                .or_else(|| msg.username.clone())
                .unwrap_or_else(|| msg.user.clone().unwrap_or_else(|| "unknown".to_string()));

            let text = msg
                .text
                .clone()
                .or_else(|| msg.attachments.as_ref().and_then(|a| a.first().map(|att| {
                    att.fallback.clone().unwrap_or_else(|| "[attachment]".to_string())
                })))
                .unwrap_or_default();

            let timestamp = msg
                .ts
                .as_ref()
                .and_then(|ts_str| {
                    let epoch: f64 = ts_str.parse().ok()?;
                    let secs = epoch as i64;
                    let nsecs = ((epoch - secs as f64) * 1_000_000_000.0) as u32;
                    chrono::DateTime::from_timestamp(secs, nsecs)
                })
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string());

            let media_count = msg.files.as_ref().map_or(0, |f| f.len() as u32)
                + msg.attachments.as_ref().map_or(0, |a| a.len() as u32);

            messages.push(ChatMessage {
                sender,
                content: text,
                timestamp,
                media_count,
            });
        }

        Ok(messages)
    }
}

#[derive(Deserialize)]
struct SlackUser {
    id: String,
    name: String,
    real_name: Option<String>,
    profile: Option<SlackUserProfile>,
}

#[derive(Deserialize)]
struct SlackUserProfile {
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct SlackChannel {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct SlackMessage {
    user: Option<String>,
    username: Option<String>,
    text: Option<String>,
    ts: Option<String>,
    files: Option<Vec<serde_json::Value>>,
    attachments: Option<Vec<SlackAttachment>>,
}

#[derive(Deserialize)]
struct SlackAttachment {
    fallback: Option<String>,
}

pub struct BrowserHistoryRecoverer;

impl BrowserHistoryRecoverer {
    pub fn new() -> Self {
        Self
    }

    pub fn recover(
        &self,
        browser: &str,
        profile_path: &str,
    ) -> Result<Vec<HistoryEntry>, String> {
        info!("Recovering {} history from {}", browser, profile_path);

        match browser.to_lowercase().as_str() {
            "chrome" | "chromium" | "brave" | "edge" => self.recover_chromium(profile_path),
            "firefox" => self.recover_firefox(profile_path),
            "safari" => self.recover_safari(profile_path),
            _ => Err(format!("Unsupported browser: {}", browser)),
        }
    }

    fn recover_chromium(&self, profile_path: &str) -> Result<Vec<HistoryEntry>, String> {
        let db_path = Path::new(profile_path).join("History");

        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open Chromium history: {}", e))?;

        let query = r#"
            SELECT
                u.url,
                COALESCE(u.title, ''),
                v.visit_time,
                u.visit_count
            FROM urls u
            LEFT JOIN visits v ON u.id = v.url
            ORDER BY v.visit_time ASC
        "#;

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("Failed to prepare Chromium query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let title: String = row.get(1)?;
                let visit_time: i64 = row.get(2)?;
                let visit_count: i32 = row.get(3)?;

                let dt = Self::chrome_time_to_datetime(visit_time);

                Ok(HistoryEntry {
                    url,
                    title,
                    timestamp: dt,
                    visit_count: visit_count as u32,
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            match row {
                Ok(entry) => entries.push(entry),
                Err(e) => warn!("Skipping Chromium history row: {}", e),
            }
        }

        info!("Recovered {} Chromium history entries", entries.len());
        Ok(entries)
    }

    fn recover_firefox(&self, profile_path: &str) -> Result<Vec<HistoryEntry>, String> {
        let db_path = Path::new(profile_path).join("places.sqlite");

        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open Firefox places: {}", e))?;

        let query = r#"
            SELECT
                p.url,
                COALESCE(p.title, ''),
                h.visit_date,
                p.visit_count
            FROM moz_places p
            LEFT JOIN moz_historyvisits h ON p.id = h.place_id
            ORDER BY h.visit_date ASC
        "#;

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("Failed to prepare Firefox query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let title: String = row.get(1)?;
                let visit_date: i64 = row.get(2)?;
                let visit_count: i32 = row.get(3)?;

                let dt = chrono::DateTime::from_timestamp(visit_date / 1_000_000, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());

                Ok(HistoryEntry {
                    url,
                    title,
                    timestamp: dt,
                    visit_count: visit_count as u32,
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            match row {
                Ok(entry) => entries.push(entry),
                Err(e) => warn!("Skipping Firefox history row: {}", e),
            }
        }

        info!("Recovered {} Firefox history entries", entries.len());
        Ok(entries)
    }

    fn recover_safari(&self, profile_path: &str) -> Result<Vec<HistoryEntry>, String> {
        let db_path = Path::new(profile_path).join("History.db");

        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| format!("Failed to open Safari history: {}", e))?;

        let query = r#"
            SELECT
                hi.url,
                COALESCE(hi.title, ''),
                hv.visit_time,
                hi.visit_count
            FROM history_items hi
            LEFT JOIN history_visits hv ON hi.id = hv.history_item
            ORDER BY hv.visit_time ASC
        "#;

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| format!("Failed to prepare Safari query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let url: String = row.get(0)?;
                let title: String = row.get(1)?;
                let visit_time: f64 = row.get(2)?;
                let visit_count: i32 = row.get(3)?;

                let safari_epoch: i64 = 978_307_200;
                let unix_ts = visit_time as i64 + safari_epoch;

                let dt = chrono::DateTime::from_timestamp(unix_ts, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());

                Ok(HistoryEntry {
                    url,
                    title,
                    timestamp: dt,
                    visit_count: visit_count as u32,
                })
            })
            .map_err(|e| format!("Query map error: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            match row {
                Ok(entry) => entries.push(entry),
                Err(e) => warn!("Skipping Safari history row: {}", e),
            }
        }

        info!("Recovered {} Safari history entries", entries.len());
        Ok(entries)
    }

    fn chrome_time_to_datetime(chrome_time: i64) -> String {
        let chrome_epoch_offset: i64 = 11_644_473_600;
        let unix_secs = (chrome_time / 1_000_000) - chrome_epoch_offset;

        chrono::DateTime::from_timestamp(unix_secs, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

pub struct SqliteCarver;

impl SqliteCarver {
    pub fn new() -> Self {
        Self
    }

    pub fn carve(&self, device_path: &str, output_dir: &Path) -> Result<Vec<PathBuf>, String> {
        info!("Scanning {} for SQLite databases", device_path);

        std::fs::create_dir_all(output_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;

        let device_path_obj = Path::new(device_path);

        if device_path_obj.is_file() {
            return self.carve_file(device_path_obj, output_dir);
        }

        self.carve_directory(device_path_obj, output_dir)
    }

    fn carve_file(&self, file_path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>, String> {
        let data = std::fs::read(file_path)
            .map_err(|e| format!("Failed to read file {}: {}", file_path.display(), e))?;

        let sqlite_header = b"SQLite format 3\0";
        let mut recovered = Vec::new();
        let mut offset = 0;
        let mut db_index = 0;

        while offset + sqlite_header.len() <= data.len() {
            if let Some(pos) = Self::find_bytes(&data, sqlite_header, offset) {
                let db_size = self.estimate_sqlite_size(&data, pos);

                if db_size > 0 {
                    let db_data = &data[pos..pos + db_size];

                    if Self::validate_sqlite(db_data) {
                        let filename = format!("recovered_{}.db", db_index);
                        let output_path = output_dir.join(&filename);

                        std::fs::write(&output_path, db_data)
                            .map_err(|e| format!("Failed to write recovered DB: {}", e))?;

                        debug!("Recovered SQLite database at offset {} ({} bytes)", pos, db_size);
                        recovered.push(output_path);
                        db_index += 1;
                    }
                }

                offset = pos + 1;
            } else {
                break;
            }
        }

        info!("Recovered {} SQLite databases from {}", recovered.len(), file_path.display());
        Ok(recovered)
    }

    fn carve_directory(&self, dir_path: &Path, output_dir: &Path) -> Result<Vec<PathBuf>, String> {
        let mut recovered = Vec::new();

        let entries = std::fs::read_dir(dir_path)
            .map_err(|e| format!("Failed to read directory: {}", e))?;

        for entry in entries {
            let entry = entry.map_err(|e| format!("Dir entry error: {}", e))?;
            let path = entry.path();

            if path.is_file() {
                match self.carve_file(&path, output_dir) {
                    Ok(files) => recovered.extend(files),
                    Err(e) => {
                        debug!("Skipping file {}: {}", path.display(), e);
                    }
                }
            } else if path.is_dir() {
                match self.carve_directory(&path, output_dir) {
                    Ok(files) => recovered.extend(files),
                    Err(e) => {
                        debug!("Skipping directory {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(recovered)
    }

    fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
        if needle.is_empty() || start + needle.len() > haystack.len() {
            return None;
        }

        haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)
            .map(|pos| pos + start)
    }

    fn estimate_sqlite_size(&self, data: &[u8], header_offset: usize) -> usize {
        if header_offset + 100 > data.len() {
            return 0;
        }

        let page_size_bytes = &data[header_offset + 16..header_offset + 18];
        let page_size = u16::from_be_bytes([page_size_bytes[0], page_size_bytes[1]]) as usize;

        let page_size = if page_size == 1 { 65536 } else { page_size };

        if page_size == 0 || !page_size.is_power_of_two() {
            return 0;
        }

        let total_pages_bytes = &data[header_offset + 28..header_offset + 32];
        let total_pages = u32::from_be_bytes([
            total_pages_bytes[0],
            total_pages_bytes[1],
            total_pages_bytes[2],
            total_pages_bytes[3],
        ]) as usize;

        let estimated_size = page_size * total_pages;

        if estimated_size > data.len() - header_offset {
            data.len() - header_offset
        } else {
            estimated_size
        }
    }

    fn validate_sqlite(data: &[u8]) -> bool {
        if data.len() < 100 {
            return false;
        }

        let header = b"SQLite format 3\0";
        if &data[0..16] != header {
            return false;
        }

        let page_size_bytes = &data[16..18];
        let page_size = u16::from_be_bytes([page_size_bytes[0], page_size_bytes[1]]);
        let page_size = if page_size == 1 { 65536 } else { page_size as usize };

        if page_size == 0 || !page_size.is_power_of_two() {
            return false;
        }

        true
    }
}

pub struct EmailRecoverer;

impl EmailRecoverer {
    pub fn new() -> Self {
        Self
    }

    pub fn recover(&self, input_path: &str) -> Result<Vec<EmailMessage>, String> {
        info!("Recovering emails from {}", input_path);

        let path = Path::new(input_path);
        if !path.exists() {
            return Err(format!("Input file does not exist: {}", input_path));
        }

        let magic = Self::read_magic_bytes(path)?;

        if Self::is_pst_or_ost(&magic) {
            return self.recover_pst(path);
        }

        if Self::is_mbox(path) {
            return self.recover_mbox(path);
        }

        if Self::is_eml(path) {
            return self.recover_eml(path);
        }

        self.recover_mbox(path)
    }

    fn read_magic_bytes(path: &Path) -> Result<Vec<u8>, String> {
        use std::io::Read;

        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("Failed to open file: {}", e))?;

        let mut magic = vec![0u8; 16];
        let bytes_read = file
            .read(&mut magic)
            .map_err(|e| format!("Failed to read magic bytes: {}", e))?;

        magic.truncate(bytes_read);
        Ok(magic)
    }

    fn is_pst_or_ost(magic: &[u8]) -> bool {
        magic.len() >= 4 && magic[0] == 0x21 && magic[1] == 0x42 && magic[2] == 0x44 && magic[3] == 0x4E
    }

    fn is_mbox(path: &Path) -> bool {
        if let Ok(content) = std::fs::read_to_string(path) {
            content.starts_with("From ")
        } else {
            false
        }
    }

    fn is_eml(path: &Path) -> bool {
        path.extension()
            .map_or(false, |ext| ext.eq_ignore_ascii_case("eml"))
    }

    fn recover_pst(&self, path: &Path) -> Result<Vec<EmailMessage>, String> {
        use std::io::Read;

        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("Failed to open PST file: {}", e))?;

        let mut header = vec![0u8; 68];
        file.read_exact(&mut header)
            .map_err(|e| format!("Failed to read PST header: {}", e))?;

        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if magic != 0x4E444221 {
            return Err("Invalid PST magic number".to_string());
        }

        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)
            .map_err(|e| format!("Failed to read PST file data: {}", e))?;

        let mut messages = Vec::new();
        let content = String::from_utf8_lossy(&file_data);

        let mut current_from = String::new();
        let mut current_to = Vec::new();
        let mut current_subject = String::new();
        let mut current_date = String::new();
        let mut in_message = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("From ") && !in_message {
                in_message = true;
                current_from = String::new();
                current_to = Vec::new();
                current_subject = String::new();
                current_date = String::new();
            }

            if trimmed.starts_with("From:") {
                current_from = trimmed.trim_start_matches("From:").trim().to_string();
            } else if trimmed.starts_with("To:") {
                let to_str = trimmed.trim_start_matches("To:").trim().to_string();
                current_to = to_str.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            } else if trimmed.starts_with("Subject:") {
                current_subject = trimmed.trim_start_matches("Subject:").trim().to_string();
            } else if trimmed.starts_with("Date:") {
                current_date = trimmed.trim_start_matches("Date:").trim().to_string();
            } else if trimmed.is_empty() && in_message && !current_from.is_empty() {
                messages.push(EmailMessage {
                    from: current_from.clone(),
                    to: current_to.clone(),
                    subject: current_subject.clone(),
                    date: current_date.clone(),
                    has_attachments: false,
                });
                in_message = false;
            }
        }

        if !messages.is_empty() || !current_from.is_empty() {
            if !current_from.is_empty() {
                messages.push(EmailMessage {
                    from: current_from,
                    to: current_to,
                    subject: current_subject,
                    date: current_date,
                    has_attachments: false,
                });
            }
        }

        if messages.is_empty() {
            let file_size = std::fs::metadata(path)
                .map(|m| m.len())
                .unwrap_or(0);

            info!("PST file detected ({} bytes), {} email records extracted from header scan", file_size, messages.len());
        }

        info!("Recovered {} emails from PST", messages.len());
        Ok(messages)
    }

    fn recover_mbox(&self, path: &Path) -> Result<Vec<EmailMessage>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read MBOX file: {}", e))?;

        let mut messages = Vec::new();
        let mut current_from = String::new();
        let mut current_to = Vec::new();
        let mut current_subject = String::new();
        let mut current_date = String::new();
        let mut has_attachments = false;
        let mut in_headers = true;
        let mut in_message = false;

        for line in content.lines() {
            if line.starts_with("From ") {
                if in_message && !current_from.is_empty() {
                    messages.push(EmailMessage {
                        from: current_from.clone(),
                        to: current_to.clone(),
                        subject: current_subject.clone(),
                        date: current_date.clone(),
                        has_attachments,
                    });
                }

                current_from = String::new();
                current_to = Vec::new();
                current_subject = String::new();
                current_date = String::new();
                has_attachments = false;
                in_headers = true;
                in_message = true;
                continue;
            }

            if in_headers {
                if line.is_empty() {
                    in_headers = false;
                    continue;
                }

                let lower = line.to_lowercase();

                if lower.starts_with("from:") {
                    current_from = line[5..].trim().to_string();
                } else if lower.starts_with("to:") {
                    let to_str = line[3..].trim().to_string();
                    current_to = to_str.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                } else if lower.starts_with("subject:") {
                    current_subject = line[8..].trim().to_string();
                } else if lower.starts_with("date:") {
                    current_date = line[5..].trim().to_string();
                } else if lower.starts_with("content-type:") && lower.contains("multipart") {
                    // may have attachments
                } else if lower.starts_with("content-disposition:") && lower.contains("attachment") {
                    has_attachments = true;
                }
            } else {
                let lower = line.to_lowercase();
                if lower.contains("attachment") || lower.contains("filename=") {
                    has_attachments = true;
                }
            }
        }

        if in_message && !current_from.is_empty() {
            messages.push(EmailMessage {
                from: current_from,
                to: current_to,
                subject: current_subject,
                date: current_date,
                has_attachments,
            });
        }

        info!("Recovered {} emails from MBOX", messages.len());
        Ok(messages)
    }

    fn recover_eml(&self, path: &Path) -> Result<Vec<EmailMessage>, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read EML file: {}", e))?;

        let mut from = String::new();
        let mut to = Vec::new();
        let mut subject = String::new();
        let mut date = String::new();
        let mut has_attachments = false;

        for line in content.lines() {
            if line.is_empty() {
                break;
            }

            let lower = line.to_lowercase();

            if lower.starts_with("from:") {
                from = line[5..].trim().to_string();
            } else if lower.starts_with("to:") {
                let to_str = line[3..].trim().to_string();
                to = to_str.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            } else if lower.starts_with("subject:") {
                subject = line[8..].trim().to_string();
            } else if lower.starts_with("date:") {
                date = line[5..].trim().to_string();
            } else if lower.starts_with("content-disposition:") && lower.contains("attachment") {
                has_attachments = true;
            }
        }

        let message = EmailMessage {
            from,
            to,
            subject,
            date,
            has_attachments,
        };

        info!("Recovered 1 email from EML");
        Ok(vec![message])
    }
}
