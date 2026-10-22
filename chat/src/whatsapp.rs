use std::path::Path;
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppMessage {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: Option<String>,
    pub message_type: WhatsAppMessageType,
    pub media: Option<WhatsAppMedia>,
    pub is_deleted: bool,
    pub is_encrypted: bool,
    pub group_jid: Option<String>,
    pub is_from_me: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WhatsAppMessageType {
    Text,
    Image,
    Video,
    Audio,
    Document,
    Location,
    Contact,
    System,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppMedia {
    pub file_path: String,
    pub mime_type: String,
    pub file_size: u64,
    pub media_type: WhatsAppMediaType,
    pub thumbnail: Option<Vec<u8>>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WhatsAppMediaType {
    Image,
    Video,
    Audio,
    Document,
    Sticker,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppContact {
    pub jid: String,
    pub display_name: Option<String>,
    pub phone_number: Option<String>,
    pub is_group: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppGroup {
    pub jid: String,
    pub subject: String,
    pub created_at: Option<DateTime<Utc>>,
    pub creator_jid: Option<String>,
    pub participants: Vec<String>,
}

pub struct WhatsAppParser;

impl WhatsAppParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_database(&self, db_path: &Path) -> Result<Vec<WhatsAppMessage>> {
        info!("Parsing WhatsApp database at {:?}", db_path);
        let conn = Connection::open(db_path)?;
        let mut messages = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ZMESSAGE'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if table_exists {
            messages.extend(self.parse_ios_database(&conn)?);
        } else {
            messages.extend(self.parse_android_database(&conn)?);
        }

        info!("Parsed {} messages from WhatsApp database", messages.len());
        Ok(messages)
    }

    fn parse_ios_database(&self, conn: &Connection) -> Result<Vec<WhatsAppMessage>> {
        let mut stmt = conn.prepare(
            "SELECT m.Z_PK, m.ZMESSAGEDATE, m.ZFROMJID, m.ZTOJID, m.ZTEXT, \
             m.ZMEDIALOCALPATH, m.ZMEDIATYPE, m.ZISFROMME, m.ZGROUPCHATJID, \
             m.ZISDELETED, c.ZPUSHNAME \
             FROM ZMESSAGE m \
             LEFT JOIN ZCHAT c ON m.ZCHAT = c.Z_PK \
             ORDER BY m.ZMESSAGEDATE"
        )?;

        let rows = stmt.query_map([], |row| {
            let timestamp = parse_core_data_timestamp(row.get::<_, f64>(1)?);
            let from_jid: Option<String> = row.get(2)?;
            let _to_jid: Option<String> = row.get(3)?;
            let text: Option<String> = row.get(4)?;
            let media_path: Option<String> = row.get(5)?;
            let media_type_raw: Option<i64> = row.get(6)?;
            let is_from_me: bool = row.get::<_, i64>(7)? != 0;
            let group_jid: Option<String> = row.get(8)?;
            let is_deleted: bool = row.get::<_, i64>(9)? != 0;
            let sender_name: Option<String> = row.get(10)?;

            let sender = if is_from_me {
                "self".to_string()
            } else {
                from_jid.unwrap_or_else(|| "unknown".to_string())
            };

            let message_type = match media_type_raw {
                Some(0) | None => {
                    if text.is_some() { WhatsAppMessageType::Text } else { WhatsAppMessageType::Unknown }
                }
                Some(1) => WhatsAppMessageType::Image,
                Some(2) => WhatsAppMessageType::Video,
                Some(3) => WhatsAppMessageType::Audio,
                Some(4) => WhatsAppMessageType::Document,
                Some(5) => WhatsAppMessageType::Location,
                _ => WhatsAppMessageType::Unknown,
            };

            let media = media_path.map(|path| WhatsAppMedia {
                file_path: path,
                mime_type: match message_type {
                    WhatsAppMessageType::Image => "image/jpeg".to_string(),
                    WhatsAppMessageType::Video => "video/mp4".to_string(),
                    WhatsAppMessageType::Audio => "audio/ogg".to_string(),
                    WhatsAppMessageType::Document => "application/octet-stream".to_string(),
                    _ => "application/octet-stream".to_string(),
                },
                file_size: 0,
                media_type: match message_type {
                    WhatsAppMessageType::Image => WhatsAppMediaType::Image,
                    WhatsAppMessageType::Video => WhatsAppMediaType::Video,
                    WhatsAppMessageType::Audio => WhatsAppMediaType::Audio,
                    WhatsAppMessageType::Document => WhatsAppMediaType::Document,
                    _ => WhatsAppMediaType::Unknown,
                },
                thumbnail: None,
                duration_ms: None,
            });

            Ok(WhatsAppMessage {
                id: format!("msg_{}", row.get::<_, i64>(0)?),
                timestamp,
                sender,
                sender_name,
                content: text,
                message_type,
                media,
                is_deleted,
                is_encrypted: false,
                group_jid,
                is_from_me,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    fn parse_android_database(&self, conn: &Connection) -> Result<Vec<WhatsAppMessage>> {
        let mut stmt = conn.prepare(
            "SELECT m._id, m.timestamp, m.key_remote_jid, m.data, \
             m.media_mime_type, m.media_wa_type, m.media_size, \
             m.media_name, m.media_url, m.thumb_image, m.from_me, \
             m.key_from_me, m.status, m.origin \
             FROM message m \
             ORDER BY m.timestamp"
        )?;

        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let timestamp_ms: i64 = row.get(1)?;
            let remote_jid: Option<String> = row.get(2)?;
            let data: Option<String> = row.get(3)?;
            let media_mime: Option<String> = row.get(4)?;
            let media_wa_type: Option<i64> = row.get(5)?;
            let media_size: Option<i64> = row.get(6)?;
            let media_name: Option<String> = row.get(7)?;
            let _media_url: Option<String> = row.get(8)?;
            let _thumb: Option<Vec<u8>> = row.get(9)?;
            let from_me_raw: i64 = row.get(10)?;
            let _key_from_me: Option<i64> = row.get(11)?;
            let status: Option<i64> = row.get(12)?;
            let origin: Option<i64> = row.get(13)?;

            let from_me = from_me_raw != 0;
            let is_deleted = status == Some(5) || status == Some(6);
            let timestamp = DateTime::from_timestamp(timestamp_ms / 1000, 0).unwrap_or_default();

            let sender = if from_me {
                "self".to_string()
            } else {
                remote_jid.clone().unwrap_or_else(|| "unknown".to_string())
            };

            let message_type = match media_wa_type {
                None | Some(0) => {
                    if data.is_some() { WhatsAppMessageType::Text } else { WhatsAppMessageType::Unknown }
                }
                Some(1) => WhatsAppMessageType::Image,
                Some(2) => WhatsAppMessageType::Audio,
                Some(3) => WhatsAppMessageType::Video,
                Some(4) => WhatsAppMessageType::Contact,
                Some(5) => WhatsAppMessageType::Location,
                Some(9) => WhatsAppMessageType::Document,
                _ => WhatsAppMessageType::Unknown,
            };

            let media = media_mime.map(|mime| {
                let media_type = if mime.starts_with("image/") {
                    WhatsAppMediaType::Image
                } else if mime.starts_with("video/") {
                    WhatsAppMediaType::Video
                } else if mime.starts_with("audio/") {
                    WhatsAppMediaType::Audio
                } else {
                    WhatsAppMediaType::Document
                };

                WhatsAppMedia {
                    file_path: media_name.unwrap_or_default(),
                    mime_type: mime,
                    file_size: media_size.unwrap_or(0) as u64,
                    media_type,
                    thumbnail: None,
                    duration_ms: None,
                }
            });

            let is_encrypted = origin == Some(7);

            Ok(WhatsAppMessage {
                id: format!("msg_{}", id),
                timestamp,
                sender,
                sender_name: None,
                content: data,
                message_type,
                media,
                is_deleted,
                is_encrypted,
                group_jid: if remote_jid.as_deref().map_or(false, |jid| jid.contains("@g.us")) {
                    remote_jid
                } else {
                    None
                },
                is_from_me: from_me,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    pub fn recover_from_wal(&self, wal_path: &Path) -> Result<Vec<WhatsAppMessage>> {
        info!("Attempting WAL recovery from {:?}", wal_path);
        let data = std::fs::read(wal_path)?;

        if data.len() < 32 {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let needle = b"ZTEXT\0";
        let needle2 = b"data\0";

        let mut pos = 0;
        while pos < data.len() {
            let found = data[pos..].windows(needle.len()).position(|w| w == needle);
            let found2 = data[pos..].windows(needle2.len()).position(|w| w == needle2);

            let offset = match (found, found2) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => break,
            };

            if let Some(off) = offset {
                pos += off;
                if let Some(text) = extract_text_after_offset(&data, pos + needle.len()) {
                    messages.push(WhatsAppMessage {
                        id: format!("wal_recovered_{}", messages.len()),
                        timestamp: Utc::now(),
                        sender: "unknown".to_string(),
                        sender_name: None,
                        content: Some(text),
                        message_type: WhatsAppMessageType::Text,
                        media: None,
                        is_deleted: true,
                        is_encrypted: false,
                        group_jid: None,
                        is_from_me: false,
                    });
                }
                pos += 1;
            } else {
                break;
            }
        }

        info!("Recovered {} messages from WAL file", messages.len());
        Ok(messages)
    }

    pub fn extract_media(&self, media_dir: &Path) -> Vec<WhatsAppMedia> {
        info!("Extracting media from {:?}", media_dir);
        let mut media_files = Vec::new();

        if !media_dir.exists() {
            warn!("Media directory does not exist: {:?}", media_dir);
            return media_files;
        }

        if let Ok(entries) = std::fs::read_dir(media_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();

                    let mime_type = guess_mime_type(&file_name);
                    let media_type = guess_whatsapp_media_type(&file_name);
                    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                    media_files.push(WhatsAppMedia {
                        file_path: path.to_string_lossy().to_string(),
                        mime_type,
                        file_size,
                        media_type,
                        thumbnail: None,
                        duration_ms: None,
                    });
                }
            }
        }

        info!("Found {} media files", media_files.len());
        media_files
    }

    pub fn parse_contacts(&self, db_path: &Path) -> Result<Vec<WhatsAppContact>> {
        let conn = Connection::open(db_path)?;
        let mut contacts = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ZWAADDRESSBOOKCONTACT'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if table_exists {
            let mut stmt = conn.prepare(
                "SELECT ZUSER, ZPUSHNAME, ZFULLNAME FROM ZWAADDRESSBOOKCONTACT"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(WhatsAppContact {
                    jid: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    display_name: row.get(1)?,
                    phone_number: row.get(2)?,
                    is_group: false,
                    last_seen: None,
                })
            })?;
            for row in rows {
                contacts.push(row?);
            }
        }

        Ok(contacts)
    }

    pub fn parse_groups(&self, db_path: &Path) -> Result<Vec<WhatsAppGroup>> {
        let conn = Connection::open(db_path)?;
        let mut groups = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ZGROUPCHAT'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if table_exists {
            let mut stmt = conn.prepare(
                "SELECT ZGROUPID, ZSUBJECT, ZCREATIONDATETIME, ZCREATORJID FROM ZGROUPCHAT"
            )?;
            let rows = stmt.query_map([], |row| {
                let created: Option<f64> = row.get(2)?;
                Ok(WhatsAppGroup {
                    jid: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    subject: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    created_at: created.map(parse_core_data_timestamp),
                    creator_jid: row.get(3)?,
                    participants: Vec::new(),
                })
            })?;
            for row in rows {
                groups.push(row?);
            }
        }

        Ok(groups)
    }
}

impl Default for WhatsAppParser {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_core_data_timestamp(core_data_ts: f64) -> DateTime<Utc> {
    let core_data_epoch = 978307200.0_f64;
    let unix_ts = core_data_ts + core_data_epoch;
    DateTime::from_timestamp(unix_ts as i64, 0).unwrap_or_default()
}

fn extract_text_after_offset(data: &[u8], start: usize) -> Option<String> {
    if start >= data.len() {
        return None;
    }

    let end = data[start..].iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }

    let text_bytes = &data[start..start + end];
    String::from_utf8(text_bytes.to_vec()).ok()
}

fn guess_mime_type(filename: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg".to_string()
    } else if lower.ends_with(".png") {
        "image/png".to_string()
    } else if lower.ends_with(".gif") {
        "image/gif".to_string()
    } else if lower.ends_with(".mp4") {
        "video/mp4".to_string()
    } else if lower.ends_with(".mov") {
        "video/quicktime".to_string()
    } else if lower.ends_with(".3gp") {
        "video/3gpp".to_string()
    } else if lower.ends_with(".aac") {
        "audio/aac".to_string()
    } else if lower.ends_with(".ogg") || lower.ends_with(".opus") {
        "audio/ogg".to_string()
    } else if lower.ends_with(".mp3") {
        "audio/mpeg".to_string()
    } else if lower.ends_with(".pdf") {
        "application/pdf".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn guess_whatsapp_media_type(filename: &str) -> WhatsAppMediaType {
    let lower = filename.to_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") || lower.ends_with(".png") || lower.ends_with(".gif") || lower.ends_with(".webp") {
        WhatsAppMediaType::Image
    } else if lower.ends_with(".mp4") || lower.ends_with(".mov") || lower.ends_with(".3gp") || lower.ends_with(".avi") {
        WhatsAppMediaType::Video
    } else if lower.ends_with(".opus") || lower.ends_with(".ogg") || lower.ends_with(".aac") || lower.ends_with(".mp3") {
        WhatsAppMediaType::Audio
    } else if lower.ends_with(".webp") {
        WhatsAppMediaType::Sticker
    } else if lower.ends_with(".pdf") || lower.ends_with(".doc") || lower.ends_with(".docx") || lower.ends_with(".xls") || lower.ends_with(".xlsx") {
        WhatsAppMediaType::Document
    } else {
        WhatsAppMediaType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use std::path::PathBuf;

    fn create_test_ios_db() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("ChatStorage.sqlite");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE ZCHAT (Z_PK INTEGER PRIMARY KEY, ZGROUPID TEXT, ZPUSHNAME TEXT, ZFULLNAME TEXT);
             CREATE TABLE ZMESSAGE (Z_PK INTEGER PRIMARY KEY, ZCHAT INTEGER, ZMESSAGEDATE REAL, \
             ZFROMJID TEXT, ZTOJID TEXT, ZTEXT TEXT, ZMEDIALOCALPATH TEXT, ZMEDIATYPE INTEGER, \
             ZISFROMME INTEGER, ZGROUPCHATJID TEXT, ZISDELETED INTEGER);"
        ).unwrap();

        conn.execute(
            "INSERT INTO ZCHAT (Z_PK, ZPUSHNAME, ZFULLNAME) VALUES (1, 'Alice', 'Alice Smith')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO ZMESSAGE (Z_PK, ZCHAT, ZMESSAGEDATE, ZFROMJID, ZTOJID, ZTEXT, \
             ZMEDIALOCALPATH, ZMEDIATYPE, ZISFROMME, ZGROUPCHATJID, ZISDELETED) \
             VALUES (1, 1, 700000000.0, 'alice@wa.net', 'bob@wa.net', 'Hello World!', \
             NULL, 0, 0, NULL, 0)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO ZMESSAGE (Z_PK, ZCHAT, ZMESSAGEDATE, ZFROMJID, ZTOJID, ZTEXT, \
             ZMEDIALOCALPATH, ZMEDIATYPE, ZISFROMME, ZGROUPCHATJID, ZISDELETED) \
             VALUES (2, 1, 700000100.0, 'bob@wa.net', 'alice@wa.net', 'Photo message', \
             '/var/mobile/photo.jpg', 1, 1, NULL, 0)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO ZMESSAGE (Z_PK, ZCHAT, ZMESSAGEDATE, ZFROMJID, ZTOJID, ZTEXT, \
             ZMEDIALOCALPATH, ZMEDIATYPE, ZISFROMME, ZGROUPCHATJID, ZISDELETED) \
             VALUES (3, 1, 700000200.0, 'alice@wa.net', 'bob@wa.net', NULL, \
             NULL, 0, 0, NULL, 1)",
            [],
        ).unwrap();

        (dir, db_path)
    }

    fn create_test_android_db() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("msgstore.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE message (_id INTEGER PRIMARY KEY, timestamp INTEGER, \
             key_remote_jid TEXT, data TEXT, media_mime_type TEXT, media_wa_type INTEGER, \
             media_size INTEGER, media_name TEXT, media_url TEXT, thumb_image BLOB, \
             from_me INTEGER, key_from_me INTEGER, status INTEGER, origin INTEGER);"
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (1, 1700000000000, 'alice@s.whatsapp.net', \
             'Hello from Android', NULL, 0, NULL, NULL, NULL, NULL, 0, 0, 0, 0)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (2, 1700000100000, 'alice@s.whatsapp.net', \
             NULL, 'image/jpeg', 1, 50000, 'IMG_001.jpg', 'http://example.com', NULL, 0, 0, 0, 0)",
            [],
        ).unwrap();

        (dir, db_path)
    }

    #[test]
    fn test_parse_ios_database() {
        let (dir, db_path) = create_test_ios_db();
        let parser = WhatsAppParser::new();
        let messages = parser.parse_database(&db_path).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, Some("Hello World!".to_string()));
        assert_eq!(messages[0].sender, "alice@wa.net");
        assert!(!messages[0].is_from_me);
        assert_eq!(messages[1].message_type, WhatsAppMessageType::Image);
        assert!(messages[1].media.is_some());
        assert!(messages[1].is_from_me);
        assert!(messages[2].is_deleted);
        drop(dir);
    }

    #[test]
    fn test_parse_android_database() {
        let (dir, db_path) = create_test_android_db();
        let parser = WhatsAppParser::new();
        let messages = parser.parse_database(&db_path).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, Some("Hello from Android".to_string()));
        assert_eq!(messages[1].message_type, WhatsAppMessageType::Image);
        assert_eq!(messages[1].media.as_ref().unwrap().mime_type, "image/jpeg");
        assert_eq!(messages[1].media.as_ref().unwrap().file_size, 50000);
        drop(dir);
    }

    #[test]
    fn test_extract_media() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("photo.jpg"), b"\xFF\xD8\xFF").unwrap();
        std::fs::write(dir.path().join("voice.opus"), b"\x4F\x67\x67").unwrap();
        std::fs::write(dir.path().join("doc.pdf"), b"%PDF").unwrap();

        let parser = WhatsAppParser::new();
        let media = parser.extract_media(dir.path());
        assert_eq!(media.len(), 3);

        let jpg = media.iter().find(|m| m.file_path.ends_with(".jpg")).unwrap();
        assert_eq!(jpg.mime_type, "image/jpeg");
        assert_eq!(jpg.media_type, WhatsAppMediaType::Image);

        let opus = media.iter().find(|m| m.file_path.ends_with(".opus")).unwrap();
        assert_eq!(opus.media_type, WhatsAppMediaType::Audio);
        drop(dir);
    }

    #[test]
    fn test_recover_from_wal() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("test.wal");

        let mut wal_data = Vec::new();
        wal_data.extend_from_slice(&[0u8; 32]);
        wal_data.extend_from_slice(b"ZTEXT\0Hello recovered message\0");
        wal_data.extend_from_slice(b"\0\0\0\0");
        wal_data.extend_from_slice(b"ZTEXT\0Second message\0");
        std::fs::write(&wal_path, &wal_data).unwrap();

        let parser = WhatsAppParser::new();
        let messages = parser.recover_from_wal(&wal_path).unwrap();
        assert!(messages.len() >= 1);
        assert_eq!(messages[0].content, Some("Hello recovered message".to_string()));
        assert!(messages[0].is_deleted);
        drop(dir);
    }

    #[test]
    fn test_parse_core_data_timestamp() {
        let dt = parse_core_data_timestamp(700000000.0);
        let unix_ts = dt.timestamp();
        assert!(unix_ts > 1_600_000_000 && unix_ts < 2_000_000_000);
    }

    #[test]
    fn test_guess_mime_type() {
        assert_eq!(guess_mime_type("photo.jpg"), "image/jpeg");
        assert_eq!(guess_mime_type("photo.jpeg"), "image/jpeg");
        assert_eq!(guess_mime_type("video.mp4"), "video/mp4");
        assert_eq!(guess_mime_type("audio.opus"), "audio/ogg");
        assert_eq!(guess_mime_type("doc.pdf"), "application/pdf");
        assert_eq!(guess_mime_type("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_guess_whatsapp_media_type() {
        assert_eq!(guess_whatsapp_media_type("photo.jpg"), WhatsAppMediaType::Image);
        assert_eq!(guess_whatsapp_media_type("video.mp4"), WhatsAppMediaType::Video);
        assert_eq!(guess_whatsapp_media_type("voice.opus"), WhatsAppMediaType::Audio);
        assert_eq!(guess_whatsapp_media_type("report.pdf"), WhatsAppMediaType::Document);
    }

    #[test]
    fn test_default() {
        let _parser = WhatsAppParser::default();
    }

    #[test]
    fn test_empty_database() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("empty.db");
        Connection::open(&db_path).unwrap();

        let parser = WhatsAppParser::new();
        let messages = parser.parse_database(&db_path);
        assert!(messages.is_err() || messages.unwrap().is_empty());
        drop(dir);
    }

    #[test]
    fn test_wal_empty_file() {
        let dir = TempDir::new().unwrap();
        let wal_path = dir.path().join("empty.wal");
        std::fs::write(&wal_path, &[0u8; 10]).unwrap();

        let parser = WhatsAppParser::new();
        let messages = parser.recover_from_wal(&wal_path).unwrap();
        assert!(messages.is_empty());
        drop(dir);
    }

    #[test]
    fn test_extract_media_nonexistent_dir() {
        let parser = WhatsAppParser::new();
        let media = parser.extract_media(Path::new("/nonexistent/dir"));
        assert!(media.is_empty());
    }

    #[test]
    fn test_message_serialization() {
        let msg = WhatsAppMessage {
            id: "test_1".to_string(),
            timestamp: Utc::now(),
            sender: "alice".to_string(),
            sender_name: Some("Alice".to_string()),
            content: Some("Hello".to_string()),
            message_type: WhatsAppMessageType::Text,
            media: None,
            is_deleted: false,
            is_encrypted: false,
            group_jid: None,
            is_from_me: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: WhatsAppMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, msg.id);
        assert_eq!(deserialized.content, msg.content);
    }
}
