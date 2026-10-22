use std::path::Path;
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IMessage {
    pub rowid: i64,
    pub guid: String,
    pub timestamp: DateTime<Utc>,
    pub sender: String,
    pub text: Option<String>,
    pub is_from_me: bool,
    pub is_sms: bool,
    pub service: String,
    pub handle_id: i64,
    pub conversation_id: Option<i64>,
    pub attachments: Vec<IMessageAttachment>,
    pub subject: Option<String>,
    pub effect: Option<String>,
    pub reaction_type: Option<String>,
    pub reaction_message_id: Option<i64>,
    pub is_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IMessageAttachment {
    pub rowid: i64,
    pub filename: Option<String>,
    pub mime_type: Option<String>,
    pub transfer_name: Option<String>,
    pub total_bytes: i64,
    pub is_outgoing: bool,
    pub created_date: Option<DateTime<Utc>>,
    pub transfer_state: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IMConversation {
    pub chat_id: i64,
    pub guid: String,
    pub display_name: Option<String>,
    pub participants: Vec<String>,
    pub service_name: String,
    pub message_count: i64,
}

pub struct IMessageParser;

impl IMessageParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_database(&self, db_path: &Path) -> Result<Vec<IMessage>> {
        info!("Parsing iMessage database at {:?}", db_path);
        let conn = Connection::open(db_path)?;
        let mut messages = Vec::new();

        let mut stmt = conn.prepare(
            "SELECT m.ROWID, m.guid, m.date, m.text, m.is_from_me, \
             m.service, m.handle_id, m.subject, m.effect, m.associated_message_type, \
             m.associated_message_guid, h.id AS sender_id \
             FROM message m \
             LEFT JOIN handle h ON m.handle_id = h.ROWID \
             ORDER BY m.date"
        )?;

        let rows = stmt.query_map([], |row| {
            let rowid: i64 = row.get(0)?;
            let guid: String = row.get(1)?;
            let date_raw: i64 = row.get(2)?;
            let text: Option<String> = row.get(3)?;
            let is_from_me_raw: i64 = row.get(4)?;
            let service: Option<String> = row.get(5)?;
            let handle_id: i64 = row.get(6)?;
            let subject: Option<String> = row.get(7)?;
            let effect: Option<String> = row.get(8)?;
            let assoc_type: Option<i64> = row.get(9)?;
            let assoc_guid: Option<String> = row.get(10)?;
            let sender_id: Option<String> = row.get(11)?;

            let timestamp = parse_imessage_timestamp(date_raw);
            let is_from_me = is_from_me_raw != 0;
            let sender = if is_from_me {
                "me".to_string()
            } else {
                sender_id.unwrap_or_else(|| "unknown".to_string())
            };

            let svc = service.unwrap_or_else(|| "iMessage".to_string());
            let is_sms = svc == "SMS" || svc == "sms";

            let (reaction_type, reaction_message_id) = parse_reaction(assoc_type, &assoc_guid);

            Ok(IMessage {
                rowid,
                guid,
                timestamp,
                sender,
                text,
                is_from_me,
                is_sms,
                service: svc,
                handle_id,
                conversation_id: None,
                attachments: Vec::new(),
                subject,
                effect,
                reaction_type,
                reaction_message_id,
                is_deleted: false,
            })
        })?;

        for row in rows {
            messages.push(row?);
        }

        self.attach_attachments(&conn, &mut messages)?;
        self.attach_conversation_ids(&conn, &mut messages)?;

        info!("Parsed {} iMessages from database", messages.len());
        Ok(messages)
    }

    fn attach_attachments(&self, conn: &Connection, messages: &mut [IMessage]) -> Result<()> {
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='message_attachment_join'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            return Ok(());
        }

        let mut stmt = conn.prepare(
            "SELECT j.message_id, a.ROWID, a.filename, a.mime_type, \
             a.transfer_name, a.total_bytes, a.is_outgoing, a.created_date, a.transfer_state \
             FROM message_attachment_join j \
             JOIN attachment a ON j.attachment_id = a.ROWID \
             ORDER BY j.message_id"
        )?;

        let joins: Vec<(i64, IMessageAttachment)> = stmt.query_map([], |row| {
            let msg_id: i64 = row.get(0)?;
            let created: Option<i64> = row.get(7)?;

            Ok((msg_id, IMessageAttachment {
                rowid: row.get(1)?,
                filename: row.get(2)?,
                mime_type: row.get(3)?,
                transfer_name: row.get(4)?,
                total_bytes: row.get(5)?,
                is_outgoing: row.get::<_, i64>(6)? != 0,
                created_date: created.map(parse_imessage_timestamp),
                transfer_state: row.get::<_, i64>(8).unwrap_or(0),
            }))
        })?.collect::<Result<Vec<_>, _>>()?;

        for (msg_id, attachment) in joins {
            if let Some(msg) = messages.iter_mut().find(|m| m.rowid == msg_id) {
                msg.attachments.push(attachment);
            }
        }

        Ok(())
    }

    fn attach_conversation_ids(&self, conn: &Connection, messages: &mut [IMessage]) -> Result<()> {
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chat_message_join'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            return Ok(());
        }

        let mut stmt = conn.prepare(
            "SELECT message_id, chat_id FROM chat_message_join ORDER BY message_id"
        )?;

        let joins: Vec<(i64, i64)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?.collect::<Result<Vec<_>, _>>()?;

        for (msg_id, chat_id) in joins {
            if let Some(msg) = messages.iter_mut().find(|m| m.rowid == msg_id) {
                msg.conversation_id = Some(chat_id);
            }
        }

        Ok(())
    }

    pub fn extract_attachments(&self, attachment_dir: &Path) -> Vec<IMessageAttachment> {
        info!("Extracting attachments from {:?}", attachment_dir);
        let mut attachments = Vec::new();

        if !attachment_dir.exists() {
            warn!("Attachment directory does not exist: {:?}", attachment_dir);
            return attachments;
        }

        if let Ok(entries) = std::fs::read_dir(attachment_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    let file_name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_string();

                    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as i64;
                    let mime = guess_mime_from_extension(&file_name);

                    attachments.push(IMessageAttachment {
                        rowid: 0,
                        filename: Some(path.to_string_lossy().to_string()),
                        mime_type: Some(mime),
                        transfer_name: Some(file_name),
                        total_bytes: file_size,
                        is_outgoing: false,
                        created_date: None,
                        transfer_state: 3,
                    });
                }
            }
        }

        info!("Found {} attachments", attachments.len());
        attachments
    }

    pub fn parse_conversations(&self, db_path: &Path) -> Result<Vec<IMConversation>> {
        let conn = Connection::open(db_path)?;
        let mut conversations = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chat'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            return Ok(conversations);
        }

        let mut stmt = conn.prepare(
            "SELECT c.ROWID, c.guid, c.display_name, c.service_name, \
             (SELECT COUNT(*) FROM chat_message_join cmj WHERE cmj.chat_id = c.ROWID) as msg_count \
             FROM chat c ORDER BY c.ROWID"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(IMConversation {
                chat_id: row.get(0)?,
                guid: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                display_name: row.get(2)?,
                participants: Vec::new(),
                service_name: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                message_count: row.get(4)?,
            })
        })?;

        for row in rows {
            conversations.push(row?);
        }

        let participant_stmt = conn.prepare(
            "SELECT cmj.chat_id, h.id FROM chat_message_join cmj \
             JOIN handle h ON h.ROWID = (SELECT m.handle_id FROM message m WHERE m.ROWID = cmj.message_id LIMIT 1) \
             GROUP BY cmj.chat_id, h.id"
        );

        if let Ok(mut stmt) = participant_stmt {
            let participant_rows: Vec<(i64, String)> = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?.collect::<Result<Vec<_>, _>>()?;

            for (chat_id, participant) in participant_rows {
                if let Some(conv) = conversations.iter_mut().find(|c| c.chat_id == chat_id) {
                    conv.participants.push(participant);
                }
            }
        }

        Ok(conversations)
    }
}

impl Default for IMessageParser {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_imessage_timestamp(timestamp_ns: i64) -> DateTime<Utc> {
    let core_data_epoch = 978307200_i64;

    let timestamp_s = if timestamp_ns > 1_000_000_000_000 {
        timestamp_ns / 1_000_000_000
    } else if timestamp_ns > 1_000_000_000 {
        timestamp_ns
    } else {
        timestamp_ns
    };

    let unix_ts = timestamp_s + core_data_epoch;
    DateTime::from_timestamp(unix_ts, 0).unwrap_or_default()
}

fn parse_reaction(assoc_type: Option<i64>, _assoc_guid: &Option<String>) -> (Option<String>, Option<i64>) {
    match assoc_type {
        Some(2000) => (Some("love".to_string()), None),
        Some(2001) => (Some("like".to_string()), None),
        Some(2002) => (Some("dislike".to_string()), None),
        Some(2003) => (Some("laugh".to_string()), None),
        Some(2004) => (Some("emphasize".to_string()), None),
        Some(2005) => (Some("question".to_string()), None),
        Some(2006) => (Some("arrow".to_string()), None),
        _ => (None, None),
    }
}

fn guess_mime_from_extension(filename: &str) -> String {
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
    } else if lower.ends_with(".pdf") {
        "application/pdf".to_string()
    } else if lower.ends_with(".heic") {
        "image/heic".to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use std::path::PathBuf;

    fn create_test_imessage_db() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("chat.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, service TEXT);
             CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, date INTEGER, \
             text TEXT, is_from_me INTEGER, service TEXT, handle_id INTEGER, \
             subject TEXT, effect TEXT, associated_message_type INTEGER, \
             associated_message_guid TEXT);
             CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT, display_name TEXT, service_name TEXT);
             CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER);
             CREATE TABLE attachment (ROWID INTEGER PRIMARY KEY, filename TEXT, mime_type TEXT, \
             transfer_name TEXT, total_bytes INTEGER, is_outgoing INTEGER, created_date INTEGER, \
             transfer_state INTEGER);
             CREATE TABLE message_attachment_join (message_id INTEGER, attachment_id INTEGER);"
        ).unwrap();

        conn.execute(
            "INSERT INTO handle VALUES (1, '+1234567890', 'iMessage')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO handle VALUES (2, 'alice@icloud.com', 'iMessage')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (1, 'guid-001', 700000000000000000, 'Hello from iMessage!', \
             0, 'iMessage', 1, NULL, NULL, NULL, NULL)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (2, 'guid-002', 700000100000000000, 'Reply', \
             1, 'iMessage', 0, 'Test Subject', NULL, NULL, NULL)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (3, 'guid-003', 700000200000000000, NULL, \
             0, 'SMS', 1, NULL, NULL, 2000, NULL)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (4, 'guid-004', 700000300000000000, 'With effect', \
             1, 'iMessage', 0, NULL, 'slam', NULL, NULL)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO chat VALUES (1, 'chat-guid-001', 'Alice', 'iMessage')",
            [],
        ).unwrap();

        conn.execute("INSERT INTO chat_message_join VALUES (1, 1)", []).unwrap();
        conn.execute("INSERT INTO chat_message_join VALUES (1, 2)", []).unwrap();

        conn.execute(
            "INSERT INTO attachment VALUES (1, '/Attachments/abc/photo.jpg', 'image/jpeg', \
             'photo.jpg', 50000, 0, 700000000, 3)",
            [],
        ).unwrap();

        conn.execute("INSERT INTO message_attachment_join VALUES (1, 1)", []).unwrap();

        (dir, db_path)
    }

    #[test]
    fn test_parse_imessage_database() {
        let (dir, db_path) = create_test_imessage_db();
        let parser = IMessageParser::new();
        let messages = parser.parse_database(&db_path).unwrap();
        assert_eq!(messages.len(), 4);

        assert_eq!(messages[0].text, Some("Hello from iMessage!".to_string()));
        assert_eq!(messages[0].sender, "+1234567890");
        assert!(!messages[0].is_from_me);
        assert!(!messages[0].is_sms);

        assert_eq!(messages[1].text, Some("Reply".to_string()));
        assert!(messages[1].is_from_me);
        assert_eq!(messages[1].subject, Some("Test Subject".to_string()));

        assert!(messages[2].is_sms);
        assert_eq!(messages[2].reaction_type, Some("love".to_string()));

        assert_eq!(messages[3].effect, Some("slam".to_string()));
        drop(dir);
    }

    #[test]
    fn test_attachments_linked() {
        let (dir, db_path) = create_test_imessage_db();
        let parser = IMessageParser::new();
        let messages = parser.parse_database(&db_path).unwrap();
        let msg_with_attachment = messages.iter().find(|m| !m.attachments.is_empty());
        assert!(msg_with_attachment.is_some());
        let attachment = &msg_with_attachment.unwrap().attachments[0];
        assert_eq!(attachment.mime_type, Some("image/jpeg".to_string()));
        assert_eq!(attachment.total_bytes, 50000);
        drop(dir);
    }

    #[test]
    fn test_parse_conversations() {
        let (dir, db_path) = create_test_imessage_db();
        let parser = IMessageParser::new();
        let conversations = parser.parse_conversations(&db_path).unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].display_name, Some("Alice".to_string()));
        assert_eq!(conversations[0].message_count, 2);
        drop(dir);
    }

    #[test]
    fn test_extract_attachments() {
        let dir = TempDir::new().unwrap();
        let att_dir = dir.path().join("attachments");
        std::fs::create_dir(&att_dir).unwrap();
        std::fs::write(att_dir.join("photo.jpg"), b"\xFF\xD8\xFF").unwrap();
        std::fs::write(att_dir.join("doc.pdf"), b"%PDF-1.4").unwrap();

        let parser = IMessageParser::new();
        let attachments = parser.extract_attachments(&att_dir);
        assert_eq!(attachments.len(), 2);
        drop(dir);
    }

    #[test]
    fn test_parse_imessage_timestamp() {
        let dt = parse_imessage_timestamp(700000000000000000);
        assert!(dt.timestamp() > 1_600_000_000);
    }

    #[test]
    fn test_parse_imessage_timestamp_seconds() {
        let dt = parse_imessage_timestamp(700000000);
        assert!(dt.timestamp() > 1_600_000_000);
    }

    #[test]
    fn test_guess_mime() {
        assert_eq!(guess_mime_from_extension("photo.jpg"), "image/jpeg");
        assert_eq!(guess_mime_from_extension("photo.heic"), "image/heic");
        assert_eq!(guess_mime_from_extension("video.mov"), "video/quicktime");
        assert_eq!(guess_mime_from_extension("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_default() {
        let _parser = IMessageParser::default();
    }

    #[test]
    fn test_empty_database() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("empty.db");
        Connection::open(&db_path).unwrap();

        let parser = IMessageParser::new();
        let messages = parser.parse_database(&db_path);
        assert!(messages.is_err() || messages.unwrap().is_empty());
        drop(dir);
    }

    #[test]
    fn test_message_serialization() {
        let msg = IMessage {
            rowid: 1,
            guid: "test-guid".to_string(),
            timestamp: Utc::now(),
            sender: "alice".to_string(),
            text: Some("Hello".to_string()),
            is_from_me: false,
            is_sms: false,
            service: "iMessage".to_string(),
            handle_id: 1,
            conversation_id: Some(1),
            attachments: Vec::new(),
            subject: None,
            effect: None,
            reaction_type: None,
            reaction_message_id: None,
            is_deleted: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: IMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.guid, msg.guid);
    }
}
