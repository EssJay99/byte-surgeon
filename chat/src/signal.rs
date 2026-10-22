use std::path::Path;
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalMessage {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: Option<String>,
    pub message_type: SignalMessageType,
    pub is_outgoing: bool,
    pub thread_id: i64,
    pub is_encrypted: bool,
    pub is_read: bool,
    pub expires_in_ms: Option<i64>,
    pub attachment_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignalMessageType {
    Text,
    GroupAlert,
    ProfileChange,
    Call,
    Payment,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalContact {
    pub uuid: String,
    pub phone: Option<String>,
    pub display_name: Option<String>,
    pub profile_name: Option<String>,
    pub color: Option<String>,
    pub is_blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalGroup {
    pub group_id: Vec<u8>,
    pub title: String,
    pub members: Vec<String>,
    pub avatar_id: Option<String>,
    pub is_active: bool,
}

pub struct SignalParser;

impl SignalParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_database(&self, db_path: &Path) -> Result<Vec<SignalMessage>> {
        info!("Parsing Signal database at {:?}", db_path);
        let conn = Connection::open(db_path)?;
        let mut messages = Vec::new();

        let ios_schema = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='model_TSMessages'",
            [],
            |row| row.get::<_, i64>(0),
        ).unwrap_or(0) > 0;

        if ios_schema {
            messages.extend(self.parse_ios_database(&conn)?);
        } else {
            messages.extend(self.parse_android_database(&conn)?);
        }

        info!("Parsed {} Signal messages from database", messages.len());
        Ok(messages)
    }

    fn parse_ios_database(&self, conn: &Connection) -> Result<Vec<SignalMessage>> {
        let mut stmt = conn.prepare(
            "SELECT m.primaryKeyId, m.receivedAt, m.interactionType, m.isOutgoing, \
             m.body, m.isRead, m.expiresIn, m.threadId, m.attachmentId, \
             c.profileName \
             FROM model_TSMessages m \
             LEFT JOIN model_TSContacts c ON m.senderId = c.primaryKeyId \
             ORDER BY m.receivedAt"
        )?;

        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let timestamp_ms: Option<i64> = row.get(1)?;
            let interaction_type: Option<i64> = row.get(2)?;
            let is_outgoing_raw: Option<i64> = row.get(3)?;
            let body: Option<String> = row.get(4)?;
            let is_read_raw: Option<i64> = row.get(5)?;
            let expires_in: Option<i64> = row.get(6)?;
            let thread_id: i64 = row.get(7)?;
            let attachment_id: Option<i64> = row.get(8)?;
            let sender_name: Option<String> = row.get(9)?;

            let timestamp = timestamp_ms
                .and_then(|ms| DateTime::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32))
                .unwrap_or_default();

            let is_outgoing = is_outgoing_raw == Some(1);
            let is_read = is_read_raw == Some(1);

            let message_type = match interaction_type {
                Some(0) | None => SignalMessageType::Text,
                Some(1) => SignalMessageType::GroupAlert,
                Some(2) => SignalMessageType::ProfileChange,
                Some(3) => SignalMessageType::Call,
                Some(4) => SignalMessageType::Payment,
                _ => SignalMessageType::Unknown,
            };

            let attachment_path = attachment_id.map(|aid| format!("attachments/{}", aid));

            Ok(SignalMessage {
                id,
                timestamp,
                sender: if is_outgoing { "me".to_string() } else { "contact".to_string() },
                sender_name,
                content: body,
                message_type,
                is_outgoing,
                thread_id,
                is_encrypted: true,
                is_read,
                expires_in_ms: expires_in,
                attachment_path,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    fn parse_android_database(&self, conn: &Connection) -> Result<Vec<SignalMessage>> {
        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='message'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            return Ok(Vec::new());
        }

        let mut stmt = conn.prepare(
            "SELECT m._id, m.date_received, m.type, m.body, \
             m.mms, m.thread_id, m.read, m.expires_in, m.reactions \
             FROM message m \
             ORDER BY m.date_received"
        )?;

        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let timestamp_ms: i64 = row.get(1)?;
            let msg_type: Option<i64> = row.get(2)?;
            let body: Option<String> = row.get(3)?;
            let is_mms_raw: Option<i64> = row.get(4)?;
            let thread_id: i64 = row.get(5)?;
            let is_read_raw: Option<i64> = row.get(6)?;
            let expires_in: Option<i64> = row.get(7)?;
            let _reactions: Option<String> = row.get(8)?;

            let timestamp = DateTime::from_timestamp(timestamp_ms / 1000, 0).unwrap_or_default();
            let is_outgoing = msg_type == Some(20);
            let is_read = is_read_raw == Some(1);

            let message_type = match msg_type {
                Some(20) | Some(10) => SignalMessageType::Text,
                Some(30) => SignalMessageType::Call,
                Some(40) => SignalMessageType::GroupAlert,
                _ => SignalMessageType::Text,
            };

            let _is_mms = is_mms_raw == Some(1);

            Ok(SignalMessage {
                id,
                timestamp,
                sender: if is_outgoing { "me".to_string() } else { "contact".to_string() },
                sender_name: None,
                content: body,
                message_type,
                is_outgoing,
                thread_id,
                is_encrypted: true,
                is_read,
                expires_in_ms: expires_in,
                attachment_path: None,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    pub fn parse_contacts(&self, db_path: &Path) -> Result<Vec<SignalContact>> {
        info!("Parsing Signal contacts from {:?}", db_path);
        let conn = Connection::open(db_path)?;
        let mut contacts = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='model_TSContacts'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            warn!("Contacts table not found in iOS Signal database");
            return Ok(contacts);
        }

        let mut stmt = conn.prepare(
            "SELECT primaryKeyId, phone, displayName, profileName, color, isBlocked \
             FROM model_TSContacts"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(SignalContact {
                uuid: row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                phone: row.get(1)?,
                display_name: row.get(2)?,
                profile_name: row.get(3)?,
                color: row.get(4)?,
                is_blocked: row.get::<_, i64>(5)? != 0,
            })
        })?;

        for row in rows {
            contacts.push(row?);
        }

        info!("Parsed {} Signal contacts", contacts.len());
        Ok(contacts)
    }

    pub fn parse_groups(&self, db_path: &Path) -> Result<Vec<SignalGroup>> {
        info!("Parsing Signal groups from {:?}", db_path);
        let conn = Connection::open(db_path)?;
        let mut groups = Vec::new();

        let table_exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='groups'",
            [],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if !table_exists {
            let table_exists2: bool = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='model_TSGroups'",
                [],
                |row| row.get::<_, i64>(0),
            ).map(|c| c > 0)?;

            if table_exists2 {
                let mut stmt = conn.prepare(
                    "SELECT primaryKeyId, title, isActive FROM model_TSGroups"
                )?;
                let rows = stmt.query_map([], |row| {
                    let group_id_str: String = row.get(0)?;
                    Ok(SignalGroup {
                        group_id: group_id_str.into_bytes(),
                        title: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        members: Vec::new(),
                        avatar_id: None,
                        is_active: row.get::<_, i64>(2)? != 0,
                    })
                })?;
                for row in rows {
                    groups.push(row?);
                }
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT g.group_id, g.title, gm.recipient_id \
                 FROM groups g LEFT JOIN group_membership gm ON g.group_id = gm.group_id \
                 ORDER BY g.group_id"
            )?;
            let rows = stmt.query_map([], |row| {
                let group_id: Vec<u8> = row.get(0)?;
                let title: Option<String> = row.get(1)?;
                let member: Option<String> = row.get(2)?;
                Ok((group_id, title.unwrap_or_default(), member))
            })?;

            for row in rows {
                let (group_id, title, member) = row?;
                if let Some(existing) = groups.iter_mut().find(|g| g.group_id == group_id) {
                    if let Some(m) = member {
                        existing.members.push(m);
                    }
                } else {
                    groups.push(SignalGroup {
                        group_id: group_id.clone(),
                        title,
                        members: member.into_iter().collect(),
                        avatar_id: None,
                        is_active: true,
                    });
                }
            }
        }

        info!("Parsed {} Signal groups", groups.len());
        Ok(groups)
    }
}

impl Default for SignalParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use tempfile::TempDir;
    use std::path::PathBuf;

    fn create_test_signal_ios_db() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("signal.sqlite");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE model_TSContacts (primaryKeyId TEXT, phone TEXT, displayName TEXT, \
             profileName TEXT, color TEXT, isBlocked INTEGER);
             CREATE TABLE model_TSMessages (primaryKeyId INTEGER PRIMARY KEY, receivedAt INTEGER, \
             interactionType INTEGER, isOutgoing INTEGER, body TEXT, isRead INTEGER, \
             expiresIn INTEGER, threadId INTEGER, attachmentId INTEGER, senderId TEXT);
             CREATE TABLE model_TSGroups (primaryKeyId TEXT, title TEXT, isActive INTEGER);"
        ).unwrap();

        conn.execute(
            "INSERT INTO model_TSContacts VALUES ('uuid-001', '+1234567890', 'Alice', 'Alice P', 'blue', 0)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO model_TSMessages VALUES (1, 1700000000000, 0, 0, 'Hello Signal!', 1, 0, 1, NULL, 'uuid-001')",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO model_TSMessages VALUES (2, 1700000100000, 0, 1, 'Reply', 1, 5000, 1, 42, NULL)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO model_TSGroups VALUES ('group-001', 'Test Group', 1)",
            [],
        ).unwrap();

        (dir, db_path)
    }

    fn create_test_signal_android_db() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("signal.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "CREATE TABLE message (_id INTEGER PRIMARY KEY, date_received INTEGER, type INTEGER, \
             body TEXT, mms INTEGER, thread_id INTEGER, read INTEGER, expires_in INTEGER, \
             reactions TEXT);"
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (1, 1700000000000, 10, 'Android message', 0, 1, 1, 0, NULL)",
            [],
        ).unwrap();

        conn.execute(
            "INSERT INTO message VALUES (2, 1700000100000, 20, 'Outgoing reply', 0, 1, 1, 0, NULL)",
            [],
        ).unwrap();

        (dir, db_path)
    }

    #[test]
    fn test_parse_signal_ios() {
        let (dir, db_path) = create_test_signal_ios_db();
        let parser = SignalParser::new();
        let messages = parser.parse_database(&db_path).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, Some("Hello Signal!".to_string()));
        assert!(!messages[0].is_outgoing);
        assert!(messages[0].is_encrypted);
        assert!(messages[1].is_outgoing);
        assert_eq!(messages[1].expires_in_ms, Some(5000));
        assert_eq!(messages[1].attachment_path, Some("attachments/42".to_string()));
        drop(dir);
    }

    #[test]
    fn test_parse_signal_android() {
        let (dir, db_path) = create_test_signal_android_db();
        let parser = SignalParser::new();
        let messages = parser.parse_database(&db_path).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, Some("Android message".to_string()));
        assert!(!messages[0].is_outgoing);
        assert!(messages[1].is_outgoing);
        drop(dir);
    }

    #[test]
    fn test_parse_contacts() {
        let (dir, db_path) = create_test_signal_ios_db();
        let parser = SignalParser::new();
        let contacts = parser.parse_contacts(&db_path).unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].display_name, Some("Alice".to_string()));
        assert_eq!(contacts[0].phone, Some("+1234567890".to_string()));
        assert!(!contacts[0].is_blocked);
        drop(dir);
    }

    #[test]
    fn test_parse_groups() {
        let (dir, db_path) = create_test_signal_ios_db();
        let parser = SignalParser::new();
        let groups = parser.parse_groups(&db_path).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].title, "Test Group");
        assert!(groups[0].is_active);
        drop(dir);
    }

    #[test]
    fn test_default() {
        let _parser = SignalParser::default();
    }

    #[test]
    fn test_empty_database() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("empty.db");
        Connection::open(&db_path).unwrap();

        let parser = SignalParser::new();
        let messages = parser.parse_database(&db_path);
        assert!(messages.is_err() || messages.unwrap().is_empty());
        drop(dir);
    }

    #[test]
    fn test_message_serialization() {
        let msg = SignalMessage {
            id: 1,
            timestamp: Utc::now(),
            sender: "alice".to_string(),
            sender_name: Some("Alice".to_string()),
            content: Some("Hello".to_string()),
            message_type: SignalMessageType::Text,
            is_outgoing: false,
            thread_id: 1,
            is_encrypted: true,
            is_read: true,
            expires_in_ms: None,
            attachment_path: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: SignalMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.content, msg.content);
    }
}
