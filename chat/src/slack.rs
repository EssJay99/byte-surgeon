use std::path::Path;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackMessage {
    pub ts: String,
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub bot_id: Option<String>,
    pub text: String,
    pub channel: String,
    pub channel_type: SlackChannelType,
    pub thread_ts: Option<String>,
    pub reply_count: Option<u64>,
    pub files: Vec<SlackFile>,
    pub reactions: Vec<SlackReaction>,
    pub subtype: Option<String>,
    pub is_deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlackChannelType {
    PublicChannel,
    PrivateChannel,
    DirectMessage,
    MultiPartyDirectMessage,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackFile {
    pub id: String,
    pub name: Option<String>,
    pub title: Option<String>,
    pub mimetype: Option<String>,
    pub filetype: Option<String>,
    pub size: u64,
    pub url_private: Option<String>,
    pub permalink: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackReaction {
    pub name: String,
    pub users: Vec<String>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackChannel {
    pub id: String,
    pub name: Option<String>,
    pub is_channel: bool,
    pub is_private: bool,
    pub is_im: bool,
    pub is_mpim: bool,
    pub topic: Option<String>,
    pub purpose: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub message_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackUser {
    pub id: String,
    pub name: Option<String>,
    pub real_name: Option<String>,
    pub email: Option<String>,
    pub title: Option<String>,
    pub is_bot: bool,
    pub deleted: bool,
}

pub struct SlackParser;

impl SlackParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_export(&self, export_dir: &Path) -> Result<Vec<SlackMessage>> {
        info!("Parsing Slack export from {:?}", export_dir);

        let users = self.parse_users(export_dir)?;
        let channels = self.parse_channels(export_dir)?;

        let mut all_messages = Vec::new();

        for channel in &channels {
            let channel_path = export_dir.join(channel.name.as_deref().unwrap_or(&channel.id));
            if !channel_path.is_dir() {
                continue;
            }

            let messages = self.parse_channel_messages(&channel_path, &channel.id, &channel.channel_type(), &users)?;
            all_messages.extend(messages);
        }

        all_messages.sort_by(|a, b| a.ts.cmp(&b.ts));

        info!("Parsed {} total Slack messages", all_messages.len());
        Ok(all_messages)
    }

    fn parse_channel_messages(
        &self,
        channel_dir: &Path,
        channel_id: &str,
        channel_type: &SlackChannelType,
        users: &[SlackUser],
    ) -> Result<Vec<SlackMessage>> {
        let mut messages = Vec::new();

        let mut json_files: Vec<_> = std::fs::read_dir(channel_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
            .collect();
        json_files.sort_by_key(|e| e.file_name());

        for entry in json_files {
            let file_content = std::fs::read_to_string(entry.path())?;
            let raw_messages: Vec<RawSlackMessage> = match serde_json::from_str(&file_content) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Failed to parse {:?}: {}", entry.path(), e);
                    continue;
                }
            };

            for raw in raw_messages {
                let ts_f64: f64 = raw.ts.parse().unwrap_or(0.0);
                let timestamp = DateTime::from_timestamp(ts_f64 as i64, ((ts_f64.fract()) * 1_000_000_000.0) as u32)
                    .unwrap_or_default();

                let user = if let Some(user_id) = &raw.user {
                    users.iter()
                        .find(|u| &u.id == user_id)
                        .and_then(|u| u.real_name.as_ref().or(u.name.as_ref()))
                        .cloned()
                        .unwrap_or_else(|| user_id.clone())
                } else if let Some(bot_id) = &raw.bot_id {
                    format!("bot:{}", bot_id)
                } else {
                    "unknown".to_string()
                };

                let text = if let Some(ref subtype) = raw.subtype {
                    match subtype.as_str() {
                        "channel_join" => format!("<@{}> joined the channel", raw.user.as_deref().unwrap_or("unknown")),
                        "channel_leave" => format!("<@{}> left the channel", raw.user.as_deref().unwrap_or("unknown")),
                        "channel_purpose" => raw.text.clone().unwrap_or_else(|| "set channel purpose".to_string()),
                        "channel_topic" => raw.text.clone().unwrap_or_else(|| "set channel topic".to_string()),
                        "message_deleted" => String::new(),
                        _ => raw.text.clone().unwrap_or_default(),
                    }
                } else {
                    raw.text.clone().unwrap_or_default()
                };

                let files = raw.files.unwrap_or_default().into_iter().map(|f| {
                    SlackFile {
                        id: f.id.unwrap_or_default(),
                        name: f.name,
                        title: f.title,
                        mimetype: f.mimetype,
                        filetype: f.filetype,
                        size: f.size.unwrap_or(0),
                        url_private: f.url_private,
                        permalink: f.permalink,
                    }
                }).collect();

                let reactions = raw.reactions.unwrap_or_default().into_iter().map(|r| {
                    SlackReaction {
                        name: r.name,
                        users: r.users.unwrap_or_default(),
                        count: r.count.unwrap_or(0),
                    }
                }).collect();

                let is_deleted = raw.subtype.as_deref() == Some("message_deleted");

                messages.push(SlackMessage {
                    ts: raw.ts,
                    timestamp,
                    user,
                    bot_id: raw.bot_id,
                    text,
                    channel: channel_id.to_string(),
                    channel_type: channel_type.clone(),
                    thread_ts: raw.thread_ts,
                    reply_count: raw.reply_count,
                    files,
                    reactions,
                    subtype: raw.subtype,
                    is_deleted,
                });
            }
        }

        Ok(messages)
    }

    pub fn parse_users(&self, export_dir: &Path) -> Result<Vec<SlackUser>> {
        let users_path = export_dir.join("users.json");
        if !users_path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&users_path)?;
        let raw_users: Vec<RawSlackUser> = serde_json::from_str(&content)?;

        let users: Vec<SlackUser> = raw_users.into_iter().map(|u| {
            let email = u.profile.as_ref().and_then(|p| p.email.clone());
            let title = u.profile.as_ref().and_then(|p| p.title.clone());
            SlackUser {
                id: u.id,
                name: u.name,
                real_name: u.real_name,
                email,
                title,
                is_bot: u.is_bot.unwrap_or(false),
                deleted: u.deleted.unwrap_or(false),
            }
        }).collect();

        info!("Parsed {} Slack users", users.len());
        Ok(users)
    }

    pub fn parse_channels(&self, export_dir: &Path) -> Result<Vec<SlackChannel>> {
        let channels_path = export_dir.join("channels.json");
        let dms_path = export_dir.join("dms.json");
        let mpims_path = export_dir.join("mpims.json");
        let groups_path = export_dir.join("groups.json");

        let mut channels = Vec::new();

        if channels_path.exists() {
            let content = std::fs::read_to_string(&channels_path)?;
            let raw: Vec<RawSlackChannel> = serde_json::from_str(&content)?;
            for c in raw {
                channels.push(SlackChannel {
                    id: c.id,
                    name: c.name,
                    is_channel: true,
                    is_private: c.is_private.unwrap_or(false),
                    is_im: false,
                    is_mpim: false,
                    topic: c.topic.and_then(|t| t.value),
                    purpose: c.purpose.and_then(|p| p.value),
                    created: c.created.and_then(|ts| DateTime::from_timestamp(ts, 0)),
                    message_count: 0,
                });
            }
        }

        if groups_path.exists() {
            let content = std::fs::read_to_string(&groups_path)?;
            let raw: Vec<RawSlackChannel> = serde_json::from_str(&content)?;
            for c in raw {
                channels.push(SlackChannel {
                    id: c.id,
                    name: c.name,
                    is_channel: false,
                    is_private: true,
                    is_im: false,
                    is_mpim: false,
                    topic: c.topic.and_then(|t| t.value),
                    purpose: c.purpose.and_then(|p| p.value),
                    created: c.created.and_then(|ts| DateTime::from_timestamp(ts, 0)),
                    message_count: 0,
                });
            }
        }

        if dms_path.exists() {
            let content = std::fs::read_to_string(&dms_path)?;
            let raw: Vec<RawSlackDm> = serde_json::from_str(&content)?;
            for dm in raw {
                channels.push(SlackChannel {
                    id: dm.id,
                    name: None,
                    is_channel: false,
                    is_private: true,
                    is_im: true,
                    is_mpim: false,
                    topic: None,
                    purpose: None,
                    created: None,
                    message_count: 0,
                });
            }
        }

        if mpims_path.exists() {
            let content = std::fs::read_to_string(&mpims_path)?;
            let raw: Vec<RawSlackDm> = serde_json::from_str(&content)?;
            for dm in raw {
                channels.push(SlackChannel {
                    id: dm.id,
                    name: None,
                    is_channel: false,
                    is_private: true,
                    is_im: false,
                    is_mpim: true,
                    topic: None,
                    purpose: None,
                    created: None,
                    message_count: 0,
                });
            }
        }

        info!("Parsed {} Slack channels", channels.len());
        Ok(channels)
    }
}

impl Default for SlackParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SlackChannel {
    pub fn channel_type(&self) -> SlackChannelType {
        if self.is_im {
            SlackChannelType::DirectMessage
        } else if self.is_mpim {
            SlackChannelType::MultiPartyDirectMessage
        } else if self.is_private {
            SlackChannelType::PrivateChannel
        } else if self.is_channel {
            SlackChannelType::PublicChannel
        } else {
            SlackChannelType::Unknown
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawSlackMessage {
    ts: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    bot_id: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    thread_ts: Option<String>,
    #[serde(default)]
    reply_count: Option<u64>,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default)]
    files: Option<Vec<RawSlackFile>>,
    #[serde(default)]
    reactions: Option<Vec<RawSlackReaction>>,
}

#[derive(Debug, Deserialize)]
struct RawSlackFile {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    mimetype: Option<String>,
    #[serde(default)]
    filetype: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    url_private: Option<String>,
    #[serde(default)]
    permalink: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSlackReaction {
    name: String,
    #[serde(default)]
    users: Option<Vec<String>>,
    #[serde(default)]
    count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawSlackUser {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    real_name: Option<String>,
    #[serde(default)]
    is_bot: Option<bool>,
    #[serde(default)]
    deleted: Option<bool>,
    #[serde(default)]
    profile: Option<RawSlackProfile>,
}

#[derive(Debug, Deserialize)]
struct RawSlackProfile {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSlackChannel {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    is_private: Option<bool>,
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    topic: Option<RawSlackTopic>,
    #[serde(default)]
    purpose: Option<RawSlackTopic>,
}

#[derive(Debug, Deserialize)]
struct RawSlackTopic {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawSlackDm {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_slack_export() -> TempDir {
        let dir = TempDir::new().unwrap();

        let users = r#"[
            {"id": "U001", "name": "alice", "real_name": "Alice Smith", "is_bot": false, "deleted": false,
             "profile": {"email": "alice@example.com", "title": "Engineer"}},
            {"id": "U002", "name": "bob", "real_name": "Bob Jones", "is_bot": false, "deleted": false,
             "profile": {"email": "bob@example.com", "title": null}}
        ]"#;
        std::fs::write(dir.path().join("users.json"), users).unwrap();

        let channels = r#"[
            {"id": "C001", "name": "general", "is_private": false, "created": 1600000000,
             "topic": {"value": "General chat"}, "purpose": {"value": "Company-wide channel"}},
            {"id": "C002", "name": "random", "is_private": false, "created": 1600000100,
             "topic": {"value": "Random"}, "purpose": {"value": "Random stuff"}}
        ]"#;
        std::fs::write(dir.path().join("channels.json"), channels).unwrap();

        let dms = r#"[{"id": "D001"}]"#;
        std::fs::write(dir.path().join("dms.json"), dms).unwrap();

        let channel_dir = dir.path().join("general");
        std::fs::create_dir(&channel_dir).unwrap();

        let day1 = r#"[
            {"ts": "1700000000.000100", "user": "U001", "text": "Hello everyone!", "reactions": [{"name": "wave", "users": ["U002"], "count": 1}]},
            {"ts": "1700000100.000200", "user": "U002", "text": "Hi Alice!", "thread_ts": "1700000000.000100", "reply_count": 1}
        ]"#;
        std::fs::write(channel_dir.join("2024-01-01.json"), day1).unwrap();

        let day2 = r#"[
            {"ts": "1700100000.000300", "user": "U001", "text": "Check out this file",
             "files": [{"id": "F001", "name": "report.pdf", "title": "Report", "mimetype": "application/pdf", "filetype": "pdf", "size": 50000, "url_private": "https://example.com/report.pdf", "permalink": "https://example.com/perma/report"}]},
            {"ts": "1700100100.000400", "subtype": "channel_join", "user": "U002", "text": ""}
        ]"#;
        std::fs::write(channel_dir.join("2024-01-02.json"), day2).unwrap();

        dir
    }

    #[test]
    fn test_parse_users() {
        let dir = create_test_slack_export();
        let parser = SlackParser::new();
        let users = parser.parse_users(dir.path()).unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].name, Some("alice".to_string()));
        assert_eq!(users[0].real_name, Some("Alice Smith".to_string()));
        assert_eq!(users[0].email, Some("alice@example.com".to_string()));
        assert!(!users[0].is_bot);
        drop(dir);
    }

    #[test]
    fn test_parse_channels() {
        let dir = create_test_slack_export();
        let parser = SlackParser::new();
        let channels = parser.parse_channels(dir.path()).unwrap();
        assert_eq!(channels.len(), 3);
        assert_eq!(channels[0].name, Some("general".to_string()));
        assert!(channels[0].is_channel);
        assert!(!channels[0].is_private);
        assert_eq!(channels[0].topic, Some("General chat".to_string()));
        assert!(channels[2].is_im);
        drop(dir);
    }

    #[test]
    fn test_parse_export() {
        let dir = create_test_slack_export();
        let parser = SlackParser::new();
        let messages = parser.parse_export(dir.path()).unwrap();
        assert_eq!(messages.len(), 4);

        assert_eq!(messages[0].text, "Hello everyone!");
        assert_eq!(messages[0].user, "Alice Smith");
        assert_eq!(messages[0].reactions.len(), 1);
        assert_eq!(messages[0].reactions[0].name, "wave");

        assert_eq!(messages[1].thread_ts, Some("1700000000.000100".to_string()));
        assert_eq!(messages[1].text, "Hi Alice!");

        assert_eq!(messages[2].files.len(), 1);
        assert_eq!(messages[2].files[0].name, Some("report.pdf".to_string()));
        assert_eq!(messages[2].files[0].size, 50000);

        assert!(messages[3].text.contains("joined the channel"));
        drop(dir);
    }

    #[test]
    fn test_channel_type() {
        let ch = SlackChannel {
            id: "C001".to_string(),
            name: Some("general".to_string()),
            is_channel: true,
            is_private: false,
            is_im: false,
            is_mpim: false,
            topic: None,
            purpose: None,
            created: None,
            message_count: 0,
        };
        assert_eq!(ch.channel_type(), SlackChannelType::PublicChannel);

        let dm = SlackChannel {
            id: "D001".to_string(),
            name: None,
            is_channel: false,
            is_private: true,
            is_im: true,
            is_mpim: false,
            topic: None,
            purpose: None,
            created: None,
            message_count: 0,
        };
        assert_eq!(dm.channel_type(), SlackChannelType::DirectMessage);
    }

    #[test]
    fn test_default() {
        let _parser = SlackParser::default();
    }

    #[test]
    fn test_empty_export() {
        let dir = TempDir::new().unwrap();
        let parser = SlackParser::new();
        let messages = parser.parse_export(dir.path()).unwrap();
        assert!(messages.is_empty());
        drop(dir);
    }

    #[test]
    fn test_message_serialization() {
        let msg = SlackMessage {
            ts: "1700000000.000100".to_string(),
            timestamp: Utc::now(),
            user: "alice".to_string(),
            bot_id: None,
            text: "Hello".to_string(),
            channel: "C001".to_string(),
            channel_type: SlackChannelType::PublicChannel,
            thread_ts: None,
            reply_count: None,
            files: Vec::new(),
            reactions: Vec::new(),
            subtype: None,
            is_deleted: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: SlackMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.text, msg.text);
    }
}
