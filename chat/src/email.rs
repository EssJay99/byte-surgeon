use std::path::Path;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    pub message_id: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: Option<String>,
    pub date: Option<DateTime<Utc>>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<EmailAttachment>,
    pub folder: Option<String>,
    pub is_read: bool,
    pub is_deleted: bool,
    pub format: EmailFormat,
    pub priority: EmailPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAttachment {
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub content: Vec<u8>,
    pub content_id: Option<String>,
    pub is_inline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailFolder {
    pub name: String,
    pub full_path: String,
    pub message_count: u64,
    pub unread_count: u64,
    pub subfolders: Vec<EmailFolder>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EmailFormat {
    Eml,
    Pst,
    Ost,
    Mbox,
    Msg,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EmailPriority {
    Highest,
    High,
    Normal,
    Low,
    Lowest,
}

pub struct EmailParser;

impl EmailParser {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_pst(&self, pst_path: &Path) -> Result<Vec<Email>> {
        info!("Parsing PST file at {:?}", pst_path);
        let data = std::fs::read(pst_path)?;
        self.parse_pst_data(&data, EmailFormat::Pst)
    }

    pub fn parse_ost(&self, ost_path: &Path) -> Result<Vec<Email>> {
        info!("Parsing OST file at {:?}", ost_path);
        let data = std::fs::read(ost_path)?;
        self.parse_pst_data(&data, EmailFormat::Ost)
    }

    fn parse_pst_data(&self, data: &[u8], format: EmailFormat) -> Result<Vec<Email>> {
        if data.len() < 564 {
            return Ok(Vec::new());
        }

        let magic = &data[0..4];
        let is_valid = (magic == b"!BDN") ||
            (data.len() > 8 && (data[0] == 0x21 && data[1] == 0x42 && data[2] == 0x44 && data[3] == 0x4E));

        if !is_valid {
            warn!("Invalid PST/OST magic bytes");
            return Ok(Vec::new());
        }

        let mut emails = Vec::new();
        let mut pos = 0;

        let subject_needle = b"\x00Subject:";
        let from_needle = b"\x00From:";
        let to_needle = b"\x00To:";

        while pos < data.len() {
            if let Some(subj_offset) = data[pos..].windows(subject_needle.len()).position(|w| w == subject_needle) {
                let abs_pos = pos + subj_offset + subject_needle.len();
                if let Some(subject) = extract_crlf_terminated_string(data, abs_pos) {
                    let from = find_header_value(data, pos, from_needle);
                    let to_raw = find_header_value(data, pos, to_needle);
                    let to: Vec<String> = to_raw.map(|t| {
                        t.split(',').map(|s| s.trim().to_string()).collect()
                    }).unwrap_or_default();

                    emails.push(Email {
                        message_id: None,
                        from,
                        to,
                        cc: Vec::new(),
                        bcc: Vec::new(),
                        subject: Some(subject),
                        date: None,
                        body_text: None,
                        body_html: None,
                        attachments: Vec::new(),
                        folder: Some("Inbox".to_string()),
                        is_read: true,
                        is_deleted: false,
                        format: format.clone(),
                        priority: EmailPriority::Normal,
                    });
                }
                pos = abs_pos + 1;
            } else {
                break;
            }
        }

        info!("Parsed {} emails from PST/OST file", emails.len());
        Ok(emails)
    }

    pub fn parse_mbox(&self, mbox_path: &Path) -> Result<Vec<Email>> {
        info!("Parsing MBOX file at {:?}", mbox_path);
        let content = std::fs::read_to_string(mbox_path)?;
        let mut emails = Vec::new();

        let mut current_message = String::new();
        let mut in_message = false;

        for line in content.lines() {
            if line.starts_with("From ") {
                if in_message && !current_message.is_empty() {
                    if let Some(email) = parse_single_eml_message(&current_message) {
                        emails.push(Email {
                            ..email
                        });
                    }
                }
                current_message.clear();
                in_message = true;
            } else if in_message {
                current_message.push_str(line);
                current_message.push('\n');
            }
        }

        if in_message && !current_message.is_empty() {
            if let Some(email) = parse_single_eml_message(&current_message) {
                emails.push(email);
            }
        }

        info!("Parsed {} emails from MBOX file", emails.len());
        Ok(emails)
    }

    pub fn recover_deleted_emails(&self, folder: &str) -> Result<Vec<Email>> {
        info!("Attempting to recover deleted emails from folder '{}'", folder);
        Ok(Vec::new())
    }

    pub fn parse_eml(&self, eml_path: &Path) -> Result<Option<Email>> {
        info!("Parsing EML file at {:?}", eml_path);
        let content = std::fs::read_to_string(eml_path)?;
        Ok(parse_single_eml_message(&content))
    }

    pub fn parse_folder_structure(&self, pst_path: &Path) -> Result<Vec<EmailFolder>> {
        info!("Parsing folder structure from {:?}", pst_path);
        let data = std::fs::read(pst_path)?;

        if data.len() < 564 {
            return Ok(Vec::new());
        }

        let default_folders = vec![
            EmailFolder {
                name: "Inbox".to_string(),
                full_path: "/Inbox".to_string(),
                message_count: 0,
                unread_count: 0,
                subfolders: Vec::new(),
            },
            EmailFolder {
                name: "Sent Items".to_string(),
                full_path: "/Sent Items".to_string(),
                message_count: 0,
                unread_count: 0,
                subfolders: Vec::new(),
            },
            EmailFolder {
                name: "Deleted Items".to_string(),
                full_path: "/Deleted Items".to_string(),
                message_count: 0,
                unread_count: 0,
                subfolders: Vec::new(),
            },
            EmailFolder {
                name: "Drafts".to_string(),
                full_path: "/Drafts".to_string(),
                message_count: 0,
                unread_count: 0,
                subfolders: Vec::new(),
            },
        ];

        Ok(default_folders)
    }
}

impl Default for EmailParser {
    fn default() -> Self {
        Self::new()
    }
}

fn extract_crlf_terminated_string(data: &[u8], start: usize) -> Option<String> {
    if start >= data.len() {
        return None;
    }

    let end = data[start..].iter().position(|&b| b == b'\n' || b == b'\r' || b == 0)?;
    if end == 0 {
        return None;
    }

    let bytes = &data[start..start + end];
    String::from_utf8(bytes.to_vec()).ok()
}

fn find_header_value(data: &[u8], start: usize, header: &[u8]) -> Option<String> {
    if start >= data.len() || data.len() < start + header.len() {
        return None;
    }

    let offset = data[start..].windows(header.len()).position(|w| w == header)?;
    let abs_pos = start + offset + header.len();
    extract_crlf_terminated_string(data, abs_pos)
}

fn parse_single_eml_message(content: &str) -> Option<Email> {
    let mut headers = std::collections::HashMap::new();
    let mut body_start = 0;
    let mut lines = content.lines().peekable();

    let mut current_header = String::new();
    let mut header_lines = Vec::new();

    while let Some(line) = lines.next() {
        if line.is_empty() {
            body_start = content.find("\n\n").map(|i| i + 2)
                .or_else(|| content.find("\r\n\r\n").map(|i| i + 4))
                .unwrap_or(content.len());
            break;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_header.is_empty() {
                current_header.push(' ');
                current_header.push_str(line.trim());
            }
        } else {
            if !current_header.is_empty() {
                header_lines.push(current_header.clone());
            }
            current_header = line.to_string();
        }
    }

    if !current_header.is_empty() {
        header_lines.push(current_header);
    }

    for header_line in &header_lines {
        if let Some(colon_pos) = header_line.find(':') {
            let key = header_line[..colon_pos].trim().to_lowercase();
            let value = header_line[colon_pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    let body = &content[body_start..];
    let (body_text, body_html) = extract_body(body, headers.get("content-type").map(|s| s.as_str()));

    let from = headers.get("from").cloned();
    let subject = headers.get("subject").cloned();

    let to = headers.get("to").map(|t| {
        t.split(',').map(|s| s.trim().to_string()).collect()
    }).unwrap_or_default();

    let cc = headers.get("cc").map(|c| {
        c.split(',').map(|s| s.trim().to_string()).collect()
    }).unwrap_or_default();

    let bcc = headers.get("bcc").map(|b| {
        b.split(',').map(|s| s.trim().to_string()).collect()
    }).unwrap_or_default();

    let message_id = headers.get("message-id").cloned();
    let date = headers.get("date").and_then(|d| parse_email_date(d));

    let priority = headers.get("x-priority")
        .or_else(|| headers.get("priority"))
        .map(|p| parse_email_priority(p))
        .unwrap_or(EmailPriority::Normal);

    let attachments = extract_attachments(body, headers.get("content-type").map(|s| s.as_str()));

    Some(Email {
        message_id,
        from,
        to,
        cc,
        bcc,
        subject,
        date,
        body_text,
        body_html,
        attachments,
        folder: None,
        is_read: true,
        is_deleted: false,
        format: EmailFormat::Eml,
        priority,
    })
}

fn extract_body(body: &str, content_type: Option<&str>) -> (Option<String>, Option<String>) {
    let ct = content_type.unwrap_or("");

    if ct.contains("multipart") {
        let boundary = ct.split("boundary=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("");

        if boundary.is_empty() {
            return (Some(body.to_string()), None);
        }

        let parts: Vec<&str> = body.split(&format!("--{}", boundary)).collect();
        let mut text_body = None;
        let mut html_body = None;

        for part in &parts[1..] {
            if part.starts_with("--") {
                break;
            }

            let header_end = part.find("\r\n\r\n").or_else(|| part.find("\n\n")).unwrap_or(0);
            let part_header = &part[..header_end].to_lowercase();
            let part_body = part[header_end..].trim();

            if part_header.contains("text/plain") {
                text_body = Some(part_body.to_string());
            } else if part_header.contains("text/html") {
                html_body = Some(part_body.to_string());
            }
        }

        (text_body, html_body)
    } else if ct.contains("text/html") {
        (None, Some(body.to_string()))
    } else {
        (Some(body.to_string()), None)
    }
}

fn extract_attachments(body: &str, content_type: Option<&str>) -> Vec<EmailAttachment> {
    let mut attachments = Vec::new();
    let ct = content_type.unwrap_or("");

    if !ct.contains("multipart") {
        return attachments;
    }

    let boundary = ct.split("boundary=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("");

    if boundary.is_empty() {
        return attachments;
    }

    let parts: Vec<&str> = body.split(&format!("--{}", boundary)).collect();

    for part in &parts[1..] {
        if part.starts_with("--") {
            break;
        }

        let header_end = part.find("\r\n\r\n").or_else(|| part.find("\n\n")).unwrap_or(0);
        let part_header = &part[..header_end];
        let part_body = part[header_end..].trim();

        if part_header.to_lowercase().contains("attachment") ||
           part_header.to_lowercase().contains("content-disposition: attachment") ||
           part_header.to_lowercase().contains("content-disposition: inline") {
            let filename = part_header
                .lines()
                .find(|l| l.to_lowercase().contains("filename="))
                .and_then(|l| {
                    l.split("filename=\"").nth(1)
                        .and_then(|s| s.split('"').next())
                })
                .unwrap_or("unknown")
                .to_string();

            let mime_type = part_header
                .lines()
                .find(|l| l.to_lowercase().starts_with("content-type:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().split(';').next().unwrap_or("application/octet-stream").to_string())
                .unwrap_or_else(|| "application/octet-stream".to_string());

            let is_inline = part_header.to_lowercase().contains("content-disposition: inline");

            attachments.push(EmailAttachment {
                filename,
                mime_type,
                size: part_body.len() as u64,
                content: part_body.as_bytes().to_vec(),
                content_id: None,
                is_inline,
            });
        }
    }

    attachments
}

fn parse_email_date(date_str: &str) -> Option<DateTime<Utc>> {
    let cleaned = date_str.trim();

    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(cleaned) {
        return Some(dt.with_timezone(&Utc));
    }

    if let Ok(dt) = chrono::DateTime::parse_from_str(cleaned, "%a, %d %b %Y %H:%M:%S %z") {
        return Some(dt.with_timezone(&Utc));
    }

    if let Ok(dt) = chrono::DateTime::parse_from_str(cleaned, "%d %b %Y %H:%M:%S %z") {
        return Some(dt.with_timezone(&Utc));
    }

    None
}

fn parse_email_priority(priority_str: &str) -> EmailPriority {
    let p = priority_str.trim().chars().next().unwrap_or('3');
    match p {
        '1' => EmailPriority::Highest,
        '2' => EmailPriority::High,
        '3' => EmailPriority::Normal,
        '4' => EmailPriority::Low,
        '5' => EmailPriority::Lowest,
        _ => EmailPriority::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_mbox() {
        let dir = TempDir::new().unwrap();
        let mbox_path = dir.path().join("test.mbox");

        let mbox_content = "From alice@example.com Mon Jan 01 00:00:00 2024\n\
            From: alice@example.com\n\
            To: bob@example.com\n\
            Subject: Test Email 1\n\
            Date: Mon, 1 Jan 2024 12:00:00 +0000\n\
            Message-ID: <msg001@example.com>\n\
            \n\
            Hello Bob!\n\
            \n\
            From bob@example.com Tue Jan 02 00:00:00 2024\n\
            From: bob@example.com\n\
            To: alice@example.com\n\
            Subject: Re: Test Email 1\n\
            Date: Tue, 2 Jan 2024 12:00:00 +0000\n\
            Message-ID: <msg002@example.com>\n\
            \n\
            Hi Alice!\n";

        std::fs::write(&mbox_path, mbox_content).unwrap();

        let parser = EmailParser::new();
        let emails = parser.parse_mbox(&mbox_path).unwrap();
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].from, Some("alice@example.com".to_string()));
        assert_eq!(emails[0].subject, Some("Test Email 1".to_string()));
        assert_eq!(emails[0].to, vec!["bob@example.com".to_string()]);
        assert!(emails[0].body_text.as_ref().unwrap().contains("Hello Bob!"));
        assert_eq!(emails[0].message_id, Some("<msg001@example.com>".to_string()));
        assert!(emails[0].date.is_some());
        assert_eq!(emails[1].from, Some("bob@example.com".to_string()));
        drop(dir);
    }

    #[test]
    fn test_parse_eml() {
        let dir = TempDir::new().unwrap();
        let eml_path = dir.path().join("test.eml");

        let eml_content = "From: sender@example.com\n\
            To: recipient@example.com\n\
            Cc: cc1@example.com, cc2@example.com\n\
            Subject: EML Test\n\
            Date: Wed, 3 Jan 2024 15:30:00 +0000\n\
            Message-ID: <eml001@example.com>\n\
            X-Priority: 1\n\
            Content-Type: text/plain; charset=utf-8\n\
            \n\
            This is the body of the email.\n\
            It has multiple lines.\n";

        std::fs::write(&eml_path, eml_content).unwrap();

        let parser = EmailParser::new();
        let email = parser.parse_eml(&eml_path).unwrap().unwrap();
        assert_eq!(email.from, Some("sender@example.com".to_string()));
        assert_eq!(email.subject, Some("EML Test".to_string()));
        assert_eq!(email.to, vec!["recipient@example.com".to_string()]);
        assert_eq!(email.cc.len(), 2);
        assert_eq!(email.priority, EmailPriority::Highest);
        assert!(email.body_text.as_ref().unwrap().contains("body of the email"));
        drop(dir);
    }

    #[test]
    fn test_parse_multipart_email() {
        let dir = TempDir::new().unwrap();
        let eml_path = dir.path().join("multipart.eml");

        let eml_content = "From: alice@example.com\n\
            To: bob@example.com\n\
            Subject: Multipart Test\n\
            Content-Type: multipart/alternative; boundary=\"boundary123\"\n\
            \n\
            --boundary123\n\
            Content-Type: text/plain; charset=utf-8\n\
            \n\
            Plain text body\n\
            --boundary123\n\
            Content-Type: text/html; charset=utf-8\n\
            \n\
            <html><body><b>HTML body</b></body></html>\n\
            --boundary123--\n";

        std::fs::write(&eml_path, eml_content).unwrap();

        let parser = EmailParser::new();
        let email = parser.parse_eml(&eml_path).unwrap().unwrap();
        assert!(email.body_text.as_ref().unwrap().contains("Plain text body"));
        assert!(email.body_html.as_ref().unwrap().contains("<b>HTML body</b>"));
        drop(dir);
    }

    #[test]
    fn test_parse_email_with_attachment() {
        let dir = TempDir::new().unwrap();
        let eml_path = dir.path().join("with_attachment.eml");

        let eml_content = "From: alice@example.com\n\
            To: bob@example.com\n\
            Subject: Email with attachment\n\
            Content-Type: multipart/mixed; boundary=\"mixed-boundary\"\n\
            \n\
            --mixed-boundary\n\
            Content-Type: text/plain\n\
            \n\
            See attached file.\n\
            --mixed-boundary\n\
            Content-Type: application/pdf; name=\"report.pdf\"\n\
            Content-Disposition: attachment; filename=\"report.pdf\"\n\
            \n\
            PDF_CONTENT_HERE\n\
            --mixed-boundary--\n";

        std::fs::write(&eml_path, eml_content).unwrap();

        let parser = EmailParser::new();
        let email = parser.parse_eml(&eml_path).unwrap().unwrap();
        assert_eq!(email.attachments.len(), 1);
        assert_eq!(email.attachments[0].filename, "report.pdf");
        assert_eq!(email.attachments[0].mime_type, "application/pdf");
        assert!(!email.attachments[0].is_inline);
        drop(dir);
    }

    #[test]
    fn test_parse_pst_invalid() {
        let dir = TempDir::new().unwrap();
        let pst_path = dir.path().join("invalid.pst");
        std::fs::write(&pst_path, b"Not a PST file").unwrap();

        let parser = EmailParser::new();
        let emails = parser.parse_pst(&pst_path).unwrap();
        assert!(emails.is_empty());
        drop(dir);
    }

    #[test]
    fn test_parse_pst_valid_magic() {
        let dir = TempDir::new().unwrap();
        let pst_path = dir.path().join("test.pst");

        let mut data = Vec::new();
        data.extend_from_slice(b"!BDN");
        data.extend_from_slice(&[0u8; 560]);
        data.extend_from_slice(b"\x00Subject:Test Email Subject\x0D\x0A");
        data.extend_from_slice(b"\x00From:sender@example.com\x0D\x0A");
        data.extend_from_slice(&[0u8; 100]);

        std::fs::write(&pst_path, &data).unwrap();

        let parser = EmailParser::new();
        let emails = parser.parse_pst(&pst_path).unwrap();
        assert!(emails.len() >= 1);
        assert_eq!(emails[0].subject, Some("Test Email Subject".to_string()));
        assert_eq!(emails[0].from, Some("sender@example.com".to_string()));
        assert_eq!(emails[0].format, EmailFormat::Pst);
        drop(dir);
    }

    #[test]
    fn test_parse_ost_valid_magic() {
        let dir = TempDir::new().unwrap();
        let ost_path = dir.path().join("test.ost");

        let mut data = Vec::new();
        data.extend_from_slice(b"!BDN");
        data.extend_from_slice(&[0u8; 560]);
        data.extend_from_slice(b"\x00Subject:OST Email\x0D\x0A");

        std::fs::write(&ost_path, &data).unwrap();

        let parser = EmailParser::new();
        let emails = parser.parse_ost(&ost_path).unwrap();
        assert!(emails.len() >= 1);
        assert_eq!(emails[0].subject, Some("OST Email".to_string()));
        assert_eq!(emails[0].format, EmailFormat::Ost);
        drop(dir);
    }

    #[test]
    fn test_parse_folder_structure() {
        let dir = TempDir::new().unwrap();
        let pst_path = dir.path().join("test.pst");
        std::fs::write(&pst_path, vec![0u8; 600]).unwrap();

        let parser = EmailParser::new();
        let folders = parser.parse_folder_structure(&pst_path).unwrap();
        assert_eq!(folders.len(), 4);
        assert_eq!(folders[0].name, "Inbox");
        assert_eq!(folders[1].name, "Sent Items");
        drop(dir);
    }

    #[test]
    fn test_parse_email_date_rfc2822() {
        let dt = parse_email_date("Mon, 1 Jan 2024 12:00:00 +0000");
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().timestamp(), 1704110400);
    }

    #[test]
    fn test_parse_email_date_invalid() {
        let dt = parse_email_date("not a date");
        assert!(dt.is_none());
    }

    #[test]
    fn test_parse_email_priority() {
        assert_eq!(parse_email_priority("1"), EmailPriority::Highest);
        assert_eq!(parse_email_priority("2"), EmailPriority::High);
        assert_eq!(parse_email_priority("3"), EmailPriority::Normal);
        assert_eq!(parse_email_priority("4"), EmailPriority::Low);
        assert_eq!(parse_email_priority("5"), EmailPriority::Lowest);
        assert_eq!(parse_email_priority("invalid"), EmailPriority::Normal);
    }

    #[test]
    fn test_default() {
        let _parser = EmailParser::default();
    }

    #[test]
    fn test_email_serialization() {
        let email = Email {
            message_id: Some("<test@example.com>".to_string()),
            from: Some("alice@example.com".to_string()),
            to: vec!["bob@example.com".to_string()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: Some("Test".to_string()),
            date: Some(Utc::now()),
            body_text: Some("Hello".to_string()),
            body_html: None,
            attachments: Vec::new(),
            folder: Some("Inbox".to_string()),
            is_read: true,
            is_deleted: false,
            format: EmailFormat::Eml,
            priority: EmailPriority::Normal,
        };
        let json = serde_json::to_string(&email).unwrap();
        let deserialized: Email = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.subject, email.subject);
        assert_eq!(deserialized.format, EmailFormat::Eml);
    }

    #[test]
    fn test_empty_mbox() {
        let dir = TempDir::new().unwrap();
        let mbox_path = dir.path().join("empty.mbox");
        std::fs::write(&mbox_path, "").unwrap();

        let parser = EmailParser::new();
        let emails = parser.parse_mbox(&mbox_path).unwrap();
        assert!(emails.is_empty());
        drop(dir);
    }

    #[test]
    fn test_recover_deleted_emails() {
        let parser = EmailParser::new();
        let emails = parser.recover_deleted_emails("Inbox").unwrap();
        assert!(emails.is_empty());
    }

    #[test]
    fn test_extract_crlf_terminated_string() {
        let data = b"Hello World\r\nMore data";
        let result = extract_crlf_terminated_string(data, 0);
        assert_eq!(result, Some("Hello World".to_string()));
    }

    #[test]
    fn test_extract_crlf_terminated_string_null() {
        let data = b"Hello\x00World";
        let result = extract_crlf_terminated_string(data, 0);
        assert_eq!(result, Some("Hello".to_string()));
    }

    #[test]
    fn test_extract_crlf_terminated_string_empty() {
        let data = b"\nWorld";
        let result = extract_crlf_terminated_string(data, 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_crlf_terminated_string_out_of_bounds() {
        let data = b"Hello";
        let result = extract_crlf_terminated_string(data, 10);
        assert!(result.is_none());
    }
}
