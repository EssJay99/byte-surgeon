use crate::{Result, RecoveredFile, RecoverySession};
use crate::error::Error;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    Created,
    Modified,
    Accessed,
    Deleted,
    Renamed,
    Moved,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Created => write!(f, "Created"),
            EventType::Modified => write!(f, "Modified"),
            EventType::Accessed => write!(f, "Accessed"),
            EventType::Deleted => write!(f, "Deleted"),
            EventType::Renamed => write!(f, "Renamed"),
            EventType::Moved => write!(f, "Moved"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub file_path: String,
    pub metadata: HashMap<String, String>,
}

impl TimelineEvent {
    pub fn new(timestamp: DateTime<Utc>, event_type: EventType, file_path: String) -> Self {
        Self {
            timestamp,
            event_type,
            file_path,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

pub struct TimelineBuilder {
    events: Vec<TimelineEvent>,
}

impl TimelineBuilder {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: TimelineEvent) -> &mut Self {
        self.events.push(event);
        self
    }

    pub fn add_events(&mut self, events: impl IntoIterator<Item = TimelineEvent>) -> &mut Self {
        self.events.extend(events);
        self
    }

    pub fn build(mut self) -> Timeline {
        self.events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Timeline {
            events: self.events,
        }
    }
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub events: Vec<TimelineEvent>,
}

impl Timeline {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn query_by_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    pub fn query_by_type(&self, event_type: &EventType) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .collect()
    }

    pub fn query_by_path_prefix(&self, prefix: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.file_path.starts_with(prefix))
            .collect()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn time_range(&self) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        if self.events.is_empty() {
            return None;
        }
        Some((self.events.first().unwrap().timestamp, self.events.last().unwrap().timestamp))
    }

    pub fn event_type_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for event in &self.events {
            *counts.entry(event.event_type.to_string()).or_insert(0) += 1;
        }
        counts
    }

    pub fn export_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.events).map_err(|e| Error::Other(e.to_string()))
    }

    pub fn from_recovered_files(files: &[RecoveredFile]) -> Self {
        let mut builder = TimelineBuilder::new();

        for file in files {
            if let Some(ref meta) = file.metadata {
                if let Some(created) = meta.created {
                    builder.add_event(
                        TimelineEvent::new(created, EventType::Created, file.recovered_path.clone())
                            .with_metadata("id", &file.id)
                            .with_metadata("size", file.file_size.to_string()),
                    );
                }
                if let Some(modified) = meta.modified {
                    builder.add_event(
                        TimelineEvent::new(modified, EventType::Modified, file.recovered_path.clone())
                            .with_metadata("id", &file.id)
                            .with_metadata("type", &file.file_type),
                    );
                }
                if let Some(accessed) = meta.accessed {
                    builder.add_event(
                        TimelineEvent::new(accessed, EventType::Accessed, file.recovered_path.clone())
                            .with_metadata("id", &file.id),
                    );
                }
            }

            builder.add_event(
                TimelineEvent::new(
                    file.recovered_at,
                    EventType::Created,
                    file.recovered_path.clone(),
                )
                .with_metadata("recovery_id", &file.id)
                .with_metadata("status", format!("{:?}", file.status))
                .with_metadata("source", "recovery_operation"),
            );
        }

        builder.build()
    }

    pub fn from_recovery_session(session: &RecoverySession, files: &[RecoveredFile]) -> Self {
        let mut builder = TimelineBuilder::new();

        builder.add_event(
            TimelineEvent::new(
                session.started_at,
                EventType::Created,
                format!("session:{}", session.id),
            )
            .with_metadata("device", &session.device_info.name)
            .with_metadata("scan_type", format!("{:?}", session.scan_type))
            .with_metadata("source", "recovery_session"),
        );

        let file_timeline = Self::from_recovered_files(files);
        builder.add_events(file_timeline.events);

        if let Some(completed_at) = session.completed_at {
            builder.add_event(
                TimelineEvent::new(
                    completed_at,
                    EventType::Modified,
                    format!("session:{}", session.id),
                )
                .with_metadata("status", format!("{:?}", session.status))
                .with_metadata("files_recovered", session.files_recovered.to_string())
                .with_metadata("source", "recovery_session"),
            );
        }

        builder.build()
    }

    pub fn from_filesystem_metadata(path: &Path) -> Result<Self> {
        let mut builder = TimelineBuilder::new();
        let path_str = path.to_string_lossy().to_string();

        let metadata = std::fs::metadata(path)?;

        if let Ok(created) = metadata.created() {
            let dt: DateTime<Utc> = created.into();
            builder.add_event(
                TimelineEvent::new(dt, EventType::Created, path_str.clone())
                    .with_metadata("source", "filesystem"),
            );
        }

        if let Ok(modified) = metadata.modified() {
            let dt: DateTime<Utc> = modified.into();
            builder.add_event(
                TimelineEvent::new(dt, EventType::Modified, path_str.clone())
                    .with_metadata("source", "filesystem"),
            );
        }

        if let Ok(accessed) = metadata.accessed() {
            let dt: DateTime<Utc> = accessed.into();
            builder.add_event(
                TimelineEvent::new(dt, EventType::Accessed, path_str.clone())
                    .with_metadata("source", "filesystem"),
            );
        }

        Ok(builder.build())
    }
}

impl Default for Timeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_event(hour: u32, event_type: EventType, path: &str) -> TimelineEvent {
        let ts = Utc.with_ymd_and_hms(2024, 1, 15, hour, 0, 0).unwrap();
        TimelineEvent::new(ts, event_type, path.to_string())
    }

    #[test]
    fn test_builder_sorts_events_by_timestamp() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(make_event(10, EventType::Modified, "/b.txt"));
        builder.add_event(make_event(8, EventType::Created, "/a.txt"));
        builder.add_event(make_event(12, EventType::Deleted, "/c.txt"));

        let timeline = builder.build();

        assert_eq!(timeline.events.len(), 3);
        assert_eq!(timeline.events[0].file_path, "/a.txt");
        assert_eq!(timeline.events[1].file_path, "/b.txt");
        assert_eq!(timeline.events[2].file_path, "/c.txt");
    }

    #[test]
    fn test_query_by_type() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(make_event(8, EventType::Created, "/a.txt"));
        builder.add_event(make_event(9, EventType::Modified, "/a.txt"));
        builder.add_event(make_event(10, EventType::Created, "/b.txt"));
        builder.add_event(make_event(11, EventType::Deleted, "/c.txt"));

        let timeline = builder.build();

        let created = timeline.query_by_type(&EventType::Created);
        assert_eq!(created.len(), 2);

        let deleted = timeline.query_by_type(&EventType::Deleted);
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].file_path, "/c.txt");
    }

    #[test]
    fn test_query_by_range() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(make_event(8, EventType::Created, "/a.txt"));
        builder.add_event(make_event(10, EventType::Modified, "/b.txt"));
        builder.add_event(make_event(14, EventType::Deleted, "/c.txt"));

        let timeline = builder.build();

        let start = Utc.with_ymd_and_hms(2024, 1, 15, 9, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2024, 1, 15, 11, 0, 0).unwrap();
        let results = timeline.query_by_range(start, end);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_path, "/b.txt");
    }

    #[test]
    fn test_query_by_path_prefix() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(make_event(8, EventType::Created, "/home/user/doc.txt"));
        builder.add_event(make_event(9, EventType::Modified, "/home/user/photo.jpg"));
        builder.add_event(make_event(10, EventType::Created, "/etc/config"));

        let timeline = builder.build();

        let home_events = timeline.query_by_path_prefix("/home/user/");
        assert_eq!(home_events.len(), 2);

        let etc_events = timeline.query_by_path_prefix("/etc/");
        assert_eq!(etc_events.len(), 1);
    }

    #[test]
    fn test_event_type_counts() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(make_event(8, EventType::Created, "/a.txt"));
        builder.add_event(make_event(9, EventType::Created, "/b.txt"));
        builder.add_event(make_event(10, EventType::Modified, "/a.txt"));

        let timeline = builder.build();
        let counts = timeline.event_type_counts();

        assert_eq!(counts["Created"], 2);
        assert_eq!(counts["Modified"], 1);
    }

    #[test]
    fn test_time_range() {
        let timeline_empty = Timeline::new();
        assert!(timeline_empty.time_range().is_none());

        let mut builder = TimelineBuilder::new();
        builder.add_event(make_event(8, EventType::Created, "/a.txt"));
        builder.add_event(make_event(14, EventType::Deleted, "/b.txt"));
        let timeline = builder.build();

        let (start, end) = timeline.time_range().unwrap();
        assert_eq!(start.hour(), 8);
        assert_eq!(end.hour(), 14);
    }

    #[test]
    fn test_export_json() {
        let mut builder = TimelineBuilder::new();
        builder.add_event(
            make_event(8, EventType::Created, "/a.txt")
                .with_metadata("key", "value"),
        );
        let timeline = builder.build();

        let json = timeline.export_json().unwrap();
        assert!(json.contains("/a.txt"));
        assert!(json.contains("Created"));
        assert!(json.contains("key"));

        let parsed: Vec<TimelineEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].metadata.get("key").unwrap(), "value");
    }

    #[test]
    fn test_empty_timeline() {
        let timeline = Timeline::new();
        assert_eq!(timeline.event_count(), 0);
        assert!(timeline.time_range().is_none());
        assert!(timeline.query_by_type(&EventType::Created).is_empty());
    }

    #[test]
    fn test_event_with_metadata_chaining() {
        let event = TimelineEvent::new(
            Utc::now(),
            EventType::Renamed,
            "/old.txt".to_string(),
        )
        .with_metadata("old_path", "/old.txt")
        .with_metadata("new_path", "/new.txt");

        assert_eq!(event.metadata.get("old_path").unwrap(), "/old.txt");
        assert_eq!(event.metadata.get("new_path").unwrap(), "/new.txt");
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(EventType::Created.to_string(), "Created");
        assert_eq!(EventType::Modified.to_string(), "Modified");
        assert_eq!(EventType::Accessed.to_string(), "Accessed");
        assert_eq!(EventType::Deleted.to_string(), "Deleted");
        assert_eq!(EventType::Renamed.to_string(), "Renamed");
        assert_eq!(EventType::Moved.to_string(), "Moved");
    }

    use chrono::Timelike;

    #[test]
    fn test_add_events_batch() {
        let mut builder = TimelineBuilder::new();
        let batch = vec![
            make_event(10, EventType::Modified, "/x.txt"),
            make_event(5, EventType::Created, "/y.txt"),
        ];
        builder.add_events(batch);
        builder.add_event(make_event(1, EventType::Accessed, "/z.txt"));

        let timeline = builder.build();
        assert_eq!(timeline.event_count(), 3);
        assert_eq!(timeline.events[0].file_path, "/z.txt");
    }
}
