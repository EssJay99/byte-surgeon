use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tle_plugins::{Plugin, PluginError, PluginResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimelineEvent {
    timestamp: String,
    event_type: EventType,
    path: String,
    macb: MacbFlags,
    size: Option<u64>,
    metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum EventType {
    FileCreated,
    FileModified,
    FileAccessed,
    FileDeleted,
    MetadataChanged,
    PermissionChanged,
    OwnershipChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MacbFlags {
    modified: bool,
    accessed: bool,
    changed: bool,
    born: bool,
}

impl MacbFlags {
    fn to_string(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.modified { 'M' } else { '.' },
            if self.accessed { 'A' } else { '.' },
            if self.changed { 'C' } else { '.' },
            if self.born { 'B' } else { '.' },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimelineAnalysis {
    total_events: usize,
    time_range_start: String,
    time_range_end: String,
    events_by_type: HashMap<String, usize>,
    events_by_hour: HashMap<String, usize>,
    suspicious_clusters: Vec<SuspiciousCluster>,
    anomalies: Vec<Anomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuspiciousCluster {
    time_window: String,
    event_count: usize,
    paths: Vec<String>,
    severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Anomaly {
    timestamp: String,
    description: String,
    severity: String,
    affected_path: String,
}

#[allow(improper_ctypes_definitions)]
pub struct AdvancedForensicsPlugin {
    initialized: bool,
}

impl AdvancedForensicsPlugin {
    pub fn new() -> Self {
        Self { initialized: false }
    }

    fn parse_events(&self, data: &Value) -> PluginResult<Vec<TimelineEvent>> {
        let events_data = data.get("events").ok_or_else(|| {
            PluginError::ExecutionError("Missing 'events' array in input".into())
        })?;

        serde_json::from_value(events_data.clone()).map_err(|e| {
            PluginError::ExecutionError(format!("Failed to parse events: {}", e))
        })
    }

    fn analyze_timeline(&self, events: &[TimelineEvent]) -> TimelineAnalysis {
        if events.is_empty() {
            return TimelineAnalysis {
                total_events: 0,
                time_range_start: String::new(),
                time_range_end: String::new(),
                events_by_type: HashMap::new(),
                events_by_hour: HashMap::new(),
                suspicious_clusters: Vec::new(),
                anomalies: Vec::new(),
            };
        }

        let mut sorted = events.to_vec();
        sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let time_range_start = sorted.first().unwrap().timestamp.clone();
        let time_range_end = sorted.last().unwrap().timestamp.clone();

        let mut events_by_type: HashMap<String, usize> = HashMap::new();
        let mut events_by_hour: HashMap<String, usize> = HashMap::new();
        let mut anomalies: Vec<Anomaly> = Vec::new();

        for event in &sorted {
            let type_name = match event.event_type {
                EventType::FileCreated => "file_created",
                EventType::FileModified => "file_modified",
                EventType::FileAccessed => "file_accessed",
                EventType::FileDeleted => "file_deleted",
                EventType::MetadataChanged => "metadata_changed",
                EventType::PermissionChanged => "permission_changed",
                EventType::OwnershipChanged => "ownership_changed",
            };
            *events_by_type.entry(type_name.to_string()).or_insert(0) += 1;

            let hour = if event.timestamp.len() >= 13 {
                event.timestamp[..13].to_string()
            } else {
                "unknown".to_string()
            };
            *events_by_hour.entry(hour).or_insert(0) += 1;

            if matches!(event.event_type, EventType::FileDeleted | EventType::PermissionChanged) {
                anomalies.push(Anomaly {
                    timestamp: event.timestamp.clone(),
                    description: format!(
                        "Suspicious {:?} event on path: {}",
                        event.event_type, event.path
                    ),
                    severity: if matches!(event.event_type, EventType::FileDeleted) {
                        "high".into()
                    } else {
                        "medium".into()
                    },
                    affected_path: event.path.clone(),
                });
            }
        }

        let suspicious_clusters = self.detect_clusters(&sorted);

        TimelineAnalysis {
            total_events: events.len(),
            time_range_start,
            time_range_end,
            events_by_type,
            events_by_hour,
            suspicious_clusters,
            anomalies,
        }
    }

    fn detect_clusters(&self, events: &[TimelineEvent]) -> Vec<SuspiciousCluster> {
        let mut clusters: Vec<SuspiciousCluster> = Vec::new();

        if events.len() < 3 {
            return clusters;
        }

        let window_minutes = 5;
        let mut i = 0;

        while i < events.len() {
            let window_start = &events[i].timestamp;
            let mut window_events: Vec<&TimelineEvent> = vec![&events[i]];
            let mut j = i + 1;

            while j < events.len() && j - i < 20 {
                if self.timestamps_close(window_start, &events[j].timestamp, window_minutes) {
                    window_events.push(&events[j]);
                }
                j += 1;
            }

            if window_events.len() >= 3 {
                let paths: Vec<String> = window_events
                    .iter()
                    .map(|e| e.path.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                let severity = if window_events.len() >= 10 {
                    "critical"
                } else if window_events.len() >= 5 {
                    "high"
                } else {
                    "medium"
                };

                clusters.push(SuspiciousCluster {
                    time_window: format!("{} (+{} min)", window_start, window_minutes),
                    event_count: window_events.len(),
                    paths,
                    severity: severity.into(),
                });

                i = j;
            } else {
                i += 1;
            }
        }

        clusters
    }

    fn timestamps_close(&self, t1: &str, t2: &str, _window_minutes: u32) -> bool {
        t1[..13] == t2[..13]
    }

    fn generate_sample_events(&self) -> Vec<TimelineEvent> {
        vec![
            TimelineEvent {
                timestamp: "2024-03-15T08:00:00Z".into(),
                event_type: EventType::FileCreated,
                path: "/home/user/documents/report.docx".into(),
                macb: MacbFlags {
                    modified: true,
                    accessed: false,
                    changed: true,
                    born: true,
                },
                size: Some(24576),
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T08:15:00Z".into(),
                event_type: EventType::FileAccessed,
                path: "/home/user/documents/report.docx".into(),
                macb: MacbFlags {
                    modified: false,
                    accessed: true,
                    changed: false,
                    born: false,
                },
                size: Some(24576),
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T09:30:00Z".into(),
                event_type: EventType::FileModified,
                path: "/home/user/documents/report.docx".into(),
                macb: MacbFlags {
                    modified: true,
                    accessed: true,
                    changed: true,
                    born: false,
                },
                size: Some(32768),
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T10:00:00Z".into(),
                event_type: EventType::FileDeleted,
                path: "/var/log/auth.log".into(),
                macb: MacbFlags {
                    modified: false,
                    accessed: false,
                    changed: true,
                    born: false,
                },
                size: None,
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T10:00:05Z".into(),
                event_type: EventType::PermissionChanged,
                path: "/etc/sudoers".into(),
                macb: MacbFlags {
                    modified: false,
                    accessed: false,
                    changed: true,
                    born: false,
                },
                size: Some(4096),
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T10:00:10Z".into(),
                event_type: EventType::FileCreated,
                path: "/tmp/.hidden_backdoor.sh".into(),
                macb: MacbFlags {
                    modified: true,
                    accessed: false,
                    changed: true,
                    born: true,
                },
                size: Some(1024),
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T10:00:15Z".into(),
                event_type: EventType::FileDeleted,
                path: "/var/log/syslog".into(),
                macb: MacbFlags {
                    modified: false,
                    accessed: false,
                    changed: true,
                    born: false,
                },
                size: None,
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T10:00:20Z".into(),
                event_type: EventType::OwnershipChanged,
                path: "/usr/local/bin/suspicious_binary".into(),
                macb: MacbFlags {
                    modified: false,
                    accessed: false,
                    changed: true,
                    born: false,
                },
                size: Some(8192),
                metadata: HashMap::new(),
            },
            TimelineEvent {
                timestamp: "2024-03-15T14:00:00Z".into(),
                event_type: EventType::FileAccessed,
                path: "/home/user/downloads/data.csv".into(),
                macb: MacbFlags {
                    modified: false,
                    accessed: true,
                    changed: false,
                    born: false,
                },
                size: Some(1048576),
                metadata: HashMap::new(),
            },
        ]
    }
}

impl Plugin for AdvancedForensicsPlugin {
    fn name(&self) -> &str {
        "advanced_forensics_plugin"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn init(&mut self) -> PluginResult<()> {
        self.initialized = true;
        Ok(())
    }

    fn process(&self, data: &Value) -> PluginResult<Value> {
        if !self.initialized {
            return Err(PluginError::ExecutionError("Plugin not initialized".into()));
        }

        let action = data
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("analyze");

        match action {
            "analyze" => {
                let events = self.parse_events(data)?;
                let analysis = self.analyze_timeline(&events);

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "analysis": {
                        "total_events": analysis.total_events,
                        "time_range": {
                            "start": analysis.time_range_start,
                            "end": analysis.time_range_end,
                        },
                        "events_by_type": analysis.events_by_type,
                        "events_by_hour": analysis.events_by_hour,
                        "suspicious_clusters": analysis.suspicious_clusters,
                        "anomalies": analysis.anomalies,
                    }
                }))
            }
            "sample" => {
                let events = self.generate_sample_events();
                let analysis = self.analyze_timeline(&events);

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "sample_events_count": events.len(),
                    "analysis": {
                        "total_events": analysis.total_events,
                        "time_range": {
                            "start": analysis.time_range_start,
                            "end": analysis.time_range_end,
                        },
                        "events_by_type": analysis.events_by_type,
                        "events_by_hour": analysis.events_by_hour,
                        "suspicious_clusters": analysis.suspicious_clusters,
                        "anomalies": analysis.anomalies,
                    }
                }))
            }
            "macb_summary" => {
                let events = self.parse_events(data)?;

                let macb_counts: HashMap<String, usize> = events
                    .iter()
                    .fold(HashMap::new(), |mut acc, e| {
                        *acc.entry(e.macb.to_string()).or_insert(0) += 1;
                        acc
                    });

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "total_events": events.len(),
                    "macb_distribution": macb_counts,
                }))
            }
            _ => Err(PluginError::ExecutionError(format!(
                "Unknown action '{}'. Valid: analyze, sample, macb_summary",
                action
            ))),
        }
    }

    fn shutdown(&mut self) -> PluginResult<()> {
        self.initialized = false;
        Ok(())
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(AdvancedForensicsPlugin::new()))
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn destroy_plugin(ptr: *mut dyn Plugin) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut AdvancedForensicsPlugin));
        }
    }
}
