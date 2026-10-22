use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tle_plugins::{Plugin, PluginError, PluginResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudObject {
    key: String,
    size: u64,
    last_modified: String,
    etag: String,
    storage_class: String,
    content_type: Option<String>,
    deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudBucket {
    name: String,
    provider: CloudProvider,
    region: String,
    objects: Vec<CloudObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProvider::Aws => write!(f, "AWS S3"),
            CloudProvider::Azure => write!(f, "Azure Blob Storage"),
            CloudProvider::Gcp => write!(f, "Google Cloud Storage"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryReport {
    provider: String,
    bucket: String,
    region: String,
    total_objects: usize,
    recoverable_objects: usize,
    total_size_bytes: u64,
    recoverable_size_bytes: u64,
    recovered_keys: Vec<String>,
    scan_duration_ms: u64,
}

#[allow(improper_ctypes_definitions)]
pub struct CloudStoragePlugin {
    initialized: bool,
    simulated_buckets: HashMap<String, CloudBucket>,
}

impl CloudStoragePlugin {
    pub fn new() -> Self {
        Self {
            initialized: false,
            simulated_buckets: HashMap::new(),
        }
    }

    fn create_aws_sample(&self) -> CloudBucket {
        CloudBucket {
            name: "evidence-bucket-001".into(),
            provider: CloudProvider::Aws,
            region: "us-east-1".into(),
            objects: vec![
                CloudObject {
                    key: "forensics/disk_image_2024.dd".into(),
                    size: 536_870_912_000,
                    last_modified: "2024-03-15T10:30:00Z".into(),
                    etag: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".into(),
                    storage_class: "STANDARD".into(),
                    content_type: Some("application/octet-stream".into()),
                    deleted: false,
                },
                CloudObject {
                    key: "forensics/logs/server_access.log.gz".into(),
                    size: 2_456_789,
                    last_modified: "2024-03-14T08:15:00Z".into(),
                    etag: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7".into(),
                    storage_class: "STANDARD_IA".into(),
                    content_type: Some("application/gzip".into()),
                    deleted: false,
                },
                CloudObject {
                    key: "forensics/backups/db_snapshot_20240310.sql".into(),
                    size: 107_374_182,
                    last_modified: "2024-03-10T02:00:00Z".into(),
                    etag: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8".into(),
                    storage_class: "GLACIER".into(),
                    content_type: Some("application/sql".into()),
                    deleted: true,
                },
                CloudObject {
                    key: "forensics/evidence/photo_E001.jpg".into(),
                    size: 4_567_890,
                    last_modified: "2024-03-12T14:22:00Z".into(),
                    etag: "d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9".into(),
                    storage_class: "STANDARD".into(),
                    content_type: Some("image/jpeg".into()),
                    deleted: true,
                },
                CloudObject {
                    key: "forensics/evidence/email_export.mbox".into(),
                    size: 52_428_800,
                    last_modified: "2024-03-13T09:45:00Z".into(),
                    etag: "e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0".into(),
                    storage_class: "STANDARD".into(),
                    content_type: Some("application/mbox".into()),
                    deleted: false,
                },
            ],
        }
    }

    fn create_azure_sample(&self) -> CloudBucket {
        CloudBucket {
            name: "corp-evidence-container".into(),
            provider: CloudProvider::Azure,
            region: "eastus".into(),
            objects: vec![
                CloudObject {
                    key: "investigation/case_2024_001/filesystem.tar".into(),
                    size: 214_748_364_800,
                    last_modified: "2024-02-20T16:00:00Z".into(),
                    etag: "0x8DC123456789ABC".into(),
                    storage_class: "Hot".into(),
                    content_type: Some("application/x-tar".into()),
                    deleted: false,
                },
                CloudObject {
                    key: "investigation/case_2024_001/registry_hives.zip".into(),
                    size: 15_728_640,
                    last_modified: "2024-02-21T11:30:00Z".into(),
                    etag: "0x8DC234567890ABD".into(),
                    storage_class: "Hot".into(),
                    content_type: Some("application/zip".into()),
                    deleted: false,
                },
                CloudObject {
                    key: "investigation/case_2024_001/deleted_artifacts.vhd".into(),
                    size: 10_737_418_240,
                    last_modified: "2024-02-19T03:15:00Z".into(),
                    etag: "0x8DC345678901ABE".into(),
                    storage_class: "Cool".into(),
                    content_type: Some("application/vhd".into()),
                    deleted: true,
                },
            ],
        }
    }

    fn create_gcp_sample(&self) -> CloudBucket {
        CloudBucket {
            name: "forensic-archive-bucket".into(),
            provider: CloudProvider::Gcp,
            region: "us-central1".into(),
            objects: vec![
                CloudObject {
                    key: "archives/memory_dump_20240301.raw".into(),
                    size: 8_589_934_592,
                    last_modified: "2024-03-01T07:00:00Z".into(),
                    etag: "CMjA5fOj3oQDEAE=".into(),
                    storage_class: "STANDARD".into(),
                    content_type: Some("application/octet-stream".into()),
                    deleted: false,
                },
                CloudObject {
                    key: "archives/network_pcaps/march_capture.pcap".into(),
                    size: 1_073_741_824,
                    last_modified: "2024-03-05T19:45:00Z".into(),
                    etag: "CMjB6fPk4pRBEAE=".into(),
                    storage_class: "NEARLINE".into(),
                    content_type: Some("application/vnd.tcpdump.pcap".into()),
                    deleted: true,
                },
            ],
        }
    }

    fn simulate_recovery(&self, bucket: &CloudBucket) -> RecoveryReport {
        let total_size: u64 = bucket.objects.iter().map(|o| o.size).sum();
        let recoverable: Vec<&CloudObject> = bucket
            .objects
            .iter()
            .filter(|o| o.deleted)
            .collect();
        let recoverable_size: u64 = recoverable.iter().map(|o| o.size).sum();

        RecoveryReport {
            provider: bucket.provider.to_string(),
            bucket: bucket.name.clone(),
            region: bucket.region.clone(),
            total_objects: bucket.objects.len(),
            recoverable_objects: recoverable.len(),
            total_size_bytes: total_size,
            recoverable_size_bytes: recoverable_size,
            recovered_keys: recoverable.iter().map(|o| o.key.clone()).collect(),
            scan_duration_ms: 245,
        }
    }
}

impl Plugin for CloudStoragePlugin {
    fn name(&self) -> &str {
        "cloud_storage_plugin"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn init(&mut self) -> PluginResult<()> {
        self.initialized = true;
        let aws = self.create_aws_sample();
        let azure = self.create_azure_sample();
        let gcp = self.create_gcp_sample();
        self.simulated_buckets.insert(aws.name.clone(), aws);
        self.simulated_buckets.insert(azure.name.clone(), azure);
        self.simulated_buckets.insert(gcp.name.clone(), gcp);
        Ok(())
    }

    fn process(&self, data: &Value) -> PluginResult<Value> {
        if !self.initialized {
            return Err(PluginError::ExecutionError("Plugin not initialized".into()));
        }

        let action = data
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("list_buckets");

        match action {
            "list_buckets" => {
                let buckets: Vec<Value> = self
                    .simulated_buckets
                    .values()
                    .map(|b| {
                        serde_json::json!({
                            "name": b.name,
                            "provider": b.provider.to_string(),
                            "region": b.region,
                            "object_count": b.objects.len(),
                        })
                    })
                    .collect();

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "buckets": buckets,
                }))
            }
            "list_objects" => {
                let bucket_name = data
                    .get("bucket")
                    .and_then(|b| b.as_str())
                    .ok_or_else(|| {
                        PluginError::ExecutionError("Missing 'bucket' field".into())
                    })?;

                let bucket = self.simulated_buckets.get(bucket_name).ok_or_else(|| {
                    PluginError::ExecutionError(format!("Bucket '{}' not found", bucket_name))
                })?;

                let objects: Vec<Value> = bucket
                    .objects
                    .iter()
                    .map(|o| {
                        serde_json::json!({
                            "key": o.key,
                            "size": o.size,
                            "last_modified": o.last_modified,
                            "etag": o.etag,
                            "storage_class": o.storage_class,
                            "content_type": o.content_type,
                            "deleted": o.deleted,
                        })
                    })
                    .collect();

                Ok(serde_json::json!({
                    "status": "success",
                    "bucket": bucket_name,
                    "objects": objects,
                }))
            }
            "recover" => {
                let bucket_name = data
                    .get("bucket")
                    .and_then(|b| b.as_str())
                    .ok_or_else(|| {
                        PluginError::ExecutionError("Missing 'bucket' field".into())
                    })?;

                let bucket = self.simulated_buckets.get(bucket_name).ok_or_else(|| {
                    PluginError::ExecutionError(format!("Bucket '{}' not found", bucket_name))
                })?;

                let report = self.simulate_recovery(bucket);

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "recovery_report": {
                        "provider": report.provider,
                        "bucket": report.bucket,
                        "region": report.region,
                        "total_objects": report.total_objects,
                        "recoverable_objects": report.recoverable_objects,
                        "total_size_bytes": report.total_size_bytes,
                        "recoverable_size_bytes": report.recoverable_size_bytes,
                        "recovered_keys": report.recovered_keys,
                        "scan_duration_ms": report.scan_duration_ms,
                    },
                }))
            }
            "recover_all" => {
                let mut reports = Vec::new();
                for bucket in self.simulated_buckets.values() {
                    reports.push(self.simulate_recovery(bucket));
                }

                let total_recoverable: usize = reports.iter().map(|r| r.recoverable_objects).sum();
                let total_recoverable_size: u64 =
                    reports.iter().map(|r| r.recoverable_size_bytes).sum();

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "total_buckets": reports.len(),
                    "total_recoverable_objects": total_recoverable,
                    "total_recoverable_size_bytes": total_recoverable_size,
                    "reports": reports.iter().map(|r| {
                        serde_json::json!({
                            "provider": r.provider,
                            "bucket": r.bucket,
                            "recoverable_objects": r.recoverable_objects,
                            "recoverable_size_bytes": r.recoverable_size_bytes,
                            "recovered_keys": r.recovered_keys,
                        })
                    }).collect::<Vec<_>>(),
                }))
            }
            _ => Err(PluginError::ExecutionError(format!(
                "Unknown action '{}'. Valid: list_buckets, list_objects, recover, recover_all",
                action
            ))),
        }
    }

    fn shutdown(&mut self) -> PluginResult<()> {
        self.simulated_buckets.clear();
        self.initialized = false;
        Ok(())
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(CloudStoragePlugin::new()))
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn destroy_plugin(ptr: *mut dyn Plugin) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut CloudStoragePlugin));
        }
    }
}
