//! Common types for cloud storage recovery

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Cloud storage provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProvider {
    AwsS3,
    AzureBlob,
    GcpStorage,
}

impl CloudProvider {
    /// Get provider name as string
    pub fn to_string(&self) -> &'static str {
        match self {
            CloudProvider::AwsS3 => "AWS S3",
            CloudProvider::AzureBlob => "Azure Blob Storage",
            CloudProvider::GcpStorage => "Google Cloud Storage",
        }
    }
}

/// Cloud storage credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloudCredentials {
    Aws {
        access_key_id: String,
        secret_access_key: String,
        region: String,
        bucket: String,
    },
    Azure {
        account_name: String,
        account_key: String,
        container: String,
    },
    Gcp {
        project_id: String,
        service_account_key: String,
        bucket: String,
    },
}

/// Cloud object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudObject {
    /// Object key/path
    pub key: String,
    /// Object size in bytes
    pub size: u64,
    /// Last modified timestamp
    pub last_modified: Option<DateTime<Utc>>,
    /// ETag or version ID
    pub etag: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Storage class
    pub storage_class: Option<String>,
    /// Is this a deleted object (for versioned buckets)
    pub is_deleted: bool,
    /// Version ID (if versioning is enabled)
    pub version_id: Option<String>,
    /// Is delete marker
    pub is_delete_marker: bool,
}

impl CloudObject {
    /// Create a new cloud object
    pub fn new(key: String, size: u64) -> Self {
        Self {
            key,
            size,
            last_modified: None,
            etag: None,
            content_type: None,
            storage_class: None,
            is_deleted: false,
            version_id: None,
            is_delete_marker: false,
        }
    }

    /// Mark object as deleted
    pub fn mark_deleted(&mut self) {
        self.is_deleted = true;
    }

    /// Set version information
    pub fn set_version(&mut self, version_id: String) {
        self.version_id = Some(version_id);
    }

    /// Check if object is current version
    pub fn is_current_version(&self) -> bool {
        !self.is_deleted && !self.is_delete_marker
    }
}

/// Recovery options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryOptions {
    /// Include deleted objects
    pub include_deleted: bool,
    /// Include all versions
    pub include_versions: bool,
    /// Filter by prefix
    pub prefix: Option<String>,
    /// Filter by suffix
    pub suffix: Option<String>,
    /// Minimum size filter
    pub min_size: Option<u64>,
    /// Maximum size filter
    pub max_size: Option<u64>,
    /// Filter by content type
    pub content_type_filter: Option<String>,
    /// Output directory
    pub output_dir: String,
    /// Overwrite existing files
    pub overwrite: bool,
    /// Parallel download threads
    pub parallel_threads: usize,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            include_deleted: false,
            include_versions: false,
            prefix: None,
            suffix: None,
            min_size: None,
            max_size: None,
            content_type_filter: None,
            output_dir: "./recovered".to_string(),
            overwrite: false,
            parallel_threads: 4,
        }
    }
}

impl RecoveryOptions {
    /// Check if object matches filters
    pub fn matches_filter(&self, obj: &CloudObject) -> bool {
        // Check deleted filter
        if !self.include_deleted && obj.is_deleted {
            return false;
        }

        // Check prefix filter
        if let Some(prefix) = &self.prefix {
            if !obj.key.starts_with(prefix) {
                return false;
            }
        }

        // Check suffix filter
        if let Some(suffix) = &self.suffix {
            if !obj.key.ends_with(suffix) {
                return false;
            }
        }

        // Check size filters
        if let Some(min_size) = self.min_size {
            if obj.size < min_size {
                return false;
            }
        }

        if let Some(max_size) = self.max_size {
            if obj.size > max_size {
                return false;
            }
        }

        // Check content type filter
        if let Some(content_type) = &self.content_type_filter {
            if let Some(obj_content_type) = &obj.content_type {
                if !obj_content_type.contains(content_type) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

/// Recovery statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoveryStats {
    /// Total objects found
    pub total_objects: usize,
    /// Objects recovered
    pub recovered: usize,
    /// Objects skipped
    pub skipped: usize,
    /// Objects failed
    pub failed: usize,
    /// Total bytes recovered
    pub bytes_recovered: u64,
    /// Recovery duration in seconds
    pub duration_secs: f64,
}

impl RecoveryStats {
    /// Add to recovered count
    pub fn add_recovered(&mut self, bytes: u64) {
        self.recovered += 1;
        self.bytes_recovered += bytes;
    }

    /// Add to skipped count
    pub fn add_skipped(&mut self) {
        self.skipped += 1;
    }

    /// Add to failed count
    pub fn add_failed(&mut self) {
        self.failed += 1;
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_objects == 0 {
            0.0
        } else {
            (self.recovered as f64 / self.total_objects as f64) * 100.0
        }
    }

    /// Get throughput in MB/s
    pub fn throughput_mbps(&self) -> f64 {
        if self.duration_secs == 0.0 {
            0.0
        } else {
            (self.bytes_recovered as f64 / 1_048_576.0) / self.duration_secs
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_object_creation() {
        let mut obj = CloudObject::new("test/file.txt".to_string(), 1024);
        assert_eq!(obj.key, "test/file.txt");
        assert_eq!(obj.size, 1024);
        assert!(!obj.is_deleted);
        assert!(obj.is_current_version());

        obj.mark_deleted();
        assert!(obj.is_deleted);
        assert!(!obj.is_current_version());
    }

    #[test]
    fn test_recovery_options_filter() {
        let options = RecoveryOptions {
            prefix: Some("images/".to_string()),
            min_size: Some(1024),
            max_size: Some(10_485_760),
            ..Default::default()
        };

        let obj1 = CloudObject::new("images/photo.jpg".to_string(), 2048);
        assert!(options.matches_filter(&obj1));

        let obj2 = CloudObject::new("documents/file.txt".to_string(), 2048);
        assert!(!options.matches_filter(&obj2));

        let obj3 = CloudObject::new("images/small.jpg".to_string(), 512);
        assert!(!options.matches_filter(&obj3));
    }

    #[test]
    fn test_recovery_stats() {
        let mut stats = RecoveryStats::default();
        stats.total_objects = 10;
        stats.add_recovered(1024);
        stats.add_recovered(2048);
        stats.add_skipped();
        stats.add_failed();
        stats.duration_secs = 2.0;

        assert_eq!(stats.recovered, 2);
        assert_eq!(stats.bytes_recovered, 3072);
        assert_eq!(stats.success_rate(), 20.0);
        assert_eq!(stats.throughput_mbps(), 0.00146484375);
    }
}
