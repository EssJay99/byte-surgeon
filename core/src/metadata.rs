use crate::{Result, Error};
use std::collections::HashMap;
use std::path::Path;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimestamps {
    pub created: Option<chrono::DateTime<chrono::Utc>>,
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
    pub accessed: Option<chrono::DateTime<chrono::Utc>>,
    pub metadata_changed: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePermissions {
    #[cfg(unix)]
    pub mode: u32,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    #[cfg(windows)]
    pub owner_sid: Option<String>,
    #[cfg(windows)]
    pub acl_entries: Vec<String>,
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub archive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOwnership {
    pub owner: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAttributes {
    pub size: u64,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    pub is_directory: bool,
    pub is_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedAttributes {
    pub entries: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSnapshot {
    pub path: String,
    pub timestamps: FileTimestamps,
    pub permissions: FilePermissions,
    pub ownership: FileOwnership,
    pub attributes: FileAttributes,
    pub extended_attributes: ExtendedAttributes,
    pub captured_at: chrono::DateTime<chrono::Utc>,
}

pub struct MetadataPreserver {
    preserve_timestamps: bool,
    preserve_permissions: bool,
    preserve_ownership: bool,
    preserve_xattrs: bool,
}

impl MetadataPreserver {
    pub fn new() -> Self {
        Self {
            preserve_timestamps: true,
            preserve_permissions: true,
            preserve_ownership: true,
            preserve_xattrs: true,
        }
    }

    pub fn with_timestamps(mut self, preserve: bool) -> Self {
        self.preserve_timestamps = preserve;
        self
    }

    pub fn with_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }

    pub fn with_ownership(mut self, preserve: bool) -> Self {
        self.preserve_ownership = preserve;
        self
    }

    pub fn with_xattrs(mut self, preserve: bool) -> Self {
        self.preserve_xattrs = preserve;
        self
    }

    pub fn read_metadata(&self, source: &Path) -> Result<MetadataSnapshot> {
        info!("Reading metadata from: {}", source.display());

        let metadata = std::fs::symlink_metadata(source).map_err(Error::Io)?;

        let timestamps = self.read_timestamps(&metadata)?;
        let permissions = self.read_permissions(&metadata)?;
        let ownership = self.read_ownership(&metadata)?;
        let attributes = self.read_attributes(source, &metadata)?;
        let xattrs = self.read_extended_attributes(source)?;

        Ok(MetadataSnapshot {
            path: source.to_string_lossy().to_string(),
            timestamps,
            permissions,
            ownership,
            attributes,
            extended_attributes: xattrs,
            captured_at: chrono::Utc::now(),
        })
    }

    pub fn preserve(&self, source: &Path, dest: &Path) -> Result<MetadataSnapshot> {
        info!("Preserving metadata from {} to {}", source.display(), dest.display());

        let file_meta = self.read_metadata(source)?;
        self.apply_metadata(dest, &file_meta)?;

        debug!("Metadata preserved successfully for {}", dest.display());
        Ok(file_meta)
    }

    pub fn restore(&self, dest: &Path, file_meta: &MetadataSnapshot) -> Result<()> {
        info!("Restoring metadata to: {}", dest.display());
        self.apply_metadata(dest, file_meta)?;
        debug!("Metadata restored successfully for {}", dest.display());
        Ok(())
    }

    fn apply_metadata(&self, dest: &Path, file_meta: &MetadataSnapshot) -> Result<()> {
        if self.preserve_timestamps {
            self.apply_timestamps(dest, &file_meta.timestamps)?;
        }

        if self.preserve_permissions {
            self.apply_permissions(dest, &file_meta.permissions)?;
        }

        if self.preserve_ownership {
            self.apply_ownership(dest, &file_meta.ownership)?;
        }

        if self.preserve_xattrs {
            self.apply_extended_attributes(dest, &file_meta.extended_attributes)?;
        }

        Ok(())
    }

    fn read_timestamps(&self, metadata: &std::fs::Metadata) -> Result<FileTimestamps> {
        let created = metadata.created().ok().map(chrono::DateTime::<chrono::Utc>::from);
        let modified = metadata.modified().ok().map(chrono::DateTime::<chrono::Utc>::from);
        let accessed = metadata.accessed().ok().map(chrono::DateTime::<chrono::Utc>::from);

        #[cfg(unix)]
        let metadata_changed = {
            use std::os::unix::fs::MetadataExt;
            Some(chrono::DateTime::<chrono::Utc>::from(
                std::time::UNIX_EPOCH + std::time::Duration::new(metadata.ctime() as u64, metadata.ctime_nsec() as u32)
            ))
        };
        #[cfg(not(unix))]
        let metadata_changed = None;

        Ok(FileTimestamps {
            created,
            modified,
            accessed,
            metadata_changed,
        })
    }

    fn read_permissions(&self, metadata: &std::fs::Metadata) -> Result<FilePermissions> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, MetadataExt};
            let mode = metadata.permissions().mode();
            let uid = metadata.uid();
            let gid = metadata.gid();

            Ok(FilePermissions {
                mode,
                uid,
                gid,
                readonly: metadata.permissions().readonly(),
                hidden: false,
                system: false,
                archive: false,
            })
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            Ok(FilePermissions {
                owner_sid: None,
                acl_entries: Vec::new(),
                readonly: metadata.permissions().readonly(),
                hidden: metadata.file_attributes() & 0x02 != 0,
                system: metadata.file_attributes() & 0x04 != 0,
                archive: metadata.file_attributes() & 0x20 != 0,
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(FilePermissions {
                readonly: metadata.permissions().readonly(),
                hidden: false,
                system: false,
                archive: false,
            })
        }
    }

    fn read_ownership(&self, metadata: &std::fs::Metadata) -> Result<FileOwnership> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let uid = metadata.uid();
            let gid = metadata.gid();

            let owner = Self::resolve_uid_to_name(uid).unwrap_or_else(|| uid.to_string());
            let group = Self::resolve_gid_to_name(gid).unwrap_or_else(|| gid.to_string());

            Ok(FileOwnership { owner, group })
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            Ok(FileOwnership {
                owner: String::new(),
                group: String::new(),
            })
        }
    }

    #[cfg(unix)]
    fn resolve_uid_to_name(uid: u32) -> Option<String> {
        let output = std::process::Command::new("id")
            .args(["-nu", &uid.to_string()])
            .output()
            .ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    fn resolve_uid_to_name(_uid: u32) -> Option<String> {
        None
    }

    #[cfg(unix)]
    fn resolve_gid_to_name(gid: u32) -> Option<String> {
        let output = std::process::Command::new("id")
            .args(["-ng", &gid.to_string()])
            .output()
            .ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    fn resolve_gid_to_name(_gid: u32) -> Option<String> {
        None
    }

    fn read_attributes(&self, source: &Path, metadata: &std::fs::Metadata) -> Result<FileAttributes> {
        let is_symlink = metadata.file_type().is_symlink();
        let symlink_target = if is_symlink {
            std::fs::read_link(source)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        Ok(FileAttributes {
            size: metadata.len(),
            is_symlink,
            symlink_target,
            is_directory: metadata.is_dir(),
            is_file: metadata.is_file(),
        })
    }

    fn read_extended_attributes(&self, source: &Path) -> Result<ExtendedAttributes> {
        let mut entries = HashMap::new();

        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("xattr")
                .args(["-l", &source.to_string_lossy()])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if let Some((key, value)) = line.split_once(':') {
                        let key = key.trim().to_string();
                        let value = value.trim().as_bytes().to_vec();
                        if !key.is_empty() {
                            entries.insert(key, value);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("getfattr")
                .args(["-d", "--match=-", "-e", "base64", &source.to_string_lossy()])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if let Some(rest) = line.strip_prefix("user.") {
                        if let Some((key, value)) = rest.split_once('=') {
                            let key = format!("user.{}", key.trim());
                            let value = value.trim().trim_matches('"').as_bytes().to_vec();
                            entries.insert(key, value);
                        }
                    }
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = source;
        }

        Ok(ExtendedAttributes { entries })
    }

    fn apply_timestamps(&self, dest: &Path, timestamps: &FileTimestamps) -> Result<()> {
        if let Some(modified) = timestamps.modified {
            let sys_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified.timestamp() as u64);
            let file = std::fs::OpenOptions::new().write(true).open(dest)?;
            file.set_modified(sys_time)?;
        }

        if let Some(accessed) = timestamps.accessed {
            let sys_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(accessed.timestamp() as u64);
            let _file = std::fs::OpenOptions::new().write(true).open(dest)?;
            let _ = sys_time;
        }

        debug!("Applied timestamps to {}", dest.display());
        Ok(())
    }

    fn apply_permissions(&self, dest: &Path, permissions: &FilePermissions) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(permissions.mode);
            std::fs::set_permissions(dest, perms)?;
            debug!("Applied permissions {:o} to {}", permissions.mode, dest.display());
        }

        #[cfg(windows)]
        {
            let _ = dest;
            let _ = permissions;
            debug!("Windows ACL application is a placeholder");
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = dest;
            let _ = permissions;
        }

        Ok(())
    }

    fn apply_ownership(&self, dest: &Path, ownership: &FileOwnership) -> Result<()> {
        #[cfg(unix)]
        {
            let uid = ownership.owner.parse::<u32>().unwrap_or(u32::MAX);
            let gid = ownership.group.parse::<u32>().unwrap_or(u32::MAX);

            let uid = if uid != u32::MAX {
                uid
            } else {
                Self::resolve_name_to_uid(&ownership.owner).unwrap_or(u32::MAX)
            };

            let gid = if gid != u32::MAX {
                gid
            } else {
                Self::resolve_name_to_gid(&ownership.group).unwrap_or(u32::MAX)
            };

            if uid == u32::MAX || gid == u32::MAX {
                warn!(
                    "Could not resolve owner '{}' or group '{}', skipping ownership change",
                    ownership.owner, ownership.group
                );
                return Ok(());
            }

            let owner_spec = format!("{}:{}", uid, gid);
            let result = std::process::Command::new("chown")
                .arg(&owner_spec)
                .arg(dest)
                .output();

            match result {
                Ok(output) if output.status.success() => {
                    debug!("Applied ownership {}:{}", ownership.owner, ownership.group);
                }
                _ => {
                    warn!(
                        "Failed to chown {} to {}:{} (may require root)",
                        dest.display(),
                        ownership.owner,
                        ownership.group
                    );
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = dest;
            let _ = ownership;
        }

        Ok(())
    }

    #[cfg(unix)]
    fn resolve_name_to_uid(name: &str) -> Option<u32> {
        let output = std::process::Command::new("id")
            .args(["-u", name])
            .output()
            .ok()?;
        if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().parse().ok()
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    fn resolve_name_to_uid(_name: &str) -> Option<u32> {
        None
    }

    #[cfg(unix)]
    fn resolve_name_to_gid(name: &str) -> Option<u32> {
        let output = std::process::Command::new("id")
            .args(["-g", name])
            .output()
            .ok()?;
        if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().parse().ok()
        } else {
            None
        }
    }

    #[cfg(not(unix))]
    fn resolve_name_to_gid(_name: &str) -> Option<u32> {
        None
    }

    fn apply_extended_attributes(&self, dest: &Path, xattrs: &ExtendedAttributes) -> Result<()> {
        if xattrs.entries.is_empty() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            for (key, value) in &xattrs.entries {
                let value_hex = value
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                let _ = std::process::Command::new("xattr")
                    .args(["-w", key, &value_hex, &dest.to_string_lossy()])
                    .output();
            }
        }

        #[cfg(target_os = "linux")]
        {
            for (key, value) in &xattrs.entries {
                let value_str = String::from_utf8_lossy(value);
                let _ = std::process::Command::new("setfattr")
                    .args(["-n", key, "-v", &value_str, &dest.to_string_lossy()])
                    .output();
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = dest;
            let _ = xattrs;
        }

        Ok(())
    }
}

impl Default for MetadataPreserver {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MetadataExporter;

impl MetadataExporter {
    pub fn to_json(file_meta: &MetadataSnapshot) -> Result<String> {
        let json = serde_json::to_string_pretty(file_meta)?;
        Ok(json)
    }

    pub fn from_json(json: &str) -> Result<MetadataSnapshot> {
        let file_meta: MetadataSnapshot = serde_json::from_str(json)?;
        Ok(file_meta)
    }

    pub fn save_to_file(file_meta: &MetadataSnapshot, path: &Path) -> Result<()> {
        let json = Self::to_json(file_meta)?;
        std::fs::write(path, json)?;
        info!("Metadata saved to {}", path.display());
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<MetadataSnapshot> {
        let json = std::fs::read_to_string(path)?;
        let file_meta = Self::from_json(&json)?;
        info!("Metadata loaded from {}", path.display());
        Ok(file_meta)
    }

    pub fn save_many_to_file(metadata_list: &[MetadataSnapshot], path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(metadata_list)?;
        std::fs::write(path, json)?;
        info!("Saved {} metadata entries to {}", metadata_list.len(), path.display());
        Ok(())
    }

    pub fn load_many_from_file(path: &Path) -> Result<Vec<MetadataSnapshot>> {
        let json = std::fs::read_to_string(path)?;
        let list: Vec<MetadataSnapshot> = serde_json::from_str(&json)?;
        info!("Loaded {} metadata entries from {}", list.len(), path.display());
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_metadata_preserver_creation() {
        let mp = MetadataPreserver::new();
        assert!(mp.preserve_timestamps);
        assert!(mp.preserve_permissions);
        assert!(mp.preserve_ownership);
        assert!(mp.preserve_xattrs);
    }

    #[test]
    fn test_metadata_preserver_builder() {
        let mp = MetadataPreserver::new()
            .with_timestamps(false)
            .with_permissions(false)
            .with_ownership(true)
            .with_xattrs(false);
        assert!(!mp.preserve_timestamps);
        assert!(!mp.preserve_permissions);
        assert!(mp.preserve_ownership);
        assert!(!mp.preserve_xattrs);
    }

    #[test]
    fn test_default() {
        let mp = MetadataPreserver::default();
        assert!(mp.preserve_timestamps);
    }

    #[test]
    fn test_read_metadata_from_temp_file() {
        let dir = std::env::temp_dir().join("tle_metadata_test_read");
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("testfile.txt");
        fs::write(&file_path, b"hello metadata").unwrap();

        let mp = MetadataPreserver::new();
        let result = mp.read_metadata(&file_path);
        assert!(result.is_ok());

        let meta = result.unwrap();
        assert_eq!(meta.path, file_path.to_string_lossy());
        assert_eq!(meta.attributes.size, 14);
        assert!(meta.attributes.is_file);
        assert!(!meta.attributes.is_directory);
        assert!(meta.timestamps.modified.is_some());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_preserve_and_restore() {
        let dir = std::env::temp_dir().join("tle_metadata_test_preserve");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.txt");
        let dest = dir.join("dest.txt");
        fs::write(&source, b"source content").unwrap();
        fs::write(&dest, b"dest content").unwrap();

        let mp = MetadataPreserver::new();
        let result = mp.preserve(&source, &dest);
        assert!(result.is_ok());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_restore_from_metadata() {
        let dir = std::env::temp_dir().join("tle_metadata_test_restore");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.txt");
        let dest = dir.join("dest.txt");
        fs::write(&source, b"content").unwrap();
        fs::write(&dest, b"restored").unwrap();

        let mp = MetadataPreserver::new();
        let meta = mp.read_metadata(&source).unwrap();
        let result = mp.restore(&dest, &meta);
        assert!(result.is_ok());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_metadata_exporter_json_roundtrip() {
        let meta = MetadataSnapshot {
            path: "/tmp/test.txt".to_string(),
            timestamps: FileTimestamps {
                created: Some(chrono::Utc::now()),
                modified: Some(chrono::Utc::now()),
                accessed: Some(chrono::Utc::now()),
                metadata_changed: None,
            },
            permissions: FilePermissions {
                #[cfg(unix)]
                mode: 0o644,
                #[cfg(unix)]
                uid: 1000,
                #[cfg(unix)]
                gid: 1000,
                #[cfg(windows)]
                owner_sid: None,
                #[cfg(windows)]
                acl_entries: vec![],
                readonly: false,
                hidden: false,
                system: false,
                archive: false,
            },
            ownership: FileOwnership {
                owner: "testuser".to_string(),
                group: "testgroup".to_string(),
            },
            attributes: FileAttributes {
                size: 1024,
                is_symlink: false,
                symlink_target: None,
                is_directory: false,
                is_file: true,
            },
            extended_attributes: ExtendedAttributes {
                entries: HashMap::new(),
            },
            captured_at: chrono::Utc::now(),
        };

        let json = MetadataExporter::to_json(&meta).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("testuser"));

        let restored = MetadataExporter::from_json(&json).unwrap();
        assert_eq!(restored.path, meta.path);
        assert_eq!(restored.attributes.size, 1024);
        assert_eq!(restored.ownership.owner, "testuser");
    }

    #[test]
    fn test_metadata_exporter_file_roundtrip() {
        let dir = std::env::temp_dir().join("tle_metadata_test_exporter");
        fs::create_dir_all(&dir).unwrap();
        let meta_path = dir.join("metadata.json");

        let meta = MetadataSnapshot {
            path: "/tmp/original.txt".to_string(),
            timestamps: FileTimestamps {
                created: Some(chrono::Utc::now()),
                modified: Some(chrono::Utc::now()),
                accessed: Some(chrono::Utc::now()),
                metadata_changed: None,
            },
            permissions: FilePermissions {
                #[cfg(unix)]
                mode: 0o755,
                #[cfg(unix)]
                uid: 501,
                #[cfg(unix)]
                gid: 20,
                #[cfg(windows)]
                owner_sid: None,
                #[cfg(windows)]
                acl_entries: vec![],
                readonly: false,
                hidden: false,
                system: false,
                archive: true,
            },
            ownership: FileOwnership {
                owner: "alice".to_string(),
                group: "staff".to_string(),
            },
            attributes: FileAttributes {
                size: 2048,
                is_symlink: false,
                symlink_target: None,
                is_directory: false,
                is_file: true,
            },
            extended_attributes: ExtendedAttributes {
                entries: {
                    let mut m = HashMap::new();
                    m.insert("com.test.key".to_string(), b"value".to_vec());
                    m
                },
            },
            captured_at: chrono::Utc::now(),
        };

        MetadataExporter::save_to_file(&meta, &meta_path).unwrap();
        assert!(meta_path.exists());

        let loaded = MetadataExporter::load_from_file(&meta_path).unwrap();
        assert_eq!(loaded.path, "/tmp/original.txt");
        assert_eq!(loaded.attributes.size, 2048);
        assert_eq!(loaded.ownership.owner, "alice");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_metadata_exporter_many() {
        let dir = std::env::temp_dir().join("tle_metadata_test_many");
        fs::create_dir_all(&dir).unwrap();
        let meta_path = dir.join("many_metadata.json");

        let list: Vec<MetadataSnapshot> = (0..3)
            .map(|i| MetadataSnapshot {
                path: format!("/tmp/file_{}.txt", i),
                timestamps: FileTimestamps {
                    created: Some(chrono::Utc::now()),
                    modified: Some(chrono::Utc::now()),
                    accessed: Some(chrono::Utc::now()),
                    metadata_changed: None,
                },
                permissions: FilePermissions {
                    #[cfg(unix)]
                    mode: 0o644,
                    #[cfg(unix)]
                    uid: 1000,
                    #[cfg(unix)]
                    gid: 1000,
                    #[cfg(windows)]
                    owner_sid: None,
                    #[cfg(windows)]
                    acl_entries: vec![],
                    readonly: false,
                    hidden: false,
                    system: false,
                    archive: false,
                },
                ownership: FileOwnership {
                    owner: format!("user{}", i),
                    group: "staff".to_string(),
                },
                attributes: FileAttributes {
                    size: (i as u64 + 1) * 100,
                    is_symlink: false,
                    symlink_target: None,
                    is_directory: false,
                    is_file: true,
                },
                extended_attributes: ExtendedAttributes {
                    entries: HashMap::new(),
                },
                captured_at: chrono::Utc::now(),
            })
            .collect();

        MetadataExporter::save_many_to_file(&list, &meta_path).unwrap();
        let loaded = MetadataExporter::load_many_from_file(&meta_path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[1].ownership.owner, "user1");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_read_metadata_nonexistent_file() {
        let mp = MetadataPreserver::new();
        let result = mp.read_metadata(Path::new("/nonexistent/path/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_file_attributes_directory() {
        let dir = std::env::temp_dir().join("tle_metadata_test_dir");
        fs::create_dir_all(&dir).unwrap();

        let mp = MetadataPreserver::new();
        let meta = mp.read_metadata(&dir).unwrap();
        assert!(meta.attributes.is_directory);
        assert!(!meta.attributes.is_file);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_symlink_metadata() {
        let dir = std::env::temp_dir().join("tle_metadata_test_symlink");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.txt");
        let link = dir.join("link.txt");
        fs::write(&target, b"target content").unwrap();

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let mp = MetadataPreserver::new();
            let meta = mp.read_metadata(&link).unwrap();
            assert!(meta.attributes.is_symlink);
            assert_eq!(meta.attributes.symlink_target, Some(target.to_string_lossy().to_string()));
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_extended_attributes_empty() {
        let xattrs = ExtendedAttributes {
            entries: HashMap::new(),
        };
        assert!(xattrs.entries.is_empty());
    }

    #[test]
    fn test_timestamps_serialization() {
        let ts = FileTimestamps {
            created: Some(chrono::Utc::now()),
            modified: None,
            accessed: Some(chrono::Utc::now()),
            metadata_changed: None,
        };
        let json = serde_json::to_string(&ts).unwrap();
        let deserialized: FileTimestamps = serde_json::from_str(&json).unwrap();
        assert!(deserialized.created.is_some());
        assert!(deserialized.modified.is_none());
    }

    #[test]
    fn test_from_json_invalid() {
        let result = MetadataExporter::from_json("not valid json");
        assert!(result.is_err());
    }
}
