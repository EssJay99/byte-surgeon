use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use tle_plugins::{Plugin, PluginError, PluginResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileSignature {
    id: String,
    name: String,
    description: Option<String>,
    offset: usize,
    magic_bytes: String,
    category: Option<String>,
    extensions: Vec<String>,
}

#[allow(improper_ctypes_definitions)]
pub struct CustomSignaturePlugin {
    initialized: bool,
    signatures: RefCell<Vec<FileSignature>>,
    signature_index: RefCell<HashMap<String, Vec<usize>>>,
    signatures_path: RefCell<Option<PathBuf>>,
}

impl CustomSignaturePlugin {
    pub fn new() -> Self {
        Self {
            initialized: false,
            signatures: RefCell::new(Vec::new()),
            signature_index: RefCell::new(HashMap::new()),
            signatures_path: RefCell::new(None),
        }
    }

    fn load_signatures_from_file(&self, path: &str) -> PluginResult<usize> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PluginError::ConfigError(format!("Failed to read signatures file: {}", e)))?;

        let sigs: Vec<FileSignature> = serde_json::from_str(&content)
            .map_err(|e| PluginError::ConfigError(format!("Failed to parse signatures: {}", e)))?;

        let count = sigs.len();
        self.build_index(&sigs);
        *self.signatures.borrow_mut() = sigs;
        *self.signatures_path.borrow_mut() = Some(PathBuf::from(path));

        Ok(count)
    }

    fn load_builtin_signatures(&self) {
        let builtins = vec![
            FileSignature {
                id: "sig-png".into(),
                name: "PNG Image".into(),
                description: Some("Portable Network Graphics".into()),
                offset: 0,
                magic_bytes: "89504E470D0A1A0A".into(),
                category: Some("image".into()),
                extensions: vec!["png".into()],
            },
            FileSignature {
                id: "sig-jpeg".into(),
                name: "JPEG Image".into(),
                description: Some("Joint Photographic Experts Group".into()),
                offset: 0,
                magic_bytes: "FFD8FF".into(),
                category: Some("image".into()),
                extensions: vec!["jpg".into(), "jpeg".into()],
            },
            FileSignature {
                id: "sig-pdf".into(),
                name: "PDF Document".into(),
                description: Some("Portable Document Format".into()),
                offset: 0,
                magic_bytes: "25504446".into(),
                category: Some("document".into()),
                extensions: vec!["pdf".into()],
            },
            FileSignature {
                id: "sig-zip".into(),
                name: "ZIP Archive".into(),
                description: Some("ZIP compressed archive".into()),
                offset: 0,
                magic_bytes: "504B0304".into(),
                category: Some("archive".into()),
                extensions: vec!["zip".into()],
            },
            FileSignature {
                id: "sig-elf".into(),
                name: "ELF Binary".into(),
                description: Some("Executable and Linkable Format".into()),
                offset: 0,
                magic_bytes: "7F454C46".into(),
                category: Some("executable".into()),
                extensions: vec!["elf".into(), "so".into(), "bin".into()],
            },
            FileSignature {
                id: "sig-sqlite".into(),
                name: "SQLite Database".into(),
                description: Some("SQLite 3 database file".into()),
                offset: 0,
                magic_bytes: "53514C69746520666F726D6174203300".into(),
                category: Some("database".into()),
                extensions: vec!["db".into(), "sqlite".into(), "sqlite3".into()],
            },
        ];
        self.build_index(&builtins);
        *self.signatures.borrow_mut() = builtins;
    }

    fn build_index(&self, sigs: &[FileSignature]) {
        let mut index = self.signature_index.borrow_mut();
        index.clear();
        for (idx, sig) in sigs.iter().enumerate() {
            index
                .entry(sig.magic_bytes.clone())
                .or_default()
                .push(idx);
        }
    }

    fn match_signatures(&self, hex_data: &str) -> Vec<FileSignature> {
        let upper = hex_data.to_uppercase();
        let mut matches = Vec::new();
        let signatures = self.signatures.borrow();

        for sig in signatures.iter() {
            let end = sig.offset + sig.magic_bytes.len();
            if upper.len() >= end {
                let slice = &upper[sig.offset..end];
                if slice == sig.magic_bytes {
                    matches.push(sig.clone());
                }
            }
        }

        matches
    }
}

impl Plugin for CustomSignaturePlugin {
    fn name(&self) -> &str {
        "custom_signature_plugin"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn init(&mut self) -> PluginResult<()> {
        self.initialized = true;
        self.load_builtin_signatures();
        Ok(())
    }

    fn process(&self, data: &Value) -> PluginResult<Value> {
        if !self.initialized {
            return Err(PluginError::ExecutionError("Plugin not initialized".into()));
        }

        let action = data
            .get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("scan");

        match action {
            "scan" => {
                let hex_data = data
                    .get("data")
                    .and_then(|d| d.as_str())
                    .ok_or_else(|| {
                        PluginError::ExecutionError("Missing 'data' field with hex content".into())
                    })?;

                let matches = self.match_signatures(hex_data);
                let results: Vec<Value> = matches
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "name": s.name,
                            "description": s.description,
                            "category": s.category,
                            "extensions": s.extensions,
                            "confidence": "high",
                        })
                    })
                    .collect();

                Ok(serde_json::json!({
                    "status": "success",
                    "plugin": self.name(),
                    "matches_found": results.len(),
                    "matches": results,
                    "data_length": hex_data.len(),
                }))
            }
            "load_custom" => {
                let path = data
                    .get("signatures_path")
                    .and_then(|p| p.as_str())
                    .ok_or_else(|| {
                        PluginError::ExecutionError("Missing 'signatures_path' field".into())
                    })?;

                let count = self.load_signatures_from_file(path)?;
                let total = self.signatures.borrow().len();
                Ok(serde_json::json!({
                    "status": "success",
                    "loaded": count,
                    "total_signatures": total,
                    "message": format!("Loaded {} custom signatures from {}", count, path),
                }))
            }
            "list" => {
                let signatures = self.signatures.borrow();
                let categories: HashMap<String, usize> = signatures
                    .iter()
                    .fold(HashMap::new(), |mut acc, s| {
                        let cat = s.category.clone().unwrap_or_else(|| "unknown".into());
                        *acc.entry(cat).or_insert(0) += 1;
                        acc
                    });

                let sigs_data: Vec<Value> = signatures
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id,
                            "name": s.name,
                            "category": s.category,
                            "extensions": s.extensions,
                        })
                    })
                    .collect();

                Ok(serde_json::json!({
                    "status": "success",
                    "total_signatures": signatures.len(),
                    "categories": categories,
                    "signatures": sigs_data,
                }))
            }
            "add" => {
                let sig: FileSignature =
                    serde_json::from_value(data.get("signature").cloned().unwrap_or_default())
                        .map_err(|e| {
                            PluginError::ExecutionError(format!("Invalid signature: {}", e))
                        })?;

                let id = sig.id.clone();
                let mut sigs = self.signatures.borrow().clone();
                sigs.push(sig);
                self.build_index(&sigs);
                *self.signatures.borrow_mut() = sigs;

                Ok(serde_json::json!({
                    "status": "success",
                    "message": format!("Signature '{}' added", id),
                }))
            }
            _ => Err(PluginError::ExecutionError(format!(
                "Unknown action '{}'. Valid: scan, load_custom, list, add",
                action
            ))),
        }
    }

    fn shutdown(&mut self) -> PluginResult<()> {
        self.signatures.borrow_mut().clear();
        self.signature_index.borrow_mut().clear();
        self.initialized = false;
        Ok(())
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(CustomSignaturePlugin::new()))
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn destroy_plugin(ptr: *mut dyn Plugin) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut CustomSignaturePlugin));
        }
    }
}
