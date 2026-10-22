use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Failed to load plugin: {0}")]
    LoadError(String),
    #[error("Plugin not found: {0}")]
    NotFound(String),
    #[error("Plugin initialization failed: {0}")]
    InitError(String),
    #[error("Plugin execution failed: {0}")]
    ExecutionError(String),
    #[error("Plugin already loaded: {0}")]
    AlreadyLoaded(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Library error: {0}")]
    LibraryError(#[from] libloading::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub entry_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub metadata: PluginMetadata,
    pub settings: Option<serde_json::Value>,
}

pub type PluginResult<T> = Result<T, PluginError>;

pub trait Plugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn init(&mut self) -> PluginResult<()>;
    fn process(&self, data: &serde_json::Value) -> PluginResult<serde_json::Value>;
    fn shutdown(&mut self) -> PluginResult<()>;
}

type PluginCreateFn = unsafe fn() -> *mut dyn Plugin;
type PluginDestroyFn = unsafe fn(*mut dyn Plugin);

struct LoadedPlugin {
    library: Library,
    instance: *mut dyn Plugin,
    metadata: PluginMetadata,
}

pub struct PluginManager {
    plugins: HashMap<String, LoadedPlugin>,
    plugin_paths: HashMap<String, PathBuf>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            plugin_paths: HashMap::new(),
        }
    }

    pub fn load_plugin<P: AsRef<Path>>(&mut self, path: P) -> PluginResult<String> {
        let path = path.as_ref().to_path_buf();
        
        let config_path = path.with_extension("json");
        let metadata = if config_path.exists() {
            let config_content = std::fs::read_to_string(&config_path)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
            let config: PluginConfig = serde_json::from_str(&config_content)
                .map_err(|e| PluginError::ConfigError(e.to_string()))?;
            config.metadata
        } else {
            return Err(PluginError::ConfigError(
                "Plugin configuration file not found".to_string(),
            ));
        };

        if self.plugins.contains_key(&metadata.name) {
            return Err(PluginError::AlreadyLoaded(metadata.name.clone()));
        }

        unsafe {
            let lib = Library::new(&path)?;
            
            let create_fn: Symbol<PluginCreateFn> = lib.get(metadata.entry_point.as_bytes())?;
            
            let instance = create_fn();
            
            self.plugins.insert(
                metadata.name.clone(),
                LoadedPlugin {
                    library: lib,
                    instance,
                    metadata: metadata.clone(),
                },
            );
            self.plugin_paths.insert(metadata.name.clone(), path);
            
            Ok(metadata.name)
        }
    }

    pub fn unload_plugin(&mut self, name: &str) -> PluginResult<()> {
        if let Some(loaded) = self.plugins.remove(name) {
            unsafe {
                let destroy_fn: Symbol<PluginDestroyFn> = 
                    loaded.library.get(b"destroy_plugin")?;
                destroy_fn(loaded.instance);
            }
            self.plugin_paths.remove(name);
            Ok(())
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    pub fn list_plugins(&self) -> Vec<&PluginMetadata> {
        self.plugins.values().map(|p| &p.metadata).collect()
    }

    pub fn execute_plugin(
        &self,
        name: &str,
        data: &serde_json::Value,
    ) -> PluginResult<serde_json::Value> {
        if let Some(loaded) = self.plugins.get(name) {
            unsafe {
                let plugin = &*loaded.instance;
                plugin.process(data)
            }
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    pub fn init_plugin(&mut self, name: &str) -> PluginResult<()> {
        if let Some(loaded) = self.plugins.get_mut(name) {
            unsafe {
                let plugin = &mut *loaded.instance;
                plugin.init()
            }
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }

    pub fn shutdown_plugin(&mut self, name: &str) -> PluginResult<()> {
        if let Some(loaded) = self.plugins.get_mut(name) {
            unsafe {
                let plugin = &mut *loaded.instance;
                plugin.shutdown()
            }
        } else {
            Err(PluginError::NotFound(name.to_string()))
        }
    }
}

impl Drop for PluginManager {
    fn drop(&mut self) {
        for name in self.plugins.keys().cloned().collect::<Vec<_>>() {
            let _ = self.unload_plugin(&name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct MockPlugin {
        initialized: bool,
    }

    impl Plugin for MockPlugin {
        fn name(&self) -> &str {
            "mock_plugin"
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        fn init(&mut self) -> PluginResult<()> {
            self.initialized = true;
            Ok(())
        }

        fn process(&self, data: &serde_json::Value) -> PluginResult<serde_json::Value> {
            if !self.initialized {
                return Err(PluginError::ExecutionError("Plugin not initialized".to_string()));
            }
            
            let mut result = data.clone();
            if let Some(obj) = result.as_object_mut() {
                obj.insert("processed".to_string(), serde_json::json!(true));
            }
            Ok(result)
        }

        fn shutdown(&mut self) -> PluginResult<()> {
            self.initialized = false;
            Ok(())
        }
    }

    #[test]
    fn test_plugin_manager_creation() {
        let manager = PluginManager::new();
        assert_eq!(manager.list_plugins().len(), 0);
    }

    #[test]
    fn test_plugin_metadata_serialization() {
        let metadata = PluginMetadata {
            name: "test_plugin".to_string(),
            version: "1.0.0".to_string(),
            description: Some("A test plugin".to_string()),
            author: Some("Test Author".to_string()),
            entry_point: "create_plugin".to_string(),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: PluginMetadata = serde_json::from_str(&json).unwrap();
        
        assert_eq!(metadata.name, deserialized.name);
        assert_eq!(metadata.version, deserialized.version);
    }

    #[test]
    fn test_plugin_config_serialization() {
        let config = PluginConfig {
            metadata: PluginMetadata {
                name: "test_plugin".to_string(),
                version: "1.0.0".to_string(),
                description: None,
                author: None,
                entry_point: "create_plugin".to_string(),
            },
            settings: Some(serde_json::json!({"key": "value"})),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PluginConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.metadata.name, deserialized.metadata.name);
        assert!(deserialized.settings.is_some());
    }

    #[test]
    fn test_mock_plugin() {
        let mut plugin = MockPlugin { initialized: false };
        
        assert_eq!(plugin.name(), "mock_plugin");
        assert_eq!(plugin.version(), "1.0.0");
        
        plugin.init().unwrap();
        assert!(plugin.initialized);
        
        let input = serde_json::json!({"data": "test"});
        let result = plugin.process(&input).unwrap();
        
        assert!(result["processed"].as_bool().unwrap());
        assert_eq!(result["data"], "test");
        
        plugin.shutdown().unwrap();
        assert!(!plugin.initialized);
    }

    #[test]
    fn test_plugin_not_found() {
        let manager = PluginManager::new();
        let result = manager.execute_plugin("nonexistent", &serde_json::json!({}));
        
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }

    #[test]
    fn test_plugin_config_file() {
        let config = PluginConfig {
            metadata: PluginMetadata {
                name: "file_test_plugin".to_string(),
                version: "2.0.0".to_string(),
                description: Some("File test".to_string()),
                author: None,
                entry_point: "create_plugin".to_string(),
            },
            settings: Some(serde_json::json!({"setting1": 42})),
        };

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        let json = serde_json::to_string_pretty(&config).unwrap();
        temp_file.write_all(json.as_bytes()).unwrap();
        
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        let loaded: PluginConfig = serde_json::from_str(&content).unwrap();
        
        assert_eq!(loaded.metadata.name, "file_test_plugin");
        assert_eq!(loaded.metadata.version, "2.0.0");
    }

    #[test]
    fn test_unload_nonexistent_plugin() {
        let mut manager = PluginManager::new();
        let result = manager.unload_plugin("nonexistent");
        
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }

    #[test]
    fn test_init_nonexistent_plugin() {
        let mut manager = PluginManager::new();
        let result = manager.init_plugin("nonexistent");
        
        assert!(matches!(result, Err(PluginError::NotFound(_))));
    }
}
