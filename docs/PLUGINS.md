# Plugin Development Guide

## Overview

Data Doctor provides a dynamic plugin system that allows you to extend its functionality at runtime. Plugins are compiled as shared libraries (`cdylib`) and loaded on-demand via the `PluginManager`.

Plugins can transform data, add custom processing pipelines, integrate with external services, or implement custom recovery algorithms.

---

## Plugin Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Data Doctor Host                    │
│                                                      │
│  ┌──────────────────────────────────────────────────┐│
│  │                PluginManager                      ││
│  │                                                   ││
│  │  load_plugin()  ──►  libloading::Library          ││
│  │  execute_plugin() ──►  dyn Plugin (process())     ││
│  │  unload_plugin()  ──►  destroy_plugin()           ││
│  └──────────────────────────────────────────────────┘│
│                         │                            │
│              ┌──────────┼──────────┐                 │
│              ▼          ▼          ▼                 │
│        ┌─────────┐ ┌─────────┐ ┌─────────┐         │
│        │Plugin A │ │Plugin B │ │Plugin C │         │
│        │ (.so)   │ │ (.dylib)│ │ (.dll)  │         │
│        └─────────┘ └─────────┘ └─────────┘         │
└─────────────────────────────────────────────────────┘
```

### Lifecycle

1. **Load** - Shared library is loaded via `libloading`
2. **Create** - `create_plugin()` extern function is called to instantiate the plugin
3. **Init** - `init()` is called for setup
4. **Process** - `process()` is called with JSON data, returns JSON result
5. **Shutdown** - `shutdown()` is called for cleanup
6. **Destroy** - `destroy_plugin()` frees the plugin instance

---

## Plugin API Reference

### Plugin Trait

Every plugin must implement the `Plugin` trait:

```rust
pub trait Plugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn init(&mut self) -> PluginResult<()>;
    fn process(&self, data: &serde_json::Value) -> PluginResult<serde_json::Value>;
    fn shutdown(&mut self) -> PluginResult<()>;
}
```

| Method | Description |
|--------|-------------|
| `name()` | Returns the plugin's unique identifier |
| `version()` | Returns the plugin version string |
| `init()` | Called once after loading; perform setup here |
| `process(data)` | Core processing function; receives and returns JSON |
| `shutdown()` | Called before unloading; perform cleanup here |

### PluginResult

```rust
pub type PluginResult<T> = Result<T, PluginError>;
```

### PluginError

```rust
pub enum PluginError {
    LoadError(String),
    NotFound(String),
    InitError(String),
    ExecutionError(String),
    AlreadyLoaded(String),
    ConfigError(String),
    LibraryError(libloading::Error),
}
```

### PluginMetadata

```rust
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub entry_point: String,
}
```

### PluginConfig

```rust
pub struct PluginConfig {
    pub metadata: PluginMetadata,
    pub settings: Option<serde_json::Value>,
}
```

---

## Creating a Plugin

### Step 1: Create the Project

```bash
cargo new --lib my_plugin
cd my_plugin
```

### Step 2: Configure Cargo.toml

```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tle-plugins = { path = "../plugins" }
```

### Step 3: Implement the Plugin

```rust
use serde_json::Value;
use tle_plugins::{Plugin, PluginResult, PluginError};

pub struct MyPlugin {
    initialized: bool,
}

impl MyPlugin {
    pub fn new() -> Self {
        Self { initialized: false }
    }
}

impl Plugin for MyPlugin {
    fn name(&self) -> &str {
        "my_plugin"
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
            return Err(PluginError::ExecutionError(
                "Plugin not initialized".to_string(),
            ));
        }

        Ok(serde_json::json!({
            "result": "processed",
            "input": data
        }))
    }

    fn shutdown(&mut self) -> PluginResult<()> {
        self.initialized = false;
        Ok(())
    }
}
```

### Step 4: Export C Functions

You must export two `extern "C"` functions so the host can create and destroy your plugin:

```rust
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(MyPlugin::new()))
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn destroy_plugin(ptr: *mut dyn Plugin) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut MyPlugin));
        }
    }
}
```

### Step 5: Create Configuration File

Create `my_plugin.json` alongside the compiled library:

```json
{
    "metadata": {
        "name": "my_plugin",
        "version": "1.0.0",
        "description": "A custom Data Doctor plugin",
        "author": "Your Name",
        "entry_point": "create_plugin"
    },
    "settings": {
        "option1": "value1",
        "option2": 42
    }
}
```

### Step 6: Build

```bash
cargo build --release
```

The compiled library will be at:
- Linux: `target/release/libmy_plugin.so`
- macOS: `target/release/libmy_plugin.dylib`
- Windows: `target/release/my_plugin.dll`

---

## Example Plugin Walkthrough

### Hello Plugin

The included `hello_plugin` example demonstrates a minimal working plugin:

```rust
use serde_json::Value;
use tle_plugins::{Plugin, PluginResult, PluginError};

pub struct HelloPlugin {
    initialized: bool,
}

impl HelloPlugin {
    pub fn new() -> Self {
        Self { initialized: false }
    }
}

impl Plugin for HelloPlugin {
    fn name(&self) -> &str {
        "hello_plugin"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn init(&mut self) -> PluginResult<()> {
        self.initialized = true;
        println!("HelloPlugin initialized!");
        Ok(())
    }

    fn process(&self, data: &Value) -> PluginResult<Value> {
        if !self.initialized {
            return Err(PluginError::ExecutionError(
                "Plugin not initialized".to_string(),
            ));
        }

        let name = data.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("World");

        let greeting = format!("Hello, {}! Greetings from the plugin system!", name);

        Ok(serde_json::json!({
            "greeting": greeting,
            "plugin": self.name(),
            "version": self.version(),
            "input": data
        }))
    }

    fn shutdown(&mut self) -> PluginResult<()> {
        self.initialized = false;
        println!("HelloPlugin shutdown!");
        Ok(())
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(HelloPlugin::new()))
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn destroy_plugin(ptr: *mut dyn Plugin) {
    if !ptr.is_null() {
        unsafe {
            drop(Box::from_raw(ptr as *mut HelloPlugin));
        }
    }
}
```

### Build and Run the Example

```bash
cd plugins
cargo build --example hello_plugin
```

---

## Using Plugins from Host Code

### PluginManager

```rust
use tle_plugins::PluginManager;

let mut manager = PluginManager::new();
```

### Methods

#### `PluginManager::new() -> Self`

Creates a new plugin manager.

#### `manager.load_plugin(path: impl AsRef<Path>) -> PluginResult<String>`

Loads a plugin from a shared library path. Automatically reads the companion `.json` config file.

```rust
let plugin_name = manager.load_plugin("target/release/libmy_plugin.so")?;
```

#### `manager.init_plugin(name: &str) -> PluginResult<()>`

Initializes a loaded plugin by calling its `init()` method.

```rust
manager.init_plugin(&plugin_name)?;
```

#### `manager.execute_plugin(name: &str, data: &serde_json::Value) -> PluginResult<serde_json::Value>`

Executes a plugin's `process()` method with the given input data.

```rust
let input = serde_json::json!({"name": "Data Doctor"});
let result = manager.execute_plugin(&plugin_name, &input)?;
println!("{}", result["greeting"]);
```

#### `manager.shutdown_plugin(name: &str) -> PluginResult<()>`

Shuts down a plugin by calling its `shutdown()` method.

#### `manager.unload_plugin(name: &str) -> PluginResult<()>`

Unloads a plugin, freeing the shared library. Calls `destroy_plugin()` internally.

#### `manager.list_plugins() -> Vec<&PluginMetadata>`

Lists all currently loaded plugins.

---

## Advanced Plugin Patterns

### Configuration Access

Read settings from the plugin's JSON config:

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct MySettings {
    api_key: String,
    timeout_ms: u64,
}

impl Plugin for MyPlugin {
    fn init(&mut self) -> PluginResult<()> {
        // Settings would be passed during construction or loaded from file
        Ok(())
    }
}
```

### Error Handling

Always check initialization state and return descriptive errors:

```rust
fn process(&self, data: &Value) -> PluginResult<Value> {
    if !self.initialized {
        return Err(PluginError::ExecutionError(
            "Plugin not initialized. Call init() first.".to_string(),
        ));
    }

    if data.get("required_field").is_none() {
        return Err(PluginError::ExecutionError(
            "Missing required field: required_field".to_string(),
        ));
    }

    // Process data...
    Ok(serde_json::json!({"status": "ok"}))
}
```

### Thread Safety

If your plugin will be called from multiple threads, use interior mutability:

```rust
use std::sync::Mutex;

pub struct ThreadSafePlugin {
    state: Mutex<Vec<String>>,
}

impl Plugin for ThreadSafePlugin {
    fn process(&self, data: &Value) -> PluginResult<Value> {
        let mut state = self.state.lock().unwrap();
        state.push(data.to_string());
        Ok(serde_json::json!({"items": state.len()}))
    }
}
```

### Resource Cleanup

Release resources in `shutdown()`:

```rust
impl Plugin for NetworkPlugin {
    fn shutdown(&mut self) -> PluginResult<()> {
        // Close network connections
        // Flush buffers
        // Release file handles
        Ok(())
    }
}
```

---

## Testing Plugins

### Unit Testing the Plugin Logic

Test your plugin logic without the dynamic loading overhead:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_name() {
        let plugin = MyPlugin::new();
        assert_eq!(plugin.name(), "my_plugin");
    }

    #[test]
    fn test_plugin_version() {
        let plugin = MyPlugin::new();
        assert_eq!(plugin.version(), "1.0.0");
    }

    #[test]
    fn test_init_and_process() {
        let mut plugin = MyPlugin::new();
        plugin.init().unwrap();

        let input = serde_json::json!({"key": "value"});
        let result = plugin.process(&input).unwrap();

        assert_eq!(result["result"], "processed");
    }

    #[test]
    fn test_process_without_init() {
        let plugin = MyPlugin::new();
        let input = serde_json::json!({});
        let result = plugin.process(&input);

        assert!(result.is_err());
    }

    #[test]
    fn test_shutdown() {
        let mut plugin = MyPlugin::new();
        plugin.init().unwrap();
        plugin.shutdown().unwrap();

        let input = serde_json::json!({});
        let result = plugin.process(&input);
        assert!(result.is_err());
    }
}
```

### Integration Testing with PluginManager

Test the full load/init/process/unload cycle:

```rust
#[cfg(test)]
mod integration_tests {
    use tle_plugins::PluginManager;
    use std::io::Write;

    #[test]
    fn test_load_and_execute() {
        let mut manager = PluginManager::new();

        // Create a config file for testing
        let config = serde_json::json!({
            "metadata": {
                "name": "test_plugin",
                "version": "1.0.0",
                "description": null,
                "author": null,
                "entry_point": "create_plugin"
            },
            "settings": null
        });

        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        config_file
            .write_all(serde_json::to_string_pretty(&config).unwrap().as_bytes())
            .unwrap();

        // The shared library should be built before running this test
        let lib_path = "target/release/libtest_plugin.so"; // adjust per platform

        if std::path::Path::new(lib_path).exists() {
            let name = manager.load_plugin(lib_path).unwrap();
            manager.init_plugin(&name).unwrap();

            let result = manager.execute_plugin(&name, &serde_json::json!({"test": true})).unwrap();
            assert!(result.is_object());

            manager.shutdown_plugin(&name).unwrap();
            manager.unload_plugin(&name).unwrap();
        }
    }

    #[test]
    fn test_list_plugins() {
        let manager = PluginManager::new();
        assert_eq!(manager.list_plugins().len(), 0);
    }

    #[test]
    fn test_execute_nonexistent_plugin() {
        let manager = PluginManager::new();
        let result = manager.execute_plugin("nonexistent", &serde_json::json!({}));
        assert!(matches!(result, Err(tle_plugins::PluginError::NotFound(_))));
    }
}
```

### Running Tests

```bash
# Run all plugin tests
cargo test -p tle-plugins

# Run a specific plugin's tests
cargo test -p my-plugin

# Build example plugin
cargo build --example hello_plugin
```

---

## Platform Notes

| Platform | Library Extension | Notes |
|----------|-------------------|-------|
| Linux | `.so` | Standard ELF shared object |
| macOS | `.dylib` | Mach-O dynamic library |
| Windows | `.dll` | PE dynamic link library |

### Build Commands by Platform

```bash
# Linux
cargo build --release
# Output: target/release/libmy_plugin.so

# macOS
cargo build --release
# Output: target/release/libmy_plugin.dylib

# Windows
cargo build --release
# Output: target/release/my_plugin.dll
```

---

## Best Practices

1. **Always check initialization state** before processing data
2. **Return descriptive errors** with context about what failed
3. **Clean up resources** in `shutdown()` (file handles, network connections, memory)
4. **Use thread-safe types** if the plugin may be called concurrently
5. **Keep `process()` pure** - avoid side effects where possible
6. **Document your plugin's expected input/output** JSON schema
7. **Version your plugin** using semantic versioning
8. **Handle missing fields gracefully** with sensible defaults
9. **Test the full lifecycle** (load -> init -> process -> shutdown -> unload)
10. **Ship the `.json` config file** alongside the compiled library

---

## Plugin Ideas

| Plugin Type | Description |
|-------------|-------------|
| Custom File Carver | Add support for proprietary file formats |
| Data Transformer | Convert recovered files to different formats |
| External Integration | Upload results to cloud storage or databases |
| Custom Reporter | Generate reports in PDF, HTML, or custom formats |
| Filter Plugin | Apply custom filtering rules to recovered files |
| Enrichment Plugin | Add metadata from external sources |
| Notification Plugin | Send alerts via email, Slack, or webhooks |
| Validation Plugin | Verify recovered file integrity with custom checksums |
