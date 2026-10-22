# TLE Plugin System

A dynamic plugin architecture for extending TLE functionality without recompilation.

## Features

- **Dynamic Loading**: Load plugins at runtime from shared libraries (.so/.dylib/.dll)
- **JSON Configuration**: Plugin metadata and settings via JSON config files
- **Type-Safe Interface**: Rust trait-based plugin API
- **Lifecycle Management**: Init, process, and shutdown hooks
- **Error Handling**: Comprehensive error types with thiserror

## Architecture

### Plugin Trait

All plugins must implement the `Plugin` trait:

```rust
pub trait Plugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn init(&mut self) -> PluginResult<()>;
    fn process(&self, data: &serde_json::Value) -> PluginResult<serde_json::Value>;
    fn shutdown(&mut self) -> PluginResult<()>;
}
```

### PluginManager

Manages plugin lifecycle and execution:

```rust
let mut manager = PluginManager::new();

// Load plugin from shared library
manager.load_plugin("path/to/plugin.so")?;

// Initialize plugin
manager.init_plugin("plugin_name")?;

// Execute plugin
let result = manager.execute_plugin("plugin_name", &json_data)?;

// Shutdown and unload
manager.shutdown_plugin("plugin_name")?;
manager.unload_plugin("plugin_name")?;
```

## Creating a Plugin

### 1. Define Plugin Structure

```rust
use tle_plugins::{Plugin, PluginResult, PluginError};
use serde_json::Value;

pub struct MyPlugin {
    initialized: bool,
}

impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }
    fn version(&self) -> &str { "1.0.0" }
    
    fn init(&mut self) -> PluginResult<()> {
        self.initialized = true;
        Ok(())
    }
    
    fn process(&self, data: &Value) -> PluginResult<Value> {
        if !self.initialized {
            return Err(PluginError::ExecutionError("Not initialized".into()));
        }
        // Process data here
        Ok(data.clone())
    }
    
    fn shutdown(&mut self) -> PluginResult<()> {
        self.initialized = false;
        Ok(())
    }
}
```

### 2. Export C Functions

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
        unsafe { drop(Box::from_raw(ptr as *mut MyPlugin)); }
    }
}
```

### 3. Create Configuration File

Create `my_plugin.json`:

```json
{
  "metadata": {
    "name": "my_plugin",
    "version": "1.0.0",
    "description": "My custom plugin",
    "author": "Your Name",
    "entry_point": "create_plugin"
  },
  "settings": {
    "custom_setting": "value"
  }
}
```

### 4. Build as Dynamic Library

In `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]
```

Build with:
```bash
cargo build --release
```

## Plugin Configuration Schema

See `config/plugin.schema.json` for the complete JSON schema.

Required fields:
- `metadata.name`: Unique plugin identifier
- `metadata.version`: Semantic version
- `metadata.entry_point`: Function name to create plugin instance

Optional fields:
- `metadata.description`: Human-readable description
- `metadata.author`: Author/maintainer
- `settings`: Plugin-specific configuration

## Example Plugin

See `examples/hello_plugin.rs` for a complete working example.

Build the example:
```bash
cargo build --example hello_plugin
```

## Testing

Run unit tests:
```bash
cargo test --lib
```

## Error Handling

The plugin system provides comprehensive error types:

- `LoadError`: Failed to load plugin library
- `NotFound`: Plugin not found in manager
- `InitError`: Plugin initialization failed
- `ExecutionError`: Plugin execution failed
- `AlreadyLoaded`: Plugin already loaded
- `ConfigError`: Configuration file error

## Platform Support

- **Linux**: `.so` files
- **macOS**: `.dylib` files
- **Windows**: `.dll` files

## Security Considerations

- Plugins run in the same process as the host application
- Validate plugin signatures in production environments
- Sandboxing is recommended for untrusted plugins
- Review plugin code before loading

## License

Proprietary - Part of TLE suite
