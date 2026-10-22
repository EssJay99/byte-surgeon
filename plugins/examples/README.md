# TLE Plugin Examples

Example plugins demonstrating the TLE plugin system capabilities and best practices.

## Examples

### 1. Custom Signature Plugin (`custom_signature_plugin/`)

Extends TLE with custom file signature scanning. Loads magic-byte signatures from JSON files for identifying file types in raw data streams.

**Key Features:**
- Built-in signatures for common file types (PNG, JPEG, PDF, ZIP, ELF, SQLite)
- Dynamic loading of custom signature sets from JSON files
- Hex-pattern matching at configurable offsets
- Category-based signature organization

**Actions:**
- `scan` - Match hex-encoded data against loaded signatures
- `load_custom` - Load additional signatures from a JSON file
- `list` - List all loaded signatures and categories
- `add` - Register a new signature at runtime

**Usage Example:**
```json
{
  "action": "scan",
  "data": "89504E470D0A1A0A0000000D49484452"
}
```

---

### 2. Cloud Storage Plugin (`cloud_storage_plugin/`)

Simulates cloud storage recovery for AWS S3, Azure Blob Storage, and Google Cloud Storage. Demonstrates external service integration patterns for forensic evidence retrieval.

**Key Features:**
- Multi-provider simulation (AWS S3, Azure Blob, GCS)
- Bucket/container enumeration with forensic metadata
- Recovery simulation for deleted objects
- Storage class awareness (Standard, IA, Glacier, Cool, Nearline)

**Actions:**
- `list_buckets` - Enumerate available cloud storage buckets
- `list_objects` - List objects in a specific bucket
- `recover` - Simulate recovery of deleted objects from a bucket
- `recover_all` - Run recovery across all registered buckets

**Usage Example:**
```json
{
  "action": "recover",
  "bucket": "evidence-bucket-001"
}
```

---

### 3. Advanced Forensics Plugin (`advanced_forensics_plugin/`)

Advanced forensic timeline analysis with MACB (Modified, Accessed, Changed, Born) timestamp correlation, suspicious activity clustering, and anomaly detection.

**Key Features:**
- MACB timestamp analysis and distribution
- Time-based event clustering for suspicious activity detection
- Anomaly detection for deletions and permission changes
- Hourly activity distribution for pattern analysis
- Built-in sample events for demonstration

**Actions:**
- `analyze` - Run full timeline analysis on provided events
- `sample` - Generate sample events and run analysis
- `macb_summary` - Summarize MACB flag distribution

**Usage Example:**
```json
{
  "action": "analyze",
  "events": [
    {
      "timestamp": "2024-03-15T08:00:00Z",
      "event_type": "file_created",
      "path": "/home/user/document.txt",
      "macb": { "modified": true, "accessed": false, "changed": true, "born": true },
      "size": 1024,
      "metadata": {}
    }
  ]
}
```

---

## Plugin Interface

All plugins implement the `Plugin` trait from `tle-plugins`:

```rust
pub trait Plugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn init(&mut self) -> PluginResult<()>;
    fn process(&self, data: &serde_json::Value) -> PluginResult<serde_json::Value>;
    fn shutdown(&mut self) -> PluginResult<()>;
}
```

Each plugin exports two C functions for dynamic loading:
- `create_plugin()` - Creates and returns a boxed plugin instance
- `destroy_plugin(ptr)` - Safely destroys a plugin instance

## Building

Each plugin is a standalone Cargo package producing a dynamic library:

```bash
# Build a specific plugin
cd custom_signature_plugin
cargo build --release

# The output will be:
# Linux:   target/release/libcustom_signature_plugin.so
# macOS:   target/release/libcustom_signature_plugin.dylib
# Windows: target/release/custom_signature_plugin.dll
```

## Loading Plugins

```rust
use tle_plugins::PluginManager;

let mut manager = PluginManager::new();

// Load plugin (looks for plugin.json alongside the library)
manager.load_plugin("target/release/libcustom_signature_plugin.so")?;

// Initialize
manager.init_plugin("custom_signature_plugin")?;

// Execute
let result = manager.execute_plugin(
    "custom_signature_plugin",
    &serde_json::json!({"action": "scan", "data": "89504E470D0A1A0A"}),
)?;

// Shutdown and unload
manager.shutdown_plugin("custom_signature_plugin")?;
manager.unload_plugin("custom_signature_plugin")?;
```

## Configuration

Each plugin ships with a `plugin.json` configuration file containing:
- `metadata` - Plugin name, version, description, author, and entry point
- `settings` - Plugin-specific configuration options

The PluginManager automatically loads the JSON config when loading a plugin library.

## Best Practices

1. **Error handling** - Always check initialization state in `process()`
2. **Resource cleanup** - Release resources in `shutdown()`
3. **Thread safety** - Keep plugin state immutable where possible
4. **Input validation** - Validate all input data before processing
5. **Documentation** - Document expected input/output JSON schemas
6. **Configuration** - Use `plugin.json` settings for tunable parameters

## Platform Support

| Platform | Library Extension |
|----------|------------------|
| Linux    | `.so`            |
| macOS    | `.dylib`         |
| Windows  | `.dll`           |
