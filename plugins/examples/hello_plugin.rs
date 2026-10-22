use serde_json::Value;
use tle_plugins::{Plugin, PluginResult, PluginError};

#[allow(improper_ctypes_definitions)]
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
            return Err(PluginError::ExecutionError("Plugin not initialized".to_string()));
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
