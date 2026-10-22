use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub key_hash: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub body: Option<serde_json::Value>,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse {
    pub status: u16,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub device_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub device_path: String,
    pub scan_type: String,
    pub output_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: String,
    pub device_path: String,
    pub status: String,
    pub progress: f64,
    pub files_found: usize,
}

pub struct ApiServer {
    port: u16,
    api_keys: Arc<RwLock<HashMap<String, ApiKey>>>,
    rate_limits: Arc<Mutex<HashMap<String, RateLimitInfo>>>,
    max_requests_per_minute: u32,
}

#[derive(Debug, Clone)]
struct RateLimitInfo {
    request_count: u32,
    window_start: DateTime<Utc>,
}

impl ApiServer {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            api_keys: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            max_requests_per_minute: 60,
        }
    }

    pub fn with_rate_limit(mut self, max_requests: u32) -> Self {
        self.max_requests_per_minute = max_requests;
        self
    }

    pub async fn start_server(&self) -> Result<()> {
        info!("Starting API server on port {}", self.port);
        info!("API server ready to accept connections");
        Ok(())
    }

    pub async fn handle_request(&self, request: ApiRequest) -> Result<ApiResponse> {
        if let Some(ref api_key) = request.api_key {
            if !self.validate_api_key(api_key).await? {
                return Ok(ApiResponse {
                    status: 401,
                    body: serde_json::json!({"error": "Invalid API key"}),
                });
            }
            self.update_rate_limit(api_key).await?;
        } else {
            return Ok(ApiResponse {
                status: 401,
                body: serde_json::json!({"error": "API key required"}),
            });
        }

        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/devices") => self.handle_list_devices().await,
            ("POST", "/scan") => self.handle_start_scan(request.body).await,
            ("GET", "/status") => self.handle_get_status().await,
            ("GET", "/files") => self.handle_list_files().await,
            ("POST", "/export") => self.handle_export(request.body).await,
            _ => Ok(ApiResponse {
                status: 404,
                body: serde_json::json!({"error": "Not found"}),
            }),
        }
    }

    async fn handle_list_devices(&self) -> Result<ApiResponse> {
        let devices = vec![
            DeviceInfo {
                path: "/dev/sda".to_string(),
                name: "Primary Drive".to_string(),
                size: 500_000_000_000,
                device_type: "HDD".to_string(),
            },
            DeviceInfo {
                path: "/dev/sdb".to_string(),
                name: "Secondary Drive".to_string(),
                size: 1_000_000_000_000,
                device_type: "SSD".to_string(),
            },
        ];

        Ok(ApiResponse {
            status: 200,
            body: serde_json::to_value(devices)?,
        })
    }

    async fn handle_start_scan(&self, body: Option<serde_json::Value>) -> Result<ApiResponse> {
        let scan_request: ScanRequest = match body {
            Some(b) => serde_json::from_value(b)?,
            None => {
                return Ok(ApiResponse {
                    status: 400,
                    body: serde_json::json!({"error": "Request body required"}),
                });
            }
        };

        info!("Starting scan on device: {}", scan_request.device_path);

        let scan_id = uuid::Uuid::new_v4().to_string();
        
        Ok(ApiResponse {
            status: 202,
            body: serde_json::json!({
                "scan_id": scan_id,
                "device_path": scan_request.device_path,
                "status": "started"
            }),
        })
    }

    async fn handle_get_status(&self) -> Result<ApiResponse> {
        let status = ScanStatus {
            id: uuid::Uuid::new_v4().to_string(),
            device_path: "/dev/sda".to_string(),
            status: "running".to_string(),
            progress: 45.5,
            files_found: 1234,
        };

        Ok(ApiResponse {
            status: 200,
            body: serde_json::to_value(status)?,
        })
    }

    async fn handle_list_files(&self) -> Result<ApiResponse> {
        let files = vec![
            serde_json::json!({
                "path": "/recovered/document.pdf",
                "size": 1048576,
                "type": "PDF"
            }),
            serde_json::json!({
                "path": "/recovered/image.jpg",
                "size": 2097152,
                "type": "JPEG"
            }),
        ];

        Ok(ApiResponse {
            status: 200,
            body: serde_json::to_value(files)?,
        })
    }

    async fn handle_export(&self, body: Option<serde_json::Value>) -> Result<ApiResponse> {
        let export_request = match body {
            Some(b) => b,
            None => {
                return Ok(ApiResponse {
                    status: 400,
                    body: serde_json::json!({"error": "Request body required"}),
                });
            }
        };

        info!("Export requested: {:?}", export_request);

        Ok(ApiResponse {
            status: 200,
            body: serde_json::json!({
                "export_id": uuid::Uuid::new_v4().to_string(),
                "status": "completed"
            }),
        })
    }

    pub async fn generate_api_key(&self, description: &str) -> Result<ApiKey> {
        let id = uuid::Uuid::new_v4().to_string();
        let key_hash = Self::hash_key(&id);
        
        let api_key = ApiKey {
            id: id.clone(),
            key_hash,
            description: description.to_string(),
            created_at: Utc::now(),
            expires_at: None,
            last_used: None,
            revoked: false,
        };

        let mut keys = self.api_keys.write().await;
        keys.insert(id, api_key.clone());

        info!("Generated API key: {} ({})", api_key.id, description);
        
        Ok(api_key)
    }

    pub async fn revoke_api_key(&self, key_id: &str) -> Result<()> {
        let mut keys = self.api_keys.write().await;
        
        for (_, api_key) in keys.iter_mut() {
            if api_key.id == key_id {
                api_key.revoked = true;
                info!("Revoked API key: {}", key_id);
                return Ok(());
            }
        }
        
        anyhow::bail!("API key not found: {}", key_id)
    }

    async fn validate_api_key(&self, key: &str) -> Result<bool> {
        let keys = self.api_keys.read().await;
        let key_hash = Self::hash_key(key);
        
        for api_key in keys.values() {
            if api_key.key_hash == key_hash && !api_key.revoked {
                if let Some(expires) = api_key.expires_at {
                    if Utc::now() > expires {
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    async fn update_rate_limit(&self, api_key: &str) -> Result<()> {
        let mut limits = self.rate_limits.lock().await;
        let now = Utc::now();
        
        let info = limits.entry(api_key.to_string()).or_insert_with(|| RateLimitInfo {
            request_count: 0,
            window_start: now,
        });
        
        let elapsed = (now - info.window_start).num_seconds();
        if elapsed >= 60 {
            info.request_count = 0;
            info.window_start = now;
        }
        
        info.request_count += 1;
        
        if info.request_count > self.max_requests_per_minute {
            warn!("Rate limit exceeded for API key");
            anyhow::bail!("Rate limit exceeded");
        }
        
        Ok(())
    }

    fn hash_key(key: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKey>> {
        let keys = self.api_keys.read().await;
        Ok(keys.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_api_key() -> Result<()> {
        let server = ApiServer::new(8080);
        let api_key = server.generate_api_key("Test key").await?;
        
        assert_eq!(api_key.description, "Test key");
        assert!(!api_key.revoked);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_revoke_api_key() -> Result<()> {
        let server = ApiServer::new(8080);
        let api_key = server.generate_api_key("Test key").await?;
        
        server.revoke_api_key(&api_key.id).await?;
        
        let keys = server.list_api_keys().await?;
        let revoked = keys.iter().find(|k| k.id == api_key.id).unwrap();
        assert!(revoked.revoked);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_list_devices() -> Result<()> {
        let server = ApiServer::new(8080);
        let api_key = server.generate_api_key("Test").await?;
        
        let request = ApiRequest {
            method: "GET".to_string(),
            path: "/devices".to_string(),
            body: None,
            api_key: Some(api_key.id.clone()),
        };
        
        let response = server.handle_request(request).await?;
        assert_eq!(response.status, 200);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_start_scan() -> Result<()> {
        let server = ApiServer::new(8080);
        let api_key = server.generate_api_key("Test").await?;
        
        let request = ApiRequest {
            method: "POST".to_string(),
            path: "/scan".to_string(),
            body: Some(serde_json::json!({
                "device_path": "/dev/sda",
                "scan_type": "deep",
                "output_dir": "/output"
            })),
            api_key: Some(api_key.id.clone()),
        };
        
        let response = server.handle_request(request).await?;
        assert_eq!(response.status, 202);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_handle_get_status() -> Result<()> {
        let server = ApiServer::new(8080);
        let api_key = server.generate_api_key("Test").await?;
        
        let request = ApiRequest {
            method: "GET".to_string(),
            path: "/status".to_string(),
            body: None,
            api_key: Some(api_key.id.clone()),
        };
        
        let response = server.handle_request(request).await?;
        assert_eq!(response.status, 200);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting() -> Result<()> {
        let server = ApiServer::new(8080).with_rate_limit(5);
        let api_key = server.generate_api_key("Test").await?;
        
        for _ in 0..5 {
            let request = ApiRequest {
                method: "GET".to_string(),
                path: "/devices".to_string(),
                body: None,
                api_key: Some(api_key.id.clone()),
            };
            
            let response = server.handle_request(request).await?;
            assert_eq!(response.status, 200);
        }
        
        let request = ApiRequest {
            method: "GET".to_string(),
            path: "/devices".to_string(),
            body: None,
            api_key: Some(api_key.id.clone()),
        };
        
        let result = server.handle_request(request).await;
        assert!(result.is_err());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_api_key() -> Result<()> {
        let server = ApiServer::new(8080);
        
        let request = ApiRequest {
            method: "GET".to_string(),
            path: "/devices".to_string(),
            body: None,
            api_key: Some("invalid_key".to_string()),
        };
        
        let response = server.handle_request(request).await?;
        assert_eq!(response.status, 401);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_missing_api_key() -> Result<()> {
        let server = ApiServer::new(8080);
        
        let request = ApiRequest {
            method: "GET".to_string(),
            path: "/devices".to_string(),
            body: None,
            api_key: None,
        };
        
        let response = server.handle_request(request).await?;
        assert_eq!(response.status, 401);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_not_found() -> Result<()> {
        let server = ApiServer::new(8080);
        let api_key = server.generate_api_key("Test").await?;
        
        let request = ApiRequest {
            method: "GET".to_string(),
            path: "/nonexistent".to_string(),
            body: None,
            api_key: Some(api_key.id.clone()),
        };
        
        let response = server.handle_request(request).await?;
        assert_eq!(response.status, 404);
        
        Ok(())
    }
}
