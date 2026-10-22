use datadoctor_core::Result;
use tracing::debug;

pub struct NFSClient;

impl NFSClient {
    pub fn list_exports(host: &str) -> Result<Vec<String>> {
        debug!("Listing NFS exports on {}", host);
        Ok(Vec::new())
    }

    pub fn mount_export(host: &str, export: &str) -> Result<String> {
        debug!("Mounting NFS export {} on {}", export, host);
        Ok(String::new())
    }
}
