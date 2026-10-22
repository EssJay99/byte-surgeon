use bytesurgeon_core::Result;
use tracing::debug;

pub struct SMBClient;

impl SMBClient {
    pub fn list_shares(host: &str) -> Result<Vec<String>> {
        debug!("Listing SMB shares on {}", host);
        Ok(Vec::new())
    }

    pub fn mount_share(host: &str, share: &str) -> Result<String> {
        debug!("Mounting SMB share {} on {}", share, host);
        Ok(String::new())
    }
}
