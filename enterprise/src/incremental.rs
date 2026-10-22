use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanBitmap {
    pub device_id: String,
    pub device_size: u64,
    pub sector_size: u64,
    pub total_sectors: u64,
    pub scanned_sectors: Vec<bool>,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceHistory {
    pub device_id: String,
    pub device_path: String,
    pub device_size: u64,
    pub last_modification: DateTime<Utc>,
    pub scan_sessions: Vec<ScanSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub sectors_scanned: u64,
    pub files_found: usize,
}

pub struct IncrementalScanner {
    history_dir: PathBuf,
    device_history: HashMap<String, DeviceHistory>,
}

impl IncrementalScanner {
    pub fn new(history_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&history_dir)?;
        Ok(Self {
            history_dir,
            device_history: HashMap::new(),
        })
    }

    pub fn create_bitmap(device_id: &str, device_size: u64) -> ScanBitmap {
        let sector_size = 512;
        let total_sectors = device_size / sector_size;
        
        ScanBitmap {
            device_id: device_id.to_string(),
            device_size,
            sector_size,
            total_sectors,
            scanned_sectors: vec![false; total_sectors as usize],
            created_at: Utc::now(),
            last_updated: Utc::now(),
        }
    }

    pub fn mark_scanned(bitmap: &mut ScanBitmap, offset: u64, length: u64) {
        let start_sector = offset / bitmap.sector_size;
        let end_sector = (offset + length) / bitmap.sector_size;
        
        for sector in start_sector..=end_sector.min(bitmap.total_sectors - 1) {
            if (sector as usize) < bitmap.scanned_sectors.len() {
                bitmap.scanned_sectors[sector as usize] = true;
            }
        }
        
        bitmap.last_updated = Utc::now();
    }

    pub fn get_unscanned_ranges(bitmap: &ScanBitmap) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        let mut range_start: Option<u64> = None;
        
        for (i, &scanned) in bitmap.scanned_sectors.iter().enumerate() {
            if !scanned {
                if range_start.is_none() {
                    range_start = Some(i as u64);
                }
            } else if let Some(start) = range_start {
                ranges.push((start * bitmap.sector_size, i as u64 * bitmap.sector_size));
                range_start = None;
            }
        }
        
        if let Some(start) = range_start {
            ranges.push((start * bitmap.sector_size, bitmap.device_size));
        }
        
        ranges
    }

    pub fn save_bitmap(&self, device_id: &str, bitmap: &ScanBitmap) -> Result<()> {
        let bitmap_file = self.history_dir.join(format!("{}_bitmap.json", device_id));
        let json = serde_json::to_string_pretty(bitmap)?;
        fs::write(&bitmap_file, json)?;
        info!("Saved scan bitmap for device: {}", device_id);
        Ok(())
    }

    pub fn load_bitmap(&self, device_id: &str) -> Result<Option<ScanBitmap>> {
        let bitmap_file = self.history_dir.join(format!("{}_bitmap.json", device_id));
        if !bitmap_file.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(&bitmap_file)?;
        let bitmap: ScanBitmap = serde_json::from_str(&content)?;
        Ok(Some(bitmap))
    }

    pub fn save_device_history(&self, history: &DeviceHistory) -> Result<()> {
        let history_file = self.history_dir.join(format!("{}_history.json", history.device_id));
        let json = serde_json::to_string_pretty(history)?;
        fs::write(&history_file, json)?;
        Ok(())
    }

    pub fn load_device_history(&self, device_id: &str) -> Result<Option<DeviceHistory>> {
        let history_file = self.history_dir.join(format!("{}_history.json", device_id));
        if !history_file.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(&history_file)?;
        let history: DeviceHistory = serde_json::from_str(&content)?;
        Ok(Some(history))
    }

    pub fn record_scan_session(
        &mut self,
        device_id: &str,
        device_path: &str,
        device_size: u64,
    ) -> Result<String> {
        let history = self.device_history.entry(device_id.to_string()).or_insert_with(|| {
            DeviceHistory {
                device_id: device_id.to_string(),
                device_path: device_path.to_string(),
                device_size,
                last_modification: Utc::now(),
                scan_sessions: Vec::new(),
            }
        });
        
        let session_id = uuid::Uuid::new_v4().to_string();
        history.scan_sessions.push(ScanSession {
            session_id: session_id.clone(),
            started_at: Utc::now(),
            completed_at: None,
            sectors_scanned: 0,
            files_found: 0,
        });
        
        let history_clone = history.clone();
        self.save_device_history(&history_clone)?;
        Ok(session_id)
    }

    pub fn complete_scan_session(
        &mut self,
        device_id: &str,
        session_id: &str,
        sectors_scanned: u64,
        files_found: usize,
    ) -> Result<()> {
        if let Some(history) = self.device_history.get_mut(device_id) {
            if let Some(session) = history.scan_sessions.iter_mut().find(|s| s.session_id == session_id) {
                session.completed_at = Some(Utc::now());
                session.sectors_scanned = sectors_scanned;
                session.files_found = files_found;
            }
            let history_clone = history.clone();
            self.save_device_history(&history_clone)?;
        }
        Ok(())
    }

    pub fn has_device_changed(&self, device_id: &str, current_size: u64) -> Result<bool> {
        if let Some(history) = self.load_device_history(device_id)? {
            Ok(history.device_size != current_size)
        } else {
            Ok(false)
        }
    }

    pub fn get_scan_coverage(&self, bitmap: &ScanBitmap) -> f64 {
        let scanned_count = bitmap.scanned_sectors.iter().filter(|&&s| s).count();
        (scanned_count as f64 / bitmap.scanned_sectors.len() as f64) * 100.0
    }

    pub fn merge_bitmaps(bitmaps: &[&ScanBitmap]) -> Result<ScanBitmap> {
        if bitmaps.is_empty() {
            anyhow::bail!("No bitmaps to merge");
        }
        
        let first = bitmaps[0];
        let mut merged = first.clone();
        
        for bitmap in bitmaps.iter().skip(1) {
            if bitmap.device_id != first.device_id {
                anyhow::bail!("Cannot merge bitmaps from different devices");
            }
            
            for (i, &scanned) in bitmap.scanned_sectors.iter().enumerate() {
                if scanned && i < merged.scanned_sectors.len() {
                    merged.scanned_sectors[i] = true;
                }
            }
        }
        
        merged.last_updated = Utc::now();
        Ok(merged)
    }
}

impl ScanBitmap {
    pub fn scanned_percentage(&self) -> f64 {
        let scanned_count = self.scanned_sectors.iter().filter(|&&s| s).count();
        (scanned_count as f64 / self.scanned_sectors.len() as f64) * 100.0
    }

    pub fn is_fully_scanned(&self) -> bool {
        self.scanned_sectors.iter().all(|&s| s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_create_bitmap() {
        let bitmap = IncrementalScanner::create_bitmap("device1", 1_048_576);
        assert_eq!(bitmap.device_id, "device1");
        assert_eq!(bitmap.device_size, 1_048_576);
        assert_eq!(bitmap.sector_size, 512);
        assert_eq!(bitmap.total_sectors, 2048);
        assert_eq!(bitmap.scanned_sectors.len(), 2048);
    }

    #[test]
    fn test_mark_scanned() {
        let mut bitmap = IncrementalScanner::create_bitmap("device1", 10240);
        IncrementalScanner::mark_scanned(&mut bitmap, 0, 2048);
        
        let scanned_count = bitmap.scanned_sectors.iter().filter(|&&s| s).count();
        assert!(scanned_count > 0);
    }

    #[test]
    fn test_get_unscanned_ranges() {
        let mut bitmap = IncrementalScanner::create_bitmap("device1", 5120);
        IncrementalScanner::mark_scanned(&mut bitmap, 0, 1024);
        
        let unscanned = IncrementalScanner::get_unscanned_ranges(&bitmap);
        assert!(!unscanned.is_empty());
    }

    #[test]
    fn test_save_and_load_bitmap() -> Result<()> {
        let temp_dir = tempdir()?;
        let scanner = IncrementalScanner::new(temp_dir.path().to_path_buf())?;
        
        let bitmap = IncrementalScanner::create_bitmap("device1", 1_048_576);
        scanner.save_bitmap("device1", &bitmap)?;
        
        let loaded = scanner.load_bitmap("device1")?;
        assert!(loaded.is_some());
        
        let loaded = loaded.unwrap();
        assert_eq!(loaded.device_id, "device1");
        assert_eq!(loaded.device_size, 1_048_576);
        
        Ok(())
    }

    #[test]
    fn test_scan_session_tracking() -> Result<()> {
        let temp_dir = tempdir()?;
        let mut scanner = IncrementalScanner::new(temp_dir.path().to_path_buf())?;
        
        let session_id = scanner.record_scan_session("device1", "/dev/sda", 1_000_000)?;
        scanner.complete_scan_session("device1", &session_id, 1000, 50)?;
        
        let history = scanner.load_device_history("device1")?.unwrap();
        assert_eq!(history.scan_sessions.len(), 1);
        assert_eq!(history.scan_sessions[0].files_found, 50);
        
        Ok(())
    }

    #[test]
    fn test_scan_coverage() {
        let mut bitmap = IncrementalScanner::create_bitmap("device1", 1024);
        let temp_dir = tempdir().unwrap();
        let scanner = IncrementalScanner::new(temp_dir.path().to_path_buf()).unwrap();
        
        assert_eq!(scanner.get_scan_coverage(&bitmap), 0.0);
        
        IncrementalScanner::mark_scanned(&mut bitmap, 0, 512);
        let coverage = scanner.get_scan_coverage(&bitmap);
        assert!(coverage > 0.0);
    }

    #[test]
    fn test_bitmap_scanned_percentage() {
        let mut bitmap = IncrementalScanner::create_bitmap("device1", 1024);
        assert_eq!(bitmap.scanned_percentage(), 0.0);
        
        IncrementalScanner::mark_scanned(&mut bitmap, 0, 512);
        assert!(bitmap.scanned_percentage() > 0.0);
    }

    #[test]
    fn test_is_fully_scanned() {
        let mut bitmap = IncrementalScanner::create_bitmap("device1", 512);
        assert!(!bitmap.is_fully_scanned());
        
        for i in 0..bitmap.total_sectors {
            bitmap.scanned_sectors[i as usize] = true;
        }
        assert!(bitmap.is_fully_scanned());
    }

    #[test]
    fn test_merge_bitmaps() -> Result<()> {
        let mut bitmap1 = IncrementalScanner::create_bitmap("device1", 1024);
        let mut bitmap2 = IncrementalScanner::create_bitmap("device1", 1024);
        
        IncrementalScanner::mark_scanned(&mut bitmap1, 0, 256);
        IncrementalScanner::mark_scanned(&mut bitmap2, 512, 256);
        
        let merged = IncrementalScanner::merge_bitmaps(&[&bitmap1, &bitmap2])?;
        assert!(merged.scanned_sectors.len() > 0);
        
        Ok(())
    }
}
