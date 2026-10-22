use crate::Result;
use crate::{DeviceInfo, RecoveredFile, RecoverySession, ThreatStatus};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub session: RecoverySession,
    pub device: DeviceInfo,
    pub files: Vec<RecoveredFile>,
    pub statistics: ReportStatistics,
    pub duration_seconds: f64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportStatistics {
    pub total_files_found: u64,
    pub total_files_recovered: u64,
    pub total_size_recovered: u64,
    pub files_by_type: HashMap<String, u64>,
    pub size_by_type: HashMap<String, u64>,
    pub files_by_status: HashMap<String, u64>,
    pub files_by_integrity: HashMap<String, u64>,
    pub threat_scan_results: ThreatScanStats,
    pub recovery_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScanStats {
    pub clean: u64,
    pub suspicious: u64,
    pub threat_detected: u64,
    pub not_scanned: u64,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_report_data(&self, session: &RecoverySession, files: &[RecoveredFile]) -> ReportData {
        let stats = self.compute_statistics(files, session);
        let duration = session
            .completed_at
            .map(|end| (end - session.started_at).num_seconds() as f64)
            .unwrap_or(0.0);

        ReportData {
            session: session.clone(),
            device: session.device_info.clone(),
            files: files.to_vec(),
            statistics: stats,
            duration_seconds: duration,
            generated_at: Utc::now(),
        }
    }

    pub fn generate_csv(&self, data: &ReportData, output_path: &Path) -> Result<String> {
        let mut csv = String::new();

        csv.push_str("# Data Doctor Recovery Report\n");
        csv.push_str(&format!("# Generated: {}\n", data.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        csv.push_str(&format!("# Session: {}\n", data.session.id));
        csv.push_str(&format!("# Device: {} ({})\n", data.session.device_info.name, data.session.device_info.path));
        csv.push_str("\n");

        csv.push_str("ID,Original Name,Recovered Path,Extension,File Type,Size (bytes),Status,Integrity,Threat Scan,Recovered At,Signature Hash\n");

        for file in &data.files {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{:?},{:?},{:?},{},{}\n",
                file.id,
                file.original_name.as_deref().unwrap_or(""),
                Self::csv_escape(&file.recovered_path),
                file.extension,
                file.file_type,
                file.file_size,
                file.status,
                file.integrity_check,
                file.threat_scan,
                file.recovered_at.format("%Y-%m-%d %H:%M:%S"),
                &file.signature,
            ));
        }

        csv.push_str("\n# Summary\n");
        csv.push_str(&format!("# Total files: {}\n", data.statistics.total_files_recovered));
        csv.push_str(&format!("# Total size: {} bytes\n", data.statistics.total_size_recovered));
        csv.push_str(&format!("# Duration: {:.1}s\n", data.duration_seconds));

        std::fs::write(output_path, &csv)?;

        Ok(csv)
    }

    pub fn generate_csv_string(&self, data: &ReportData) -> String {
        let mut csv = String::new();

        csv.push_str("ID,Original Name,Recovered Path,Extension,File Type,Size (bytes),Status,Integrity,Threat Scan,Recovered At,Signature Hash\n");

        for file in &data.files {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{:?},{:?},{:?},{},{}\n",
                file.id,
                file.original_name.as_deref().unwrap_or(""),
                Self::csv_escape(&file.recovered_path),
                file.extension,
                file.file_type,
                file.file_size,
                file.status,
                file.integrity_check,
                file.threat_scan,
                file.recovered_at.format("%Y-%m-%d %H:%M:%S"),
                &file.signature,
            ));
        }

        csv
    }

    pub fn generate_html(&self, data: &ReportData, output_path: &Path) -> Result<String> {
        let html = self.build_html(data);
        std::fs::write(output_path, &html)?;
        Ok(html)
    }

    pub fn generate_html_string(&self, data: &ReportData) -> String {
        self.build_html(data)
    }

    pub fn generate_text(&self, data: &ReportData, output_path: &Path) -> Result<String> {
        let text = self.build_text(data);
        std::fs::write(output_path, &text)?;
        Ok(text)
    }

    pub fn generate_text_string(&self, data: &ReportData) -> String {
        self.build_text(data)
    }

    fn compute_statistics(&self, files: &[RecoveredFile], session: &RecoverySession) -> ReportStatistics {
        let mut files_by_type = HashMap::new();
        let mut size_by_type = HashMap::new();
        let mut files_by_status = HashMap::new();
        let mut files_by_integrity = HashMap::new();
        let mut threat_stats = ThreatScanStats {
            clean: 0,
            suspicious: 0,
            threat_detected: 0,
            not_scanned: 0,
        };

        for file in files {
            *files_by_type.entry(file.extension.clone()).or_insert(0) += 1;
            *size_by_type.entry(file.extension.clone()).or_insert(0) += file.file_size;
            *files_by_status.entry(format!("{:?}", file.status)).or_insert(0) += 1;
            *files_by_integrity.entry(format!("{:?}", file.integrity_check)).or_insert(0) += 1;

            match file.threat_scan {
                ThreatStatus::Clean => threat_stats.clean += 1,
                ThreatStatus::Suspicious => threat_stats.suspicious += 1,
                ThreatStatus::ThreatDetected => threat_stats.threat_detected += 1,
                ThreatStatus::NotScanned => threat_stats.not_scanned += 1,
            }
        }

        let total = files.len() as u64;
        let completed = *files_by_status.get("Completed").unwrap_or(&0);
        let recovery_rate = if total > 0 {
            (completed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        ReportStatistics {
            total_files_found: session.files_found,
            total_files_recovered: session.files_recovered,
            total_size_recovered: session.total_size_recovered,
            files_by_type,
            size_by_type,
            files_by_status,
            files_by_integrity,
            threat_scan_results: threat_stats,
            recovery_rate,
        }
    }

    fn build_html(&self, data: &ReportData) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str("<title>Data Doctor Recovery Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }\n");
        html.push_str(".container { max-width: 1200px; margin: 0 auto; }\n");
        html.push_str("h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }\n");
        html.push_str("h2 { color: #16213e; margin-top: 30px; }\n");
        html.push_str(".summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }\n");
        html.push_str(".card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html.push_str(".card h3 { margin: 0 0 5px 0; color: #666; font-size: 0.9em; text-transform: uppercase; }\n");
        html.push_str(".card .value { font-size: 2em; font-weight: bold; color: #1a1a2e; }\n");
        html.push_str("table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html.push_str("th { background: #1a1a2e; color: white; padding: 12px; text-align: left; font-size: 0.85em; text-transform: uppercase; }\n");
        html.push_str("td { padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 0.9em; }\n");
        html.push_str("tr:hover td { background: #f8f9fa; }\n");
        html.push_str(".status-completed { color: #28a745; font-weight: bold; }\n");
        html.push_str(".status-failed { color: #dc3545; font-weight: bold; }\n");
        html.push_str(".status-partial { color: #ffc107; font-weight: bold; }\n");
        html.push_str(".threat-clean { color: #28a745; }\n");
        html.push_str(".threat-suspicious { color: #ffc107; font-weight: bold; }\n");
        html.push_str(".threat-detected { color: #dc3545; font-weight: bold; }\n");
        html.push_str(".meta { color: #666; font-size: 0.9em; margin-bottom: 20px; }\n");
        html.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

        html.push_str("<h1>Data Doctor Recovery Report</h1>\n");
        html.push_str(&format!("<p class=\"meta\">Session: {} | Device: {} ({}) | Generated: {}</p>\n",
            data.session.id,
            data.session.device_info.name,
            data.session.device_info.path,
            data.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        ));

        html.push_str("<div class=\"summary\">\n");
        html.push_str(&format!("<div class=\"card\"><h3>Files Found</h3><div class=\"value\">{}</div></div>\n", data.statistics.total_files_found));
        html.push_str(&format!("<div class=\"card\"><h3>Files Recovered</h3><div class=\"value\">{}</div></div>\n", data.statistics.total_files_recovered));
        html.push_str(&format!("<div class=\"card\"><h3>Total Size</h3><div class=\"value\">{}</div></div>\n", Self::format_size(data.statistics.total_size_recovered)));
        html.push_str(&format!("<div class=\"card\"><h3>Recovery Rate</h3><div class=\"value\">{:.1}%</div></div>\n", data.statistics.recovery_rate));
        html.push_str(&format!("<div class=\"card\"><h3>Duration</h3><div class=\"value\">{}</div></div>\n", Self::format_duration(data.duration_seconds)));
        html.push_str(&format!("<div class=\"card\"><h3>File Types</h3><div class=\"value\">{}</div></div>\n", data.statistics.files_by_type.len()));
        html.push_str("</div>\n");

        if data.statistics.threat_scan_results.threat_detected > 0 || data.statistics.threat_scan_results.suspicious > 0 {
            html.push_str("<h2>Threat Scan Results</h2>\n");
            html.push_str("<div class=\"summary\">\n");
            html.push_str(&format!("<div class=\"card\"><h3>Clean</h3><div class=\"value threat-clean\">{}</div></div>\n", data.statistics.threat_scan_results.clean));
            html.push_str(&format!("<div class=\"card\"><h3>Suspicious</h3><div class=\"value threat-suspicious\">{}</div></div>\n", data.statistics.threat_scan_results.suspicious));
            html.push_str(&format!("<div class=\"card\"><h3>Threats</h3><div class=\"value threat-detected\">{}</div></div>\n", data.statistics.threat_scan_results.threat_detected));
            html.push_str(&format!("<div class=\"card\"><h3>Not Scanned</h3><div class=\"value\">{}</div></div>\n", data.statistics.threat_scan_results.not_scanned));
            html.push_str("</div>\n");
        }

        html.push_str("<h2>Files by Type</h2>\n");
        html.push_str("<table>\n<tr><th>Extension</th><th>Count</th><th>Total Size</th></tr>\n");

        let mut type_entries: Vec<_> = data.statistics.files_by_type.iter().collect();
        type_entries.sort_by(|a, b| b.1.cmp(a.1));

        for (ext, count) in &type_entries {
            let size = data.statistics.size_by_type.get(*ext).unwrap_or(&0);
            html.push_str(&format!("<tr><td>.{}</td><td>{}</td><td>{}</td></tr>\n",
                ext, count, Self::format_size(*size)));
        }
        html.push_str("</table>\n");

        html.push_str("<h2>Recovered Files</h2>\n");
        html.push_str("<table>\n<tr><th>Name</th><th>Type</th><th>Size</th><th>Status</th><th>Integrity</th><th>Threat</th><th>Hash</th></tr>\n");

        for file in &data.files {
            let status_class = match file.status {
                crate::RecoveryStatus::Completed => "status-completed",
                crate::RecoveryStatus::Failed | crate::RecoveryStatus::Corrupted => "status-failed",
                _ => "status-partial",
            };
            let threat_class = match file.threat_scan {
                ThreatStatus::Clean => "threat-clean",
                ThreatStatus::Suspicious => "threat-suspicious",
                ThreatStatus::ThreatDetected => "threat-detected",
                _ => "",
            };

            html.push_str(&format!(
                "<tr><td>{}</td><td>.{}</td><td>{}</td><td class=\"{}\">{:?}</td><td>{:?}</td><td class=\"{}\">{:?}</td><td><code>{}</code></td></tr>\n",
                Self::html_escape(file.original_name.as_deref().unwrap_or(&file.id)),
                file.extension,
                Self::format_size(file.file_size),
                status_class,
                file.status,
                file.integrity_check,
                threat_class,
                file.threat_scan,
                if file.signature.len() > 16 { &file.signature[..16] } else { &file.signature },
            ));
        }

        html.push_str("</table>\n");
        html.push_str("</div>\n</body>\n</html>");

        html
    }

    fn build_text(&self, data: &ReportData) -> String {
        let mut text = String::new();

        text.push_str("================================================================================\n");
        text.push_str("                     Data Doctor Recovery Report\n");
        text.push_str("================================================================================\n\n");

        text.push_str(&format!("Session ID   : {}\n", data.session.id));
        text.push_str(&format!("Device       : {} ({})\n", data.session.device_info.name, data.session.device_info.path));
        text.push_str(&format!("File System  : {:?}\n", data.session.device_info.file_system));
        text.push_str(&format!("Scan Type    : {:?}\n", data.session.scan_type));
        text.push_str(&format!("Started      : {}\n", data.session.started_at.format("%Y-%m-%d %H:%M:%S UTC")));
        text.push_str(&format!("Completed    : {}\n",
            data.session.completed_at
                .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "N/A".to_string())));
        text.push_str(&format!("Duration     : {}\n", Self::format_duration(data.duration_seconds)));
        text.push_str(&format!("Output Path  : {}\n", data.session.output_path));

        text.push_str("\n--- Summary ---\n\n");
        text.push_str(&format!("Files Found     : {}\n", data.statistics.total_files_found));
        text.push_str(&format!("Files Recovered : {}\n", data.statistics.total_files_recovered));
        text.push_str(&format!("Total Size      : {}\n", Self::format_size(data.statistics.total_size_recovered)));
        text.push_str(&format!("Recovery Rate   : {:.1}%\n", data.statistics.recovery_rate));

        text.push_str("\n--- Files by Type ---\n\n");
        let mut type_entries: Vec<_> = data.statistics.files_by_type.iter().collect();
        type_entries.sort_by(|a, b| b.1.cmp(a.1));

        text.push_str(&format!("  {:<12} {:>8} {:>15}\n", "Extension", "Count", "Size"));
        text.push_str(&format!("  {:<12} {:>8} {:>15}\n", "----------", "--------", "---------------"));
        for (ext, count) in &type_entries {
            let size = data.statistics.size_by_type.get(*ext).unwrap_or(&0);
            text.push_str(&format!("  .{:<11} {:>8} {:>15}\n", ext, count, Self::format_size(*size)));
        }

        text.push_str("\n--- Threat Scan Results ---\n\n");
        text.push_str(&format!("  Clean          : {}\n", data.statistics.threat_scan_results.clean));
        text.push_str(&format!("  Suspicious     : {}\n", data.statistics.threat_scan_results.suspicious));
        text.push_str(&format!("  Threats Found  : {}\n", data.statistics.threat_scan_results.threat_detected));
        text.push_str(&format!("  Not Scanned    : {}\n", data.statistics.threat_scan_results.not_scanned));

        text.push_str("\n--- Files by Integrity ---\n\n");
        for (status, count) in &data.statistics.files_by_integrity {
            text.push_str(&format!("  {:<20} {}\n", status, count));
        }

        text.push_str("\n--- Recovered Files ---\n\n");
        text.push_str(&format!("  {:<40} {:<8} {:>10} {:<12} {:<15}\n",
            "Name", "Ext", "Size", "Status", "Threat"));
        text.push_str(&format!("  {:<40} {:<8} {:>10} {:<12} {:<15}\n",
            "----------------------------------------", "--------", "----------", "------------", "---------------"));

        for file in &data.files {
            let name = file.original_name.as_deref().unwrap_or(&file.id);
            let display_name = if name.len() > 38 { &name[..38] } else { name };
            text.push_str(&format!("  {:<40} {:<8} {:>10} {:<12} {:<15}\n",
                display_name,
                file.extension,
                Self::format_size(file.file_size),
                format!("{:?}", file.status),
                format!("{:?}", file.threat_scan),
            ));
        }

        text.push_str("\n================================================================================\n");
        text.push_str(&format!("  Report generated: {}\n", data.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        text.push_str("================================================================================\n");

        text
    }

    fn format_size(bytes: u64) -> String {
        if bytes == 0 {
            return "0 B".to_string();
        }
        let units = ["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;
        while size >= 1024.0 && unit_idx < units.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        if unit_idx == 0 {
            format!("{} {}", bytes, units[0])
        } else {
            format!("{:.1} {}", size, units[unit_idx])
        }
    }

    fn format_duration(seconds: f64) -> String {
        let d = Duration::seconds(seconds as i64);
        let hours = d.num_hours();
        let minutes = d.num_minutes() % 60;
        let secs = d.num_seconds() % 60;
        if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, secs)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, secs)
        } else {
            format!("{}s", secs)
        }
    }

    fn csv_escape(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceInfo, RecoverySession, ScanType, RecoveryStatus, IntegrityStatus};

    fn make_test_data() -> ReportData {
        let device = DeviceInfo::new("/dev/sda", "Test Disk");
        let mut session = RecoverySession::new(device, ScanType::Deep, "/output");
        session.files_found = 10;
        session.files_recovered = 8;
        session.total_size_recovered = 5242880;
        session.completed_at = Some(session.started_at + Duration::seconds(120));

        let mut files = Vec::new();
        for i in 0..8 {
            let mut f = RecoveredFile::new(&session.id, &format!("/output/file{}.jpg", i));
            f.extension = if i < 4 { "jpg".to_string() } else { "png".to_string() };
            f.file_type = "Image".to_string();
            f.file_size = 655360;
            f.original_name = Some(format!("photo{}.jpg", i));
            f.status = RecoveryStatus::Completed;
            f.integrity_check = IntegrityStatus::Verified;
            f.threat_scan = ThreatStatus::Clean;
            f.signature = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string();
            files.push(f);
        }

        let gen = ReportGenerator::new();
        gen.generate_report_data(&session, &files)
    }

    #[test]
    fn test_report_generator_creation() {
        let gen = ReportGenerator::new();
        let _ = gen;
    }

    #[test]
    fn test_default() {
        let gen = ReportGenerator::default();
        let _ = gen;
    }

    #[test]
    fn test_generate_report_data() {
        let data = make_test_data();
        assert_eq!(data.statistics.total_files_found, 10);
        assert_eq!(data.statistics.total_files_recovered, 8);
        assert_eq!(data.statistics.total_size_recovered, 5242880);
    }

    #[test]
    fn test_statistics_computed() {
        let data = make_test_data();
        assert_eq!(data.statistics.files_by_type.len(), 2);
        assert!(data.statistics.files_by_type.contains_key("jpg"));
        assert!(data.statistics.files_by_type.contains_key("png"));
        assert_eq!(*data.statistics.files_by_type.get("jpg").unwrap(), 4);
        assert_eq!(*data.statistics.files_by_type.get("png").unwrap(), 4);
    }

    #[test]
    fn test_threat_scan_stats() {
        let data = make_test_data();
        assert_eq!(data.statistics.threat_scan_results.clean, 8);
        assert_eq!(data.statistics.threat_scan_results.suspicious, 0);
        assert_eq!(data.statistics.threat_scan_results.threat_detected, 0);
    }

    #[test]
    fn test_recovery_rate() {
        let data = make_test_data();
        assert!((data.statistics.recovery_rate - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_generate_csv_string() {
        let data = make_test_data();
        let gen = ReportGenerator::new();
        let csv = gen.generate_csv_string(&data);
        assert!(csv.contains("ID,Original Name,Recovered Path"));
        assert!(csv.contains("photo0.jpg"));
        assert!(csv.contains(".jpg"));
    }

    #[test]
    fn test_generate_csv_file() {
        let data = make_test_data();
        let gen = ReportGenerator::new();
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("report.csv");
        let csv = gen.generate_csv(&data, &output).unwrap();
        assert!(output.exists());
        assert!(csv.contains("ID,Original Name"));
    }

    #[test]
    fn test_generate_html_string() {
        let data = make_test_data();
        let gen = ReportGenerator::new();
        let html = gen.generate_html_string(&data);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Data Doctor Recovery Report"));
        assert!(html.contains("photo0.jpg"));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn test_generate_html_file() {
        let data = make_test_data();
        let gen = ReportGenerator::new();
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("report.html");
        let html = gen.generate_html(&data, &output).unwrap();
        assert!(output.exists());
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_generate_text_string() {
        let data = make_test_data();
        let gen = ReportGenerator::new();
        let text = gen.generate_text_string(&data);
        assert!(text.contains("Data Doctor Recovery Report"));
        assert!(text.contains("Files Found"));
        assert!(text.contains("photo0.jpg"));
        assert!(text.contains("Files by Type"));
    }

    #[test]
    fn test_generate_text_file() {
        let data = make_test_data();
        let gen = ReportGenerator::new();
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("report.txt");
        let text = gen.generate_text(&data, &output).unwrap();
        assert!(output.exists());
        assert!(text.contains("Data Doctor Recovery Report"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(ReportGenerator::format_size(0), "0 B");
        assert_eq!(ReportGenerator::format_size(500), "500 B");
        assert_eq!(ReportGenerator::format_size(1024), "1.0 KB");
        assert_eq!(ReportGenerator::format_size(1048576), "1.0 MB");
        assert_eq!(ReportGenerator::format_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(ReportGenerator::format_duration(0.0), "0s");
        assert_eq!(ReportGenerator::format_duration(45.0), "45s");
        assert_eq!(ReportGenerator::format_duration(90.0), "1m 30s");
        assert_eq!(ReportGenerator::format_duration(3661.0), "1h 1m 1s");
    }

    #[test]
    fn test_csv_escape() {
        assert_eq!(ReportGenerator::csv_escape("simple"), "simple");
        assert_eq!(ReportGenerator::csv_escape("has,comma"), "\"has,comma\"");
        assert_eq!(ReportGenerator::csv_escape("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(ReportGenerator::html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(ReportGenerator::html_escape("a&b"), "a&amp;b");
        assert_eq!(ReportGenerator::html_escape("a\"b"), "a&quot;b");
    }

    #[test]
    fn test_empty_report() {
        let device = DeviceInfo::new("/dev/sda", "Empty Disk");
        let session = RecoverySession::new(device, ScanType::Quick, "/output");
        let files: Vec<RecoveredFile> = Vec::new();
        let gen = ReportGenerator::new();
        let data = gen.generate_report_data(&session, &files);
        assert_eq!(data.statistics.total_files_recovered, 0);
        assert!(data.statistics.files_by_type.is_empty());
    }

    #[test]
    fn test_size_by_type() {
        let data = make_test_data();
        let jpg_size = data.statistics.size_by_type.get("jpg").unwrap();
        let png_size = data.statistics.size_by_type.get("png").unwrap();
        assert_eq!(jpg_size, png_size);
    }

    #[test]
    fn test_files_by_status() {
        let data = make_test_data();
        assert!(data.statistics.files_by_status.contains_key("Completed"));
    }
}
