#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use bytesurgeon_core::{
    DeduplicationEngine, FilePreviewer, HexViewer, PartitionScanner, PreviewData,
    RecoveryEngine, ReportGenerator, ScanType, SignatureCategory, SignatureDatabase,
    WriteProtector,
};
use bytesurgeon_devices::DeviceDetector;
use bytesurgeon_diskimage::{DiskImage, ImageMetadata};
use bytesurgeon_encryption::bitlocker::BitLockerVolume;
use bytesurgeon_encryption::filevault::FileVaultVolume;
use bytesurgeon_encryption::luks::LuksVolume;
use bytesurgeon_encryption::veracrypt::VeraCryptVolume;
use bytesurgeon_encryption::EncryptedVolume;
use bytesurgeon_raid::{RaidDisk, RaidDetector};
use bytesurgeon_security::malware::MalwareScanner;
use bytesurgeon_security::SecurityScanner;
use bytesurgeon_forensic::{
    FileReparer, FragmentScanner, RegistryParser, ShadowCopyDetector, UsnJournalParser,
};
use bytesurgeon_chat::{
    BrowserHistoryRecoverer, EmailRecoverer, IMessageRecoverer, SignalRecoverer,
    SlackParser, SqliteCarver, WhatsAppRecoverer,
};
use bytesurgeon_enterprise::{
    ApiServer, BatchProcessor, CaseManager, ScanManager,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::State;

struct AppState {
    engine: Mutex<RecoveryEngine>,
    #[allow(dead_code)]
    data_dir: PathBuf,
}

#[derive(Serialize)]
struct DeviceResponse {
    id: String,
    name: String,
    path: String,
    device_type: String,
    total_size: u64,
    free_space: u64,
    file_system: String,
}

#[derive(Serialize)]
struct SessionResponse {
    id: String,
    device_id: String,
    status: String,
    scan_type: String,
    files_found: u64,
    files_recovered: u64,
    total_size_recovered: u64,
}

#[derive(Serialize)]
struct RecoveredFileResponse {
    id: String,
    original_path: Option<String>,
    recovered_path: String,
    file_size: u64,
    file_type: String,
    extension: String,
    status: String,
    integrity_check: String,
    threat_scan: String,
}

#[derive(Serialize)]
struct PartitionResponse {
    index: u32,
    start_sector: u64,
    end_sector: u64,
    partition_type: String,
    filesystem: String,
    is_active: bool,
    is_gpt: bool,
    guid: Option<String>,
}

#[derive(Serialize)]
struct DuplicateGroupResponse {
    hash: String,
    paths: Vec<String>,
}

#[derive(Serialize)]
struct UsnEntryResponse {
    filename: String,
    parent_ref: u64,
    usn: u64,
    timestamp: String,
    reason: String,
}

#[derive(Serialize)]
struct ShadowCopyResponse {
    id: String,
    volume: String,
    size: u64,
    created: String,
}

#[derive(Serialize)]
struct FragmentResponse {
    offset: u64,
    size: u64,
    signature: String,
    confidence: f32,
}

#[derive(Serialize)]
struct RepairResponse {
    success: bool,
    format: String,
    input_size: u64,
    output_size: u64,
}

#[derive(Serialize)]
struct RegistryResponse {
    keys: Vec<String>,
    values: Vec<String>,
    user_activity: Vec<String>,
}

#[derive(Serialize)]
struct MessageResponse {
    sender: String,
    content: String,
    timestamp: String,
    media_count: u32,
}

#[derive(Serialize)]
struct HistoryResponse {
    url: String,
    title: String,
    timestamp: String,
    visit_count: u32,
}

#[derive(Serialize)]
struct EmailResponse {
    from: String,
    to: Vec<String>,
    subject: String,
    date: String,
    has_attachments: bool,
}

#[derive(Serialize)]
struct ScanStateResponse {
    device: String,
    scan_type: String,
    offset: u64,
    progress: f32,
    interrupted_at: String,
}

#[derive(Serialize)]
struct IncrementalResponse {
    new_sectors: u64,
    total_scanned: u64,
    new_files: u64,
}

#[derive(Serialize)]
struct JobStatusResponse {
    id: String,
    device: String,
    status: String,
    progress: f32,
}

#[derive(Deserialize)]
struct RecoverRequest {
    device_path: String,
    scan_type: String,
    output_dir: String,
}

#[derive(Deserialize)]
struct ThreatScanRequest {
    path: String,
}

#[tauri::command]
async fn scan_devices(_state: State<'_, AppState>) -> Result<Vec<DeviceResponse>, String> {
    let detector = DeviceDetector::new();
    let devices = detector.detect_all_devices().map_err(|e| e.to_string())?;

    Ok(devices
        .iter()
        .map(|d| DeviceResponse {
            id: d.id.clone(),
            name: d.name.clone(),
            path: d.path.clone(),
            device_type: format!("{:?}", d.device_type),
            total_size: d.total_size,
            free_space: d.free_space,
            file_system: format!("{:?}", d.file_system),
        })
        .collect())
}

#[tauri::command]
async fn start_recovery(
    state: State<'_, AppState>,
    request: RecoverRequest,
) -> Result<String, String> {
    let engine = state.engine.lock().unwrap();

    let devices = engine.get_all_devices().map_err(|e| e.to_string())?;
    let device = devices
        .iter()
        .find(|d| d.path == request.device_path || d.name == request.device_path)
        .ok_or("Device not found")?;

    let scan_type = match request.scan_type.as_str() {
        "quick" => ScanType::Quick,
        "deep" => ScanType::Deep,
        "signature" => ScanType::Signature,
        "filesystem" => ScanType::FileSystem,
        "raw" => ScanType::Raw,
        _ => ScanType::Signature,
    };

    let output_dir = PathBuf::from(request.output_dir);
    engine
        .start_recovery(device, scan_type, &output_dir)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_sessions(state: State<'_, AppState>) -> Result<Vec<SessionResponse>, String> {
    let engine = state.engine.lock().unwrap();
    let devices = engine.get_all_devices().map_err(|e| e.to_string())?;

    let mut sessions = Vec::new();
    for device in devices {
        if let Ok(device_sessions) = engine.get_sessions_for_device(&device.id) {
            for session in device_sessions {
                sessions.push(SessionResponse {
                    id: session.id,
                    device_id: session.device_id,
                    status: format!("{:?}", session.status),
                    scan_type: format!("{:?}", session.scan_type),
                    files_found: session.files_found,
                    files_recovered: session.files_recovered,
                    total_size_recovered: session.total_size_recovered,
                });
            }
        }
    }

    Ok(sessions)
}

#[tauri::command]
async fn get_recovered_files(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<Vec<RecoveredFileResponse>, String> {
    let engine = state.engine.lock().unwrap();
    let files = engine
        .get_recovered_files(&session_id)
        .map_err(|e| e.to_string())?;

    Ok(files
        .iter()
        .map(|f| RecoveredFileResponse {
            id: f.id.clone(),
            original_path: f.original_path.clone(),
            recovered_path: f.recovered_path.clone(),
            file_size: f.file_size,
            file_type: f.file_type.clone(),
            extension: f.extension.clone(),
            status: format!("{:?}", f.status),
            integrity_check: format!("{:?}", f.integrity_check),
            threat_scan: format!("{:?}", f.threat_scan),
        })
        .collect())
}

#[tauri::command]
async fn scan_threats(request: ThreatScanRequest) -> Result<String, String> {
    let scanner = MalwareScanner::new();
    let path = PathBuf::from(&request.path);

    let status = scanner.scan_file(&path).map_err(|e| e.to_string())?;

    Ok(format!("{:?}", status))
}

#[tauri::command]
async fn check_compliance() -> Result<String, String> {
    let checker = bytesurgeon_security::compliance::ComplianceChecker::new();
    let report = checker.check_nist_compliance().map_err(|e| e.to_string())?;

    Ok(format!(
        "{} - {}",
        report.standard,
        if report.passed { "PASSED" } else { "FAILED" }
    ))
}

#[tauri::command]
async fn scan_partitions(device_path: String) -> Result<Vec<PartitionResponse>, String> {
    let scanner = PartitionScanner::new(&device_path);
    let partitions = scanner.scan_all().map_err(|e| e.to_string())?;

    Ok(partitions
        .into_iter()
        .map(|p| PartitionResponse {
            index: p.index,
            start_sector: p.start_sector,
            end_sector: p.end_sector,
            partition_type: format!("{:?}", p.partition_type),
            filesystem: format!("{:?}", p.filesystem),
            is_active: p.is_active,
            is_gpt: p.is_gpt,
            guid: p.guid,
        })
        .collect())
}

#[tauri::command]
async fn hex_view(path: String, offset: u64, length: u32) -> Result<String, String> {
    let viewer = HexViewer::new();
    let dump = viewer
        .read_hex(Path::new(&path), offset, length as usize)
        .map_err(|e| e.to_string())?;

    Ok(dump.formatted_output)
}

#[tauri::command]
async fn preview_file(path: String) -> Result<String, String> {
    let previewer = FilePreviewer::new();
    let path = Path::new(&path);
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();

    let preview: PreviewData = previewer
        .generate_preview(path, &extension)
        .map_err(|e| e.to_string())?;

    serde_json::to_string(&preview).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_image_info(path: String) -> Result<String, String> {
    let path = Path::new(&path);

    if let Ok(e01) = bytesurgeon_diskimage::e01::E01Image::open(path) {
        let metadata: ImageMetadata = e01.metadata();
        return serde_json::to_string(&metadata).map_err(|e| e.to_string());
    }

    let raw = bytesurgeon_diskimage::raw::RawImage::open(path).map_err(|e| e.to_string())?;
    let metadata: ImageMetadata = raw.metadata();
    serde_json::to_string(&metadata).map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_encryption(device_path: String) -> Result<String, String> {
    let mut results = HashMap::new();

    let bitlocker_detected = BitLockerVolume::detect(&device_path)
        .map_err(|e| e.to_string())
        .unwrap_or(false);
    results.insert("BitLocker", bitlocker_detected);

    let filevault_detected = FileVaultVolume::detect(&device_path)
        .map_err(|e| e.to_string())
        .unwrap_or(false);
    results.insert("FileVault", filevault_detected);

    let luks_detected = LuksVolume::detect(&device_path)
        .map_err(|e| e.to_string())
        .unwrap_or(false);
    results.insert("LUKS", luks_detected);

    let veracrypt_detected = VeraCryptVolume::detect(&device_path)
        .map_err(|e| e.to_string())
        .unwrap_or(false);
    results.insert("VeraCrypt", veracrypt_detected);

    serde_json::to_string(&results).map_err(|e| e.to_string())
}

#[tauri::command]
async fn generate_report(
    state: State<'_, AppState>,
    session_id: String,
    format: String,
    output_path: String,
) -> Result<String, String> {
    let engine = state.engine.lock().unwrap();
    let generator = ReportGenerator::new();
    let output = Path::new(&output_path);

    let devices = engine.get_all_devices().map_err(|e| e.to_string())?;
    for device in devices {
        if let Ok(sessions) = engine.get_sessions_for_device(&device.id) {
            if let Some(session) = sessions.iter().find(|s| s.id == session_id) {
                let files = engine
                    .get_recovered_files(&session_id)
                    .map_err(|e| e.to_string())?;
                let report_data = generator.generate_report_data(session, &files);

                match format.as_str() {
                    "csv" => {
                        generator
                            .generate_csv(&report_data, output)
                            .map_err(|e| e.to_string())?;
                    }
                    "html" => {
                        generator
                            .generate_html(&report_data, output)
                            .map_err(|e| e.to_string())?;
                    }
                    "text" | "txt" => {
                        generator
                            .generate_text(&report_data, output)
                            .map_err(|e| e.to_string())?;
                    }
                    _ => {
                        return Err(format!("Unsupported format: {}", format));
                    }
                }

                return Ok(format!(
                    "Report generated successfully at {}",
                    output_path
                ));
            }
        }
    }

    Err(format!("Session not found: {}", session_id))
}

#[tauri::command]
async fn get_signature_counts() -> Result<String, String> {
    let db = SignatureDatabase::new();
    let mut counts: HashMap<String, usize> = HashMap::new();

    let categories = [
        SignatureCategory::Image,
        SignatureCategory::Document,
        SignatureCategory::Audio,
        SignatureCategory::Video,
        SignatureCategory::Archive,
        SignatureCategory::Database,
        SignatureCategory::Executable,
        SignatureCategory::Font,
        SignatureCategory::Cad,
        SignatureCategory::Model3D,
        SignatureCategory::Backup,
        SignatureCategory::Email,
        SignatureCategory::DiskImage,
        SignatureCategory::Compressed,
        SignatureCategory::Virtual,
        SignatureCategory::Certificate,
        SignatureCategory::Miscellaneous,
    ];

    for cat in &categories {
        let name = cat.as_str().to_string();
        let count = db.by_category(cat).len();
        counts.insert(name, count);
    }

    serde_json::to_string(&counts).map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_write_protection(device_path: String) -> Result<String, String> {
    let mut protector = WriteProtector::new().with_strict_mode(false);
    let status = protector
        .verify_device(&device_path)
        .map_err(|e| e.to_string())?;

    serde_json::to_string(&status).map_err(|e| e.to_string())
}

#[tauri::command]
async fn find_duplicates(directory: String) -> Result<String, String> {
    let mut engine = DeduplicationEngine::new();
    let dir_path = Path::new(&directory);

    if !dir_path.exists() || !dir_path.is_dir() {
        return Err(format!("Directory not found: {}", directory));
    }

    scan_directory_for_dupes(&mut engine, dir_path)?;

    let duplicates = engine.get_duplicates().map_err(|e| e.to_string())?;
    let response: Vec<DuplicateGroupResponse> = duplicates
        .into_iter()
        .map(|(hash, paths)| DuplicateGroupResponse {
            hash,
            paths: paths.iter().map(|p| p.to_string_lossy().to_string()).collect(),
        })
        .collect();

    serde_json::to_string(&response).map_err(|e| e.to_string())
}

fn scan_directory_for_dupes(
    engine: &mut DeduplicationEngine,
    dir: &Path,
) -> Result<(), String> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    scan_directory_for_dupes(engine, &path)?;
                } else if path.is_file() {
                    let _ = engine.record_file(&path);
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn detect_raid(disks: Vec<String>) -> Result<String, String> {
    let detector = RaidDetector::new();
    let mut raid_disks: Vec<RaidDisk> = Vec::new();

    for (i, disk_path) in disks.iter().enumerate() {
        let path = Path::new(disk_path);
        let data = if path.exists() {
            std::fs::read(path).map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };

        let size = data.len() as u64;
        raid_disks.push(RaidDisk {
            path: disk_path.clone(),
            size,
            position: i,
            data,
        });
    }

    let info = detector.detect(&raid_disks).map_err(|e| e.to_string())?;
    serde_json::to_string(&info).map_err(|e| e.to_string())
}

#[tauri::command]
async fn parse_usn_journal(device_path: String) -> Result<Vec<UsnEntryResponse>, String> {
    let parser = UsnJournalParser::new();
    let entries = parser.parse(&device_path)?;
    Ok(entries
        .into_iter()
        .map(|e| UsnEntryResponse {
            filename: e.filename,
            parent_ref: e.parent_ref,
            usn: e.usn,
            timestamp: e.timestamp,
            reason: e.reason,
        })
        .collect())
}

#[tauri::command]
async fn detect_shadow_copies(device_path: String) -> Result<Vec<ShadowCopyResponse>, String> {
    let detector = ShadowCopyDetector::new();
    let copies = detector.detect(&device_path)?;
    Ok(copies
        .into_iter()
        .map(|c| ShadowCopyResponse {
            id: c.id,
            volume: c.volume,
            size: c.size,
            created: c.created,
        })
        .collect())
}

#[tauri::command]
async fn scan_fragments(device_path: String) -> Result<Vec<FragmentResponse>, String> {
    let scanner = FragmentScanner::new();
    let fragments = scanner.scan(&device_path)?;
    Ok(fragments
        .into_iter()
        .map(|f| FragmentResponse {
            offset: f.offset,
            size: f.size,
            signature: f.signature,
            confidence: f.confidence,
        })
        .collect())
}

#[tauri::command]
async fn repair_file(
    input_path: String,
    output_path: String,
    format: String,
) -> Result<RepairResponse, String> {
    let repairer = FileReparer::new();
    let result = repairer.repair(
        Path::new(&input_path),
        Path::new(&output_path),
        &format,
    )?;
    Ok(RepairResponse {
        success: result.success,
        format: result.format,
        input_size: result.input_size,
        output_size: result.output_size,
    })
}

#[tauri::command]
async fn parse_registry(hive_path: String) -> Result<RegistryResponse, String> {
    let parser = RegistryParser::new();
    let result = parser.parse(&hive_path)?;
    Ok(RegistryResponse {
        keys: result.keys,
        values: result.values,
        user_activity: result.user_activity,
    })
}

#[tauri::command]
async fn recover_whatsapp(db_path: String) -> Result<Vec<MessageResponse>, String> {
    let recoverer = WhatsAppRecoverer::new();
    let messages = recoverer.recover(&db_path)?;
    Ok(messages
        .into_iter()
        .map(|m| MessageResponse {
            sender: m.sender,
            content: m.content,
            timestamp: m.timestamp,
            media_count: m.media_count,
        })
        .collect())
}

#[tauri::command]
async fn recover_imessage(db_path: String) -> Result<Vec<MessageResponse>, String> {
    let recoverer = IMessageRecoverer::new();
    let messages = recoverer.recover(&db_path)?;
    Ok(messages
        .into_iter()
        .map(|m| MessageResponse {
            sender: m.sender,
            content: m.content,
            timestamp: m.timestamp,
            media_count: m.media_count,
        })
        .collect())
}

#[tauri::command]
async fn recover_signal(db_path: String) -> Result<Vec<MessageResponse>, String> {
    let recoverer = SignalRecoverer::new();
    let messages = recoverer.recover(&db_path)?;
    Ok(messages
        .into_iter()
        .map(|m| MessageResponse {
            sender: m.sender,
            content: m.content,
            timestamp: m.timestamp,
            media_count: m.media_count,
        })
        .collect())
}

#[tauri::command]
async fn parse_slack(export_dir: String) -> Result<Vec<MessageResponse>, String> {
    let parser = SlackParser::new();
    let messages = parser.parse(&export_dir)?;
    Ok(messages
        .into_iter()
        .map(|m| MessageResponse {
            sender: m.sender,
            content: m.content,
            timestamp: m.timestamp,
            media_count: m.media_count,
        })
        .collect())
}

#[tauri::command]
async fn recover_browser_history(
    browser: String,
    profile_path: String,
) -> Result<Vec<HistoryResponse>, String> {
    let recoverer = BrowserHistoryRecoverer::new();
    let entries = recoverer.recover(&browser, &profile_path)?;
    Ok(entries
        .into_iter()
        .map(|e| HistoryResponse {
            url: e.url,
            title: e.title,
            timestamp: e.timestamp,
            visit_count: e.visit_count,
        })
        .collect())
}

#[tauri::command]
async fn carve_sqlite(
    device_path: String,
    output_dir: String,
) -> Result<Vec<PathBuf>, String> {
    let carver = SqliteCarver::new();
    carver.carve(&device_path, Path::new(&output_dir))
}

#[tauri::command]
async fn recover_emails(input_path: String) -> Result<Vec<EmailResponse>, String> {
    let recoverer = EmailRecoverer::new();
    let emails = recoverer.recover(&input_path)?;
    Ok(emails
        .into_iter()
        .map(|e| EmailResponse {
            from: e.from,
            to: e.to,
            subject: e.subject,
            date: e.date,
            has_attachments: e.has_attachments,
        })
        .collect())
}

#[tauri::command]
async fn resume_scan(device_path: String) -> Result<ScanStateResponse, String> {
    let manager = ScanManager::new();
    let state = manager.resume_scan(&device_path)?;
    Ok(ScanStateResponse {
        device: state.device,
        scan_type: state.scan_type,
        offset: state.offset,
        progress: state.progress,
        interrupted_at: state.interrupted_at,
    })
}

#[tauri::command]
async fn list_interrupted_scans() -> Result<Vec<ScanStateResponse>, String> {
    let manager = ScanManager::new();
    let scans = manager.list_interrupted_scans()?;
    Ok(scans
        .into_iter()
        .map(|s| ScanStateResponse {
            device: s.device,
            scan_type: s.scan_type,
            offset: s.offset,
            progress: s.progress,
            interrupted_at: s.interrupted_at,
        })
        .collect())
}

#[tauri::command]
async fn incremental_scan(
    device_path: String,
    output_dir: String,
) -> Result<IncrementalResponse, String> {
    let manager = ScanManager::new();
    let result = manager.incremental_scan(&device_path, Path::new(&output_dir))?;
    Ok(IncrementalResponse {
        new_sectors: result.new_sectors,
        total_scanned: result.total_scanned,
        new_files: result.new_files,
    })
}

#[tauri::command]
async fn batch_add_job(
    device: String,
    output: String,
    mode: String,
) -> Result<String, String> {
    let processor = BatchProcessor::new();
    processor.add_job(&device, &output, &mode)
}

#[tauri::command]
async fn batch_start() -> Result<String, String> {
    let processor = BatchProcessor::new();
    processor.start()
}

#[tauri::command]
async fn batch_status() -> Result<Vec<JobStatusResponse>, String> {
    let processor = BatchProcessor::new();
    let jobs = processor.status()?;
    Ok(jobs
        .into_iter()
        .map(|j| JobStatusResponse {
            id: j.id,
            device: j.device,
            status: j.status,
            progress: j.progress,
        })
        .collect())
}

#[tauri::command]
async fn create_case(
    case_number: String,
    examiner: String,
) -> Result<String, String> {
    let manager = CaseManager::new();
    manager.create_case(&case_number, &examiner)
}

#[tauri::command]
async fn add_evidence(
    case_id: String,
    device_path: String,
) -> Result<String, String> {
    let manager = CaseManager::new();
    manager.add_evidence(&case_id, &device_path)
}

#[tauri::command]
async fn generate_case_report(case_id: String) -> Result<String, String> {
    let manager = CaseManager::new();
    manager.generate_report(&case_id)
}

#[tauri::command]
async fn start_api_server(port: u16) -> Result<String, String> {
    let server = ApiServer::new();
    server.start(port)
}

fn main() {
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::env::temp_dir())
        .join("bytesurgeon");
    let engine = RecoveryEngine::new(&data_dir).expect("Failed to initialize engine");

    tauri::Builder::default()
        .manage(AppState {
            engine: Mutex::new(engine),
            data_dir,
        })
        .invoke_handler(tauri::generate_handler![
            scan_devices,
            start_recovery,
            get_sessions,
            get_recovered_files,
            scan_threats,
            check_compliance,
            scan_partitions,
            hex_view,
            preview_file,
            get_image_info,
            check_encryption,
            generate_report,
            get_signature_counts,
            check_write_protection,
            find_duplicates,
            detect_raid,
            parse_usn_journal,
            detect_shadow_copies,
            scan_fragments,
            repair_file,
            parse_registry,
            recover_whatsapp,
            recover_imessage,
            recover_signal,
            parse_slack,
            recover_browser_history,
            carve_sqlite,
            recover_emails,
            resume_scan,
            list_interrupted_scans,
            incremental_scan,
            batch_add_job,
            batch_start,
            batch_status,
            create_case,
            add_evidence,
            generate_case_report,
            start_api_server,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
