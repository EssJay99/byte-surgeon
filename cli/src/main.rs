use clap::{Parser, Subcommand};
#[allow(unused_imports)]
use bytesurgeon_core::{
    RecoveryEngine, ScanType, PartitionScanner, HexViewer, FilePreviewer,
    SignatureDatabase, RecoveryFilter, RecoveryFilterBuilder,
    WriteProtector, DeduplicationEngine, ReportGenerator, ReportData,
};
#[allow(unused_imports)]
use bytesurgeon_diskimage::{self, DiskImage};
#[allow(unused_imports)]
use bytesurgeon_encryption::{self, EncryptedVolume, VolumeType};
#[allow(unused_imports)]
use bytesurgeon_raid::{self, RaidReconstructor, RaidLevel};
use bytesurgeon_devices::DeviceDetector;
use bytesurgeon_security::compliance::ComplianceChecker;
use bytesurgeon_security::SecurityScanner;
use bytesurgeon_crypto::DecryptionEngine;
#[allow(unused_imports)]
use bytesurgeon_forensic::{
    UsnJournalParser, ShadowCopyDetector, FragmentScanner, FileReparer, RegistryParser,
};
#[allow(unused_imports)]
use bytesurgeon_chat::{
    WhatsAppRecoverer, IMessageRecoverer, SignalRecoverer, SlackParser,
    BrowserHistoryRecoverer, SqliteCarver, EmailRecoverer,
};
#[allow(unused_imports)]
use bytesurgeon_enterprise::{
    ScanManager, BatchProcessor, CaseManager, ApiServer,
};
mod wizards;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::path::PathBuf;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use dialoguer::Input;
use walkdir::WalkDir;

#[derive(Parser)]
#[command(name = "Byte Surgeon")]
#[command(about = "Advanced cross-platform data recovery software")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "info")]
    log_level: String,

    #[arg(short, long, default_value = "./bytesurgeon_data")]
    data_dir: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Scan for connected devices")]
    Scan,

    #[command(about = "Recover data from a device")]
    Recover {
        #[arg(short, long)]
        device: String,

        #[arg(short, long, default_value = "signature")]
        mode: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "List recovery sessions")]
    Sessions,

    #[command(about = "Show recovered files from a session")]
    Files {
        #[arg(short, long)]
        session: String,
    },

    #[command(about = "Scan file for threats")]
    ThreatScan {
        #[arg(short, long)]
        path: PathBuf,
    },

    #[command(about = "Check system compliance")]
    Compliance,

    #[command(about = "Show device information")]
    Info {
        #[arg(short, long)]
        device: String,
    },

    #[command(about = "Run network scan")]
    NetworkScan {
        #[arg(short, long, default_value = "192.168.1")]
        subnet: String,
    },

    #[command(about = "Decrypt encrypted file")]
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "Scan for partitions on a device")]
    PartitionScan {
        #[arg(short, long)]
        device: String,
    },

    #[command(about = "View raw hex of device/file")]
    HexView {
        #[arg(short, long)]
        path: String,

        #[arg(short, long, default_value_t = 0)]
        offset: u64,

        #[arg(short, long, default_value_t = 512)]
        length: usize,
    },

    #[command(about = "Preview a recovered file")]
    Preview {
        #[arg(short, long)]
        path: PathBuf,
    },

    #[command(about = "Show disk image information")]
    ImageInfo {
        #[arg(short, long)]
        path: PathBuf,
    },

    #[command(about = "Create disk image from device")]
    CreateImage {
        #[arg(short, long)]
        device: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "Show RAID configuration")]
    RaidInfo {
        #[arg(short, long, num_args = 1..)]
        disks: Vec<String>,
    },

    #[command(about = "Check if volume is encrypted")]
    EncryptedCheck {
        #[arg(short, long)]
        device: String,
    },

    #[command(about = "Generate recovery report")]
    Report {
        #[arg(short, long)]
        session: String,

        #[arg(short, long, default_value = "text")]
        format: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "Show signature database info")]
    Signatures {
        #[arg(short, long)]
        category: Option<String>,
    },

    #[command(about = "Check write protection status")]
    WriteProtect {
        #[arg(short, long)]
        device: String,
    },

    #[command(about = "Find duplicate files in recovered data")]
    Dedup {
        #[arg(short, long)]
        directory: PathBuf,
    },

    #[command(about = "Parse NTFS USN Journal")]
    UsnJournal {
        #[arg(short, long)]
        device: String,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "List and extract Volume Shadow Copies")]
    ShadowCopies {
        #[arg(short, long)]
        device: String,

        #[arg(short, long)]
        extract: Option<String>,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "Scan for and reassemble file fragments")]
    Fragments {
        #[arg(short, long)]
        device: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "Repair corrupted files")]
    Repair {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(short, long)]
        format: String,
    },

    #[command(about = "Parse Windows registry hive")]
    Registry {
        #[arg(short, long)]
        hive: PathBuf,

        #[arg(short, long)]
        extract: Option<String>,
    },

    #[command(about = "Recover WhatsApp messages")]
    Whatsapp {
        #[arg(short, long)]
        database: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "Recover iMessage/SMS")]
    Imessage {
        #[arg(short, long)]
        database: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "Recover Signal messages")]
    Signal {
        #[arg(short, long)]
        database: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "Parse Slack export")]
    Slack {
        #[arg(short, long)]
        export_dir: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "Recover browser history")]
    BrowserHistory {
        #[arg(short, long)]
        browser: String,

        #[arg(short, long)]
        profile: PathBuf,
    },

    #[command(about = "Carve SQLite databases from device")]
    SqliteCarve {
        #[arg(short, long)]
        device: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "Recover emails from PST/OST/MBOX")]
    Email {
        #[arg(short, long)]
        input: PathBuf,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    #[command(about = "Resume interrupted scan")]
    ResumeScan {
        #[arg(short, long)]
        device: String,

        #[arg(short, long, default_value_t = false)]
        list: bool,
    },

    #[command(about = "Perform incremental scan")]
    IncrementalScan {
        #[arg(short, long)]
        device: String,

        #[arg(short, long)]
        output: PathBuf,
    },

    #[command(about = "Batch processing")]
    Batch {
        #[arg(short, long)]
        command: String,

        #[arg(short, long)]
        job_id: Option<String>,
    },

    #[command(about = "Forensic case management")]
    Case {
        #[arg(short, long)]
        command: String,

        #[arg(short, long)]
        case_id: Option<String>,
    },

    #[command(about = "Start REST API server")]
    ApiServer {
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
    },

    #[command(about = "Run interactive command wizards")]
    Wizard {
        #[arg(short, long)]
        name: Option<String>,

        #[arg(short, long)]
        list: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&cli.log_level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Scan => {
            println!("{}", "Scanning for devices...".cyan());
            let detector = DeviceDetector::new();
            let devices = detector.detect_all_devices()?;

            if devices.is_empty() {
                println!("{}", "No devices found".yellow());
            } else {
                println!("{}", format!("Found {} devices:", devices.len()).green());
                for (i, device) in devices.iter().enumerate() {
                    println!("  {}. {} - {} ({:?})",
                             i + 1,
                             device.name,
                             device.path,
                             device.device_type);
                }
            }
        }

        Commands::Recover { device, mode, output } => {
            println!("{}", "Starting data recovery...".cyan());

            let engine = RecoveryEngine::new(&cli.data_dir)?;
            let devices = engine.get_all_devices()?;

            let target_device = devices.iter().find(|d| d.path == device || d.name == device);

            if let Some(device_info) = target_device {
                let scan_type = match mode.as_str() {
                    "quick" => ScanType::Quick,
                    "deep" => ScanType::Deep,
                    "signature" => ScanType::Signature,
                    "filesystem" => ScanType::FileSystem,
                    "raw" => ScanType::Raw,
                    _ => ScanType::Signature,
                };

                let pb = ProgressBar::new_spinner();
                pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.green} {msg}")
                        .unwrap()
                );
                pb.set_message("Recovering files...");
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                let session_id = engine.start_recovery(device_info, scan_type, &output)?;

                pb.finish_with_message(format!("Recovery complete! Session ID: {}", session_id));
                println!("{}", format!("Session ID: {}", session_id).green());
            } else {
                println!("{}", format!("Device not found: {}", device).red());
            }
        }

        Commands::Sessions => {
            let engine = RecoveryEngine::new(&cli.data_dir)?;
            let devices = engine.get_all_devices()?;

            println!("{}", "Recovery Sessions:".cyan());
            for device in devices {
                println!("\nDevice: {} ({})", device.name, device.path);
                println!("  No sessions found");
            }
        }

        Commands::Files { session } => {
            let engine = RecoveryEngine::new(&cli.data_dir)?;
            let files = engine.get_recovered_files(&session)?;

            if files.is_empty() {
                println!("{}", "No files recovered in this session".yellow());
            } else {
                println!("{}", format!("Recovered {} files:", files.len()).green());
                for file in files {
                    println!("  - {} ({} bytes) - {:?}",
                             file.recovered_path,
                             file.file_size,
                             file.status);
                }
            }
        }

        Commands::ThreatScan { path } => {
            println!("{}", format!("Scanning {} for threats...", path.display()).cyan());

            let scanner = bytesurgeon_security::malware::MalwareScanner::new();
            let status = scanner.scan_file(&path)?;

            match status {
                bytesurgeon_core::ThreatStatus::Clean => {
                    println!("{}", "✓ File is clean".green());
                }
                bytesurgeon_core::ThreatStatus::Suspicious => {
                    println!("{}", "⚠ File contains suspicious patterns".yellow());
                }
                bytesurgeon_core::ThreatStatus::ThreatDetected => {
                    println!("{}", "✗ Threat detected!".red());
                }
                _ => {
                    println!("{}", "? Scan incomplete".yellow());
                }
            }
        }

        Commands::Compliance => {
            println!("{}", "Checking system compliance...".cyan());

            let checker = ComplianceChecker::new();
            let report = checker.check_nist_compliance()?;

            println!("{}", format!("Standard: {}", report.standard).cyan());
            println!("Status: {}", if report.passed { "PASSED".green() } else { "FAILED".red() });

            if !report.findings.is_empty() {
                println!("\nFindings:");
                for finding in report.findings {
                    println!("  - {}", finding);
                }
            }

            if !report.recommendations.is_empty() {
                println!("\nRecommendations:");
                for rec in report.recommendations {
                    println!("  - {}", rec);
                }
            }
        }

        Commands::Info { device } => {
            let engine = RecoveryEngine::new(&cli.data_dir)?;
            let devices = engine.get_all_devices()?;

            if let Some(device_info) = devices.iter().find(|d| d.path == device || d.name == device) {
                println!("{}", format!("Device Information: {}", device_info.name).cyan());
                println!("  Path: {}", device_info.path);
                println!("  Type: {:?}", device_info.device_type);
                println!("  File System: {:?}", device_info.file_system);
                println!("  Total Size: {} bytes", device_info.total_size);
                println!("  Free Space: {} bytes", device_info.free_space);

                if let Some(vendor) = &device_info.vendor {
                    println!("  Vendor: {}", vendor);
                }
                if let Some(model) = &device_info.model {
                    println!("  Model: {}", model);
                }
                if let Some(mount) = &device_info.mount_point {
                    println!("  Mount Point: {}", mount);
                }
            } else {
                println!("{}", format!("Device not found: {}", device).red());
            }
        }

        Commands::NetworkScan { subnet } => {
            println!("{}", format!("Scanning network {}...", subnet).cyan());

            let scanner = bytesurgeon_network::NetworkScanner::new();
            let hosts = scanner.scan_subnet(&subnet)?;

            if hosts.is_empty() {
                println!("{}", "No hosts found".yellow());
            } else {
                println!("{}", format!("Found {} hosts:", hosts.len()).green());
                for host in hosts {
                    println!("  - {}", host);
                }
            }
        }

        Commands::Decrypt { input, output } => {
            println!("{}", "Decrypting file...".cyan());

            let decryptor = bytesurgeon_crypto::decryptor::FileDecryptor::new();

            if decryptor.is_encrypted(&input)? {
                let enc_type = decryptor.get_encryption_type(&input)?;
                println!("Encryption type: {}", enc_type);

                let password: String = Input::new()
                    .with_prompt("Enter password")
                    .interact_text()?;

                match decryptor.decrypt_file(&input, &output, &password) {
                    Ok(_) => println!("{}", "✓ Decryption successful".green()),
                    Err(e) => println!("{}", format!("✗ Decryption failed: {}", e).red()),
                }
            } else {
                println!("{}", "File is not encrypted".yellow());
            }
        }

        Commands::PartitionScan { device } => {
            println!("{}", format!("Scanning partitions on {}...", device).cyan());

            let scanner = PartitionScanner::new(&device);

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning MBR partitions...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            match scanner.scan_mbr() {
                Ok(partitions) if !partitions.is_empty() => {
                    pb.finish_with_message("MBR scan complete");
                    println!("\n{}", "MBR Partitions:".cyan());
                    for p in &partitions {
                        println!("  #{} {} {:?} {:?} sectors {}-{} {}",
                                 p.index,
                                 if p.is_active { "[ACTIVE]" } else { "        " },
                                 p.partition_type,
                                 p.filesystem,
                                 p.start_sector,
                                 p.end_sector,
                                 if p.is_gpt { "(GPT)" } else { "(MBR)" });
                    }
                }
                _ => {
                    pb.finish_with_message("No MBR partitions found");
                    println!("\n{}", "No MBR partitions found".yellow());
                }
            }

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning GPT partitions...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            match scanner.scan_gpt() {
                Ok(partitions) if !partitions.is_empty() => {
                    pb.finish_with_message("GPT scan complete");
                    println!("\n{}", "GPT Partitions:".cyan());
                    for p in &partitions {
                        let guid_str = p.guid.as_deref().unwrap_or("N/A");
                        println!("  #{} {:?} {:?} sectors {}-{} GUID: {}",
                                 p.index,
                                 p.partition_type,
                                 p.filesystem,
                                 p.start_sector,
                                 p.end_sector,
                                 guid_str);
                    }
                }
                _ => {
                    pb.finish_with_message("No GPT partitions found");
                    println!("\n{}", "No GPT partitions found".yellow());
                }
            }

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning for lost partitions...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            match scanner.find_lost_partitions() {
                Ok(partitions) if !partitions.is_empty() => {
                    pb.finish_with_message(format!("Found {} lost partitions", partitions.len()));
                    println!("\n{}", "Lost Partitions:".cyan());
                    for p in &partitions {
                        println!("  #{} {:?} {:?} sectors {}-{}",
                                 p.index,
                                 p.partition_type,
                                 p.filesystem,
                                 p.start_sector,
                                 p.end_sector);
                    }
                }
                _ => {
                    pb.finish_with_message("No lost partitions found");
                    println!("\n{}", "No lost partitions found".yellow());
                }
            }
        }

        Commands::HexView { path, offset, length } => {
            println!("{}", format!("Hex view: {} (offset={}, length={})", path, offset, length).cyan());

            let viewer = HexViewer::new();
            let dump = viewer.read_hex(std::path::Path::new(&path), offset, length)?;

            println!();
            print!("{}", dump.formatted_output);
            println!("\n{} bytes read from offset 0x{:X}", dump.data.len(), dump.offset);
        }

        Commands::Preview { path } => {
            println!("{}", format!("Previewing {}...", path.display()).cyan());

            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("unknown")
                .to_string();

            let previewer = FilePreviewer::new();
            let preview = previewer.generate_preview(&path, &ext)?;

            println!("\n{}", "File Preview:".cyan());
            println!("  File Type : {}", preview.file_type);
            println!("  MIME Type : {}", preview.mime_type);
            println!("  Data Size : {} bytes", preview.preview_bytes.len());

            if let Some(thumb) = &preview.thumbnail_data {
                println!("  Thumbnail : {} bytes", thumb.len());
            }

            if let Some(text) = &preview.text_content {
                println!("\n{}", "Content Preview:".cyan());
                let max_lines = 30;
                for (i, line) in text.lines().enumerate() {
                    if i >= max_lines {
                        println!("  ... ({} more lines)", text.lines().count() - max_lines);
                        break;
                    }
                    println!("  {}", line);
                }
            }
        }

        Commands::ImageInfo { path } => {
            println!("{}", format!("Analyzing disk image: {}", path.display()).cyan());

            if !path.exists() {
                println!("{}", format!("File not found: {}", path.display()).red());
                return Ok(());
            }

            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            let metadata = std::fs::metadata(&path)?;
            println!("\n{}", "Image Information:".cyan());
            println!("  Path      : {}", path.display());
            println!("  File Size : {} bytes", metadata.len());

            let detected_format = match ext.as_str() {
                "e01" | "ex01" => "E01 (EnCase)",
                "vmdk" => "VMDK (VMware)",
                "vhd" | "vhdx" => "VHD/VHDX (Hyper-V)",
                "img" | "raw" | "dd" | "bin" | "iso" => "Raw",
                _ => {
                    let mut header = [0u8; 8];
                    if let Ok(mut f) = std::fs::File::open(&path) {
                        use std::io::Read;
                        let _ = f.read(&mut header);
                    }
                    if &header[0..4] == b"con\x65ctix" || &header[0..8] == b"conectix" {
                        "VHD"
                    } else if &header[0..8] == b"vhdxfile" {
                        "VHDX"
                    } else if header[0] == 0x4B && header[1] == 0x44 && header[2] == 0x4D && header[3] == 0x56 {
                        "VMDK (sparse)"
                    } else if header[0] == 0x76 && header[1] == 0x68 && header[2] == 0x64 && header[3] == 0x78 {
                        "VHDX"
                    } else {
                        "Raw"
                    }
                }
            };

            println!("  Format    : {}", detected_format.green());

            let result: anyhow::Result<()> = match detected_format {
                "VMDK (sparse)" | "VMDK (VMware)" => {
                    match bytesurgeon_diskimage::vmdk::VmdkImage::open(&path) {
                        Ok(img) => {
                            let meta = img.metadata();
                            print_image_metadata(&meta);
                        }
                        Err(e) => println!("  {} (metadata unavailable: {})", "Warning:".yellow(), e),
                    }
                    Ok(())
                }
                "VHD" | "VHDX" | "VHD/VHDX (Hyper-V)" => {
                    match bytesurgeon_diskimage::vhd::VhdImage::open(&path) {
                        Ok(img) => {
                            let meta = img.metadata();
                            print_image_metadata(&meta);
                        }
                        Err(e) => println!("  {} (metadata unavailable: {})", "Warning:".yellow(), e),
                    }
                    Ok(())
                }
                "E01 (EnCase)" => {
                    match bytesurgeon_diskimage::e01::E01Image::open(&path) {
                        Ok(img) => {
                            let meta = img.metadata();
                            print_image_metadata(&meta);
                        }
                        Err(e) => println!("  {} (metadata unavailable: {})", "Warning:".yellow(), e),
                    }
                    Ok(())
                }
                _ => {
                    match bytesurgeon_diskimage::raw::RawImage::open(&path) {
                        Ok(img) => {
                            let meta = img.metadata();
                            print_image_metadata(&meta);
                        }
                        Err(e) => println!("  {} (metadata unavailable: {})", "Warning:".yellow(), e),
                    }
                    Ok(())
                }
            };

            if let Err(e) = result {
                println!("{}", format!("Error reading image: {}", e).red());
            }
        }

        Commands::CreateImage { device, output } => {
            println!("{}", format!("Creating disk image from {}...", device).cyan());

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Imaging device...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            match bytesurgeon_diskimage::raw::RawImage::create_from_device(
                std::path::Path::new(&device),
                &output,
            ) {
                Ok(img) => {
                    let meta = img.metadata();
                    pb.finish_with_message("Imaging complete");
                    println!("\n{}", "Image Created:".green());
                    println!("  Output     : {}", output.display());
                    println!("  Size       : {} bytes", meta.size_bytes);
                    println!("  Sectors    : {}", meta.total_sectors);
                    if let Some(hash) = &meta.sha256 {
                        println!("  SHA-256    : {}", hash);
                    }
                }
                Err(e) => {
                    pb.finish_with_message("Imaging failed");
                    println!("{}", format!("Error: {}", e).red());
                }
            }
        }

        Commands::RaidInfo { disks } => {
            println!("{}", format!("Analyzing RAID configuration across {} disks...", disks.len()).cyan());

            let mut raid_disks = Vec::new();
            for (i, disk_path) in disks.iter().enumerate() {
                let data = match std::fs::read(disk_path) {
                    Ok(d) => d,
                    Err(e) => {
                        println!("{}", format!("Warning: could not read {}: {}", disk_path, e).yellow());
                        Vec::new()
                    }
                };
                let size = data.len() as u64;
                raid_disks.push(bytesurgeon_raid::RaidDisk {
                    path: disk_path.clone(),
                    size,
                    position: i,
                    data,
                });
            }

            let detector = bytesurgeon_raid::RaidDetector::new();
            match detector.detect(&raid_disks) {
                Ok(info) => {
                    println!("\n{}", "RAID Information:".cyan());
                    println!("  RAID Level  : {:?}", info.level);
                    println!("  Disk Count  : {}", info.disk_count);
                    println!("  Stripe Size : {} bytes", info.stripe_size);
                    println!("  Chunk Size  : {} bytes", info.chunk_size);

                    if info.level == RaidLevel::Unknown {
                        println!("\n{}", "Could not auto-detect RAID level.".yellow());
                        println!("Provide disks with RAID metadata for detection.");
                    }
                }
                Err(e) => {
                    println!("{}", format!("RAID detection failed: {}", e).red());
                }
            }
        }

        Commands::EncryptedCheck { device } => {
            println!("{}", format!("Checking encryption on {}...", device).cyan());

            let mut detected = Vec::new();

            match bytesurgeon_encryption::bitlocker::BitLockerVolume::detect(&device) {
                Ok(true) => detected.push(("BitLocker", VolumeType::BitLocker)),
                Ok(false) => {}
                Err(e) => println!("  BitLocker check error: {}", e),
            }

            match bytesurgeon_encryption::filevault::FileVaultVolume::detect(&device) {
                Ok(true) => detected.push(("FileVault", VolumeType::FileVault)),
                Ok(false) => {}
                Err(e) => println!("  FileVault check error: {}", e),
            }

            match bytesurgeon_encryption::luks::LuksVolume::detect(&device) {
                Ok(true) => detected.push(("LUKS", VolumeType::LUKS)),
                Ok(false) => {}
                Err(e) => println!("  LUKS check error: {}", e),
            }

            match bytesurgeon_encryption::veracrypt::VeraCryptVolume::detect(&device) {
                Ok(true) => detected.push(("VeraCrypt", VolumeType::VeraCrypt)),
                Ok(false) => {}
                Err(e) => println!("  VeraCrypt check error: {}", e),
            }

            if detected.is_empty() {
                println!("\n{}", "No encryption detected.".green());
            } else {
                println!("\n{}", "Encryption Detected:".red());
                for (name, vol_type) in &detected {
                    println!("  - {} ({})", name, vol_type);
                }
            }
        }

        Commands::Report { session, format, output } => {
            println!("{}", format!("Generating {} report for session {}...", format, session).cyan());

            let engine = RecoveryEngine::new(&cli.data_dir)?;

            let session_data = engine.get_session(&session)?;
            let files = engine.get_recovered_files(&session)?;

            match session_data {
                Some(sess) => {
                    let generator = ReportGenerator::new();
                    let data = generator.generate_report_data(&sess, &files);

                    match format.as_str() {
                        "csv" => {
                            generator.generate_csv(&data, &output)?;
                            println!("{}", format!("CSV report written to {}", output.display()).green());
                        }
                        "html" => {
                            generator.generate_html(&data, &output)?;
                            println!("{}", format!("HTML report written to {}", output.display()).green());
                        }
                        "text" | "txt" => {
                            generator.generate_text(&data, &output)?;
                            println!("{}", format!("Text report written to {}", output.display()).green());
                        }
                        other => {
                            println!("{}", format!("Unknown format '{}'. Use: csv, html, text", other).red());
                        }
                    }

                    println!("\n{}", "Report Summary:".cyan());
                    println!("  Files Found     : {}", data.statistics.total_files_found);
                    println!("  Files Recovered : {}", data.statistics.total_files_recovered);
                    println!("  Total Size      : {} bytes", data.statistics.total_size_recovered);
                    println!("  Recovery Rate   : {:.1}%", data.statistics.recovery_rate);
                }
                None => {
                    println!("{}", format!("Session not found: {}", session).red());
                }
            }
        }

        Commands::Signatures { category } => {
            println!("{}", "Signature Database:".cyan());

            let db = SignatureDatabase::new();

            match &category {
                Some(cat) => {
                    let entries = db.by_category_name(cat);
                    println!("\n  Category: {} ({} signatures)", cat.green(), entries.len());
                    println!();
                    println!("  {:<12} {:<40} {:<8}", "Extension", "Description", "Offset");
                    println!("  {:<12} {:<40} {:<8}", "----------", "--------------------", "------");
                    for entry in &entries {
                        let desc = if entry.description.len() > 38 {
                            format!("{}...", &entry.description[..38])
                        } else {
                            entry.description.clone()
                        };
                        println!("  {:<12} {:<40} {:<8}", entry.extension, desc, entry.offset);
                    }
                }
                None => {
                    println!("\n  Total signatures: {}", format!("{}", db.count()).green());
                    println!();

                    let categories = [
                        "Image", "Document", "Audio", "Video", "Archive",
                        "Database", "Executable", "Font", "CAD", "3D",
                        "Backup", "Email", "DiskImage", "Compressed",
                        "Virtual", "Certificate", "Miscellaneous",
                    ];
                    println!("  {:<16} {}", "Category", "Count");
                    println!("  {:<16} {}", "----------------", "-----");
                    for cat in &categories {
                        let entries = db.by_category_name(cat);
                        println!("  {:<16} {}", cat, entries.len());
                    }
                }
            }
        }

        Commands::WriteProtect { device } => {
            println!("{}", format!("Checking write protection for {}...", device).cyan());

            let mut protector = WriteProtector::new();
            match protector.verify_device(&device) {
                Ok(status) => {
                    println!("\n{}", "Write Protection Status:".cyan());
                    println!("  Device       : {}", status.device_path);
                    println!("  Protected    : {}",
                             if status.is_write_protected {
                                 "YES".green()
                             } else {
                                 "NO".red()
                             });
                    println!("  Method       : {}", status.method_used);
                    println!("  Details      : {}", status.details);
                    println!("  Verified At  : {}", status.verified_at.format("%Y-%m-%d %H:%M:%S UTC"));

                    if !status.is_write_protected {
                        println!("\n{}", "WARNING: Device is NOT write-protected!".red());
                        println!("Proceed with caution to avoid data modification.");
                    }
                }
                Err(e) => {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
        }

        Commands::Dedup { directory } => {
            println!("{}", format!("Scanning for duplicates in {}...", directory.display()).cyan());

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning files...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let mut engine = DeduplicationEngine::new();
            let mut file_count = 0u64;

            for entry in WalkDir::new(&directory).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let _ = engine.record_file(entry.path());
                    file_count += 1;
                    if file_count % 100 == 0 {
                        pb.set_message(format!("Scanned {} files...", file_count));
                    }
                }
            }

            pb.finish_with_message(format!("Scanned {} files", file_count));

            let duplicates = engine.get_duplicates()?;
            let dup_count = engine.get_duplicate_count();
            let total_files = engine.get_total_files();
            let unique = engine.get_unique_count();
            let saved = engine.get_duplicate_bytes_saved()?;

            println!("\n{}", "Deduplication Results:".cyan());
            println!("  Total Files    : {}", total_files);
            println!("  Unique Files   : {}", unique);
            println!("  Duplicate Sets : {}", dup_count);
            println!("  Space Wasted   : {} bytes", saved);

            if !duplicates.is_empty() {
                println!("\n{}", "Duplicate Groups:".cyan());
                for (i, (hash, paths)) in duplicates.iter().enumerate().take(20) {
                    println!("\n  Group {} (hash: {}...)", i + 1, &hash[..16]);
                    for path in paths {
                        println!("    - {}", path.display());
                    }
                }
                if duplicates.len() > 20 {
                    println!("\n  ... and {} more groups", duplicates.len() - 20);
                }
            }
        }

        Commands::UsnJournal { device, output } => {
            println!("{}", format!("Parsing USN Journal from {}...", device).cyan());

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Parsing journal entries...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let parser = UsnJournalParser::new();
            let entries = parser.parse(&device).map_err(|e| anyhow::anyhow!("{}", e))?;

            pb.finish_with_message(format!("Found {} entries", entries.len()));

            println!("\n{}", format!("Total entries: {}", entries.len()).green());

            if !entries.is_empty() {
                println!("\n{}", "Journal Entries:".cyan());
                for entry in &entries {
                    println!("  - {} (USN: {}, {})", entry.filename, entry.usn, entry.reason);
                }
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&entries)?;
                std::fs::write(&output_path, &json)?;
                println!("\n{}", format!("Results written to {}", output_path.display()).green());
            }
        }

        Commands::ShadowCopies { device, extract, output } => {
            println!("{}", format!("Scanning for Volume Shadow Copies on {}...", device).cyan());

            let detector = ShadowCopyDetector::new();
            let copies = detector.detect(&device).map_err(|e| anyhow::anyhow!("{}", e))?;

            if copies.is_empty() {
                println!("{}", "No shadow copies found".yellow());
            } else {
                println!("{}", format!("Found {} shadow copies:", copies.len()).green());
                for copy in &copies {
                    println!("  - {} ({} bytes)", copy.id, copy.size);
                    println!("    Volume: {}", copy.volume);
                    println!("    Created: {}", copy.created);
                }

                if let Some(extract_id) = extract {
                    println!("\n{}", format!("Extracting shadow copy {}...", extract_id).cyan());
                    let out = output.unwrap_or_else(|| PathBuf::from("extracted_shadow"));
                    std::fs::create_dir_all(&out)?;
                    println!("{}", format!("Shadow copy {} would be extracted to {}", extract_id, out.display()).green());
                }
            }
        }

        Commands::Fragments { device, output } => {
            println!("{}", format!("Scanning for file fragments on {}...", device).cyan());

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning fragments...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let scanner = FragmentScanner::new();
            let fragments = scanner.scan(&device).map_err(|e| anyhow::anyhow!("{}", e))?;
            pb.finish_with_message(format!("Found {} fragments", fragments.len()));

            println!("\n{}", format!("Found {} fragments", fragments.len()).green());

            if fragments.is_empty() {
                println!("{}", "No fragments found".yellow());
            } else {
                for frag in &fragments {
                    println!("  - offset: {}, size: {}, sig: {}, confidence: {:.0}%",
                             frag.offset,
                             frag.size,
                             frag.signature,
                             frag.confidence * 100.0);
                }

                std::fs::create_dir_all(&output)?;
                let json = serde_json::to_string_pretty(&fragments)?;
                let fragments_json = output.join("fragments.json");
                std::fs::write(&fragments_json, &json)?;
                println!("\n{}", format!("Fragment data written to {}", fragments_json.display()).green());
            }
        }

        Commands::Repair { input, output, format } => {
            println!("{}", format!("Repairing {} as {}...", input.display(), format).cyan());

            let repairer = FileReparer::new();

            let result = repairer.repair(&input, &output, &format).map_err(|e| anyhow::anyhow!("{}", e))?;

            if result.success {
                println!("{}", "Repair successful!".green());
                println!("  Format        : {}", result.format);
                println!("  Original size : {} bytes", result.input_size);
                println!("  Output size   : {} bytes", result.output_size);
                println!("\n{}", format!("Output written to {}", output.display()).green());
            } else {
                println!("{}", "Repair failed".red());
            }
        }

        Commands::Registry { hive, extract } => {
            println!("{}", format!("Parsing registry hive: {}...", hive.display()).cyan());

            let parser = RegistryParser::new();
            let result = parser.parse(&hive.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", "Registry Hive Information:".cyan());
            println!("  Keys         : {}", result.keys.len());
            println!("  Values       : {}", result.values.len());
            println!("  User Activity: {}", result.user_activity.len());

            if !result.keys.is_empty() {
                println!("\n{}", "Keys:".cyan());
                for key in result.keys.iter().take(20) {
                    println!("  - {}", key);
                }
                if result.keys.len() > 20 {
                    println!("  ... and {} more keys", result.keys.len() - 20);
                }
            }

            if !result.values.is_empty() {
                println!("\n{}", "Values:".cyan());
                for val in result.values.iter().take(20) {
                    println!("  - {}", val);
                }
            }

            if !result.user_activity.is_empty() {
                println!("\n{}", "User Activity:".cyan());
                for activity in result.user_activity.iter().take(20) {
                    println!("  - {}", activity);
                }
            }

            if let Some(extract_type) = extract {
                match extract_type.to_lowercase().as_str() {
                    "user-activity" | "activity" => {
                        println!("\n{}", "User activity data included above.".green());
                    }
                    "software" | "installed" => {
                        println!("\n{}", "Note: Software extraction requires full hive parsing.".yellow());
                    }
                    _ => {
                        println!("{}", format!("Unknown extract type: {}. Use: user-activity, software", extract_type).red());
                    }
                }
            }
        }

        Commands::Whatsapp { database, output } => {
            println!("{}", format!("Recovering WhatsApp messages from {}...", database.display()).cyan());

            let recoverer = WhatsAppRecoverer::new();
            let messages = recoverer.recover(&database.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", format!("Recovered {} messages", messages.len()).green());

            if !messages.is_empty() {
                println!("\n{}", "Recent Messages:".cyan());
                for msg in messages.iter().take(20) {
                    println!("  [{}] {}: {}",
                             msg.timestamp,
                             msg.sender,
                             if msg.content.len() > 60 { &msg.content[..60] } else { &msg.content });
                }
                if messages.len() > 20 {
                    println!("  ... and {} more messages", messages.len() - 20);
                }
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&messages)?;
                std::fs::write(&output_path, &json)?;
                println!("\n{}", format!("Results written to {}", output_path.display()).green());
            }
        }

        Commands::Imessage { database, output } => {
            println!("{}", format!("Recovering iMessage/SMS from {}...", database.display()).cyan());

            let recoverer = IMessageRecoverer::new();
            let messages = recoverer.recover(&database.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", format!("Recovered {} messages", messages.len()).green());

            if !messages.is_empty() {
                println!("\n{}", "Recent Messages:".cyan());
                for msg in messages.iter().take(20) {
                    println!("  [{}] {}: {}",
                             msg.timestamp,
                             msg.sender,
                             if msg.content.len() > 60 { &msg.content[..60] } else { &msg.content });
                }
                if messages.len() > 20 {
                    println!("  ... and {} more messages", messages.len() - 20);
                }
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&messages)?;
                std::fs::write(&output_path, &json)?;
                println!("\n{}", format!("Results written to {}", output_path.display()).green());
            }
        }

        Commands::Signal { database, output } => {
            println!("{}", format!("Recovering Signal messages from {}...", database.display()).cyan());

            let recoverer = SignalRecoverer::new();
            let messages = recoverer.recover(&database.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", format!("Recovered {} messages", messages.len()).green());

            if !messages.is_empty() {
                println!("\n{}", "Recent Messages:".cyan());
                for msg in messages.iter().take(20) {
                    println!("  [{}] {}: {}",
                             msg.timestamp,
                             msg.sender,
                             if msg.content.len() > 50 { &msg.content[..50] } else { &msg.content });
                }
                if messages.len() > 20 {
                    println!("  ... and {} more messages", messages.len() - 20);
                }
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&messages)?;
                std::fs::write(&output_path, &json)?;
                println!("\n{}", format!("Results written to {}", output_path.display()).green());
            }
        }

        Commands::Slack { export_dir, output } => {
            println!("{}", format!("Parsing Slack export from {}...", export_dir.display()).cyan());

            let parser = SlackParser::new();
            let messages = parser.parse(&export_dir.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", format!("Parsed {} messages", messages.len()).green());

            if !messages.is_empty() {
                println!("\n{}", "Recent Messages:".cyan());
                for msg in messages.iter().take(20) {
                    println!("  [{}] {}: {}",
                             msg.timestamp,
                             msg.sender,
                             if msg.content.len() > 50 { &msg.content[..50] } else { &msg.content });
                }
                if messages.len() > 20 {
                    println!("  ... and {} more messages", messages.len() - 20);
                }
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&messages)?;
                std::fs::write(&output_path, &json)?;
                println!("\n{}", format!("Results written to {}", output_path.display()).green());
            }
        }

        Commands::BrowserHistory { browser, profile } => {
            println!("{}", format!("Recovering {} history from {}...", browser, profile.display()).cyan());

            let recoverer = BrowserHistoryRecoverer::new();
            let entries = recoverer.recover(&browser, &profile.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", format!("Recovered {} history entries", entries.len()).green());

            if !entries.is_empty() {
                println!("\n{}", "Recent History:".cyan());
                for entry in entries.iter().take(30) {
                    println!("  [{}] {} - {}",
                             entry.timestamp,
                             entry.title,
                             entry.url);
                }
                if entries.len() > 30 {
                    println!("  ... and {} more entries", entries.len() - 30);
                }
            }
        }

        Commands::SqliteCarve { device, output } => {
            println!("{}", format!("Carving SQLite databases from {}...", device).cyan());

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning device...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let carver = SqliteCarver::new();
            let found = carver.carve(&device, &output).map_err(|e| anyhow::anyhow!("{}", e))?;

            pb.finish_with_message(format!("Found {} databases", found.len()));

            println!("\n{}", format!("Found {} SQLite databases", found.len()).green());

            if !found.is_empty() {
                for (_i, db_path) in found.iter().enumerate() {
                    println!("  - {} ({} bytes)",
                             db_path.display(),
                             std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0));
                }

                println!("\n{}", format!("Databases written to {}", output.display()).green());
            }
        }

        Commands::Email { input, output } => {
            println!("{}", format!("Recovering emails from {}...", input.display()).cyan());

            let recoverer = EmailRecoverer::new();
            let emails = recoverer.recover(&input.to_string_lossy()).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("\n{}", format!("Recovered {} emails", emails.len()).green());

            if !emails.is_empty() {
                println!("\n{}", "Emails:".cyan());
                for email in emails.iter().take(20) {
                    let to = email.to.join(", ");
                    let attachments = if email.has_attachments { " [ATTACHMENTS]" } else { "" };
                    println!("  [{}] From: {} - To: {}{}", email.date, email.from, to, attachments);
                    println!("    Subject: {}", email.subject);
                }
                if emails.len() > 20 {
                    println!("  ... and {} more emails", emails.len() - 20);
                }
            }

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&emails)?;
                std::fs::write(&output_path, &json)?;
                println!("\n{}", format!("Results written to {}", output_path.display()).green());
            }
        }

        Commands::ResumeScan { device, list } => {
            let manager = ScanManager::new();

            if list {
                println!("{}", "Listing interrupted scans...".cyan());
                let interrupted = manager.list_interrupted_scans().map_err(|e| anyhow::anyhow!("{}", e))?;

                if interrupted.is_empty() {
                    println!("{}", "No interrupted scans found".yellow());
                } else {
                    println!("{}", format!("Found {} interrupted scans:", interrupted.len()).green());
                    for state in &interrupted {
                        println!("  - Device : {}", state.device);
                        println!("    Type   : {}", state.scan_type);
                        println!("    Progress: {:.1}%", state.progress * 100.0);
                        println!("    Offset : {}", state.offset);
                        println!("    Interrupted At: {}", state.interrupted_at);
                        println!();
                    }
                }
            } else {
                println!("{}", format!("Resuming scan for {}...", device).cyan());
                match manager.resume_scan(&device) {
                    Ok(state) => {
                        println!("\n{}", "Found previous scan state:".cyan());
                        println!("  Device  : {}", state.device);
                        println!("  Type    : {}", state.scan_type);
                        println!("  Progress: {:.1}%", state.progress * 100.0);
                        println!("  Offset  : {}", state.offset);
                        println!("\n{}", "Ready to resume from last checkpoint.".green());
                    }
                    Err(e) => {
                        println!("{}", format!("No previous scan found: {}", e).yellow());
                    }
                }
            }
        }

        Commands::IncrementalScan { device, output } => {
            println!("{}", format!("Performing incremental scan on {}...", device).cyan());

            let manager = ScanManager::new();

            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap()
            );
            pb.set_message("Scanning...");
            pb.enable_steady_tick(std::time::Duration::from_millis(100));

            let result = manager.incremental_scan(&device, &output).map_err(|e| anyhow::anyhow!("{}", e))?;

            pb.finish_with_message("Incremental scan complete");

            println!("\n{}", "Scan Results:".cyan());
            println!("  New sectors scanned: {}", result.new_sectors);
            println!("  Total sectors scanned: {}", result.total_scanned);
            println!("  New files found: {}", result.new_files);
            println!("\n{}", format!("Output written to {}", output.display()).green());
        }

        Commands::Batch { command, job_id: _ } => {
            let processor = BatchProcessor::new();

            match command.to_lowercase().as_str() {
                "add" => {
                    println!("{}", "Adding job to batch queue...".cyan());
                    let id = processor.add_job("/dev/sda", "./output", "deep").map_err(|e| anyhow::anyhow!("{}", e))?;
                    println!("{}", format!("Job added with ID: {}", id).green());
                }
                "start" => {
                    println!("{}", "Starting batch execution...".cyan());
                    let msg = processor.start().map_err(|e| anyhow::anyhow!("{}", e))?;
                    println!("{}", format!("Batch execution: {}", msg).green());
                }
                "status" => {
                    println!("{}", "Batch job status:".cyan());
                    let jobs = processor.status().map_err(|e| anyhow::anyhow!("{}", e))?;
                    if jobs.is_empty() {
                        println!("{}", "No jobs in queue".yellow());
                    } else {
                        for job in &jobs {
                            println!("  - {} ({}) - {}: {:.1}%", job.id, job.device, job.status, job.progress * 100.0);
                        }
                    }
                }
                _ => {
                    println!("{}", format!("Unknown command: {}. Use: add, start, status", command).red());
                }
            }
        }

        Commands::Case { command, case_id } => {
            let manager = CaseManager::new();

            match command.to_lowercase().as_str() {
                "create" => {
                    println!("{}", "Creating new forensic case...".cyan());
                    let case_number = format!("CASE-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                    let case_id_result = manager.create_case(&case_number, "CLI User").map_err(|e| anyhow::anyhow!("{}", e))?;
                    println!("{}", format!("Case created: {} (ID: {})", case_number, case_id_result).green());
                }
                "evidence" => {
                    if let Some(id) = &case_id {
                        println!("{}", format!("Adding evidence to case {}...", id).cyan());
                        let evidence_id = manager.add_evidence(id, "/dev/sda").map_err(|e| anyhow::anyhow!("{}", e))?;
                        println!("{}", format!("Evidence added: {}", evidence_id).green());
                    } else {
                        println!("{}", "Please specify --case-id".red());
                    }
                }
                "report" => {
                    if let Some(id) = &case_id {
                        println!("{}", format!("Generating report for case {}...", id).cyan());
                        let report_path = manager.generate_report(id).map_err(|e| anyhow::anyhow!("{}", e))?;
                        println!("\n{}", format!("Report generated: {}", report_path).green());
                    } else {
                        println!("{}", "Please specify --case-id for report".yellow());
                    }
                }
                _ => {
                    println!("{}", format!("Unknown command: {}. Use: create, evidence, report", command).red());
                }
            }
        }

        Commands::ApiServer { port } => {
            println!("{}", format!("Starting REST API server on port {}...", port).cyan());

            let server = ApiServer::new();
            let msg = server.start(port).map_err(|e| anyhow::anyhow!("{}", e))?;

            println!("{}", "API Server started".green());
            println!("  {}", msg);
            println!("\n{}", "Available endpoints:".cyan());
            println!("  GET  /devices  - List devices");
            println!("  POST /scan     - Start scan");
            println!("  GET  /status   - Get scan status");
            println!("  GET  /files    - List recovered files");
            println!("  POST /export   - Export results");
            println!("\n{}", "Press Ctrl+C to stop".yellow());
        }

        Commands::Wizard { name, list } => {
            let manager = wizards::WizardManager::new();

            if list {
                manager.list_wizards();
            } else if let Some(wizard_name) = &name {
                let names: Vec<String> = Vec::new();
                let _ = names;
                let lower = wizard_name.to_lowercase();
                let idx = match lower.as_str() {
                    "recovery" | "recover" | "0" => 0,
                    "device" | "scan" | "devices" | "1" => 1,
                    "encryption" | "encrypt" | "2" => 2,
                    _ => {
                        println!("{}", format!("Unknown wizard: {}", wizard_name).red());
                        println!("{}", "Available: recovery, device, encryption".yellow());
                        return Ok(());
                    }
                };
                manager.run_wizard(idx)?;
            } else {
                manager.run_interactive()?;
            }
        }
    }

    Ok(())
}

fn print_image_metadata(meta: &bytesurgeon_diskimage::ImageMetadata) {
    println!("  Format     : {}", meta.format);
    println!("  Size       : {} bytes", meta.size_bytes);
    println!("  Sectors    : {}", meta.total_sectors);
    println!("  Sector Size: {} bytes", meta.sector_size);
    if let Some(hash) = &meta.sha256 {
        println!("  SHA-256    : {}", hash);
    }
    if let Some(created) = &meta.created {
        println!("  Created    : {}", created);
    }
    if let Some(modified) = &meta.modified {
        println!("  Modified   : {}", modified);
    }
    if let Some(examiner) = &meta.examiner {
        println!("  Examiner   : {}", examiner);
    }
    if let Some(case) = &meta.case_number {
        println!("  Case #     : {}", case);
    }
    if let Some(ev) = &meta.evidence_number {
        println!("  Evidence # : {}", ev);
    }
    if let Some(desc) = &meta.description {
        println!("  Description: {}", desc);
    }
}
