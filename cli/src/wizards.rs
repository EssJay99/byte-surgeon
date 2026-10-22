use anyhow::Result;
use colored::*;
use dialoguer::{Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use datadoctor_encryption::EncryptedVolume;
use datadoctor_crypto::DecryptionEngine;

pub struct Step {
    pub prompt: String,
    pub default: Option<String>,
    pub options: Option<Vec<String>>,
    pub required: bool,
    pub validator: Option<Box<dyn Fn(&str) -> Result<(), String>>>,
}

impl Step {
    pub fn new(prompt: &str) -> Self {
        Self {
            prompt: prompt.to_string(),
            default: None,
            options: None,
            required: false,
            validator: None,
        }
    }

    pub fn with_default(mut self, default: &str) -> Self {
        self.default = Some(default.to_string());
        self
    }

    pub fn with_options(mut self, options: Vec<&str>) -> Self {
        self.options = Some(options.into_iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn with_validator<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<(), String> + 'static,
    {
        self.validator = Some(Box::new(f));
        self
    }
}

pub trait Wizard {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn steps(&self) -> Vec<Step>;
    fn execute(&self, answers: &HashMap<String, String>) -> Result<()>;
}

pub struct WizardManager {
    wizards: Vec<Box<dyn Wizard>>,
}

impl WizardManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            wizards: Vec::new(),
        };
        mgr.wizards.push(Box::new(RecoveryWizard));
        mgr.wizards.push(Box::new(DeviceScanWizard));
        mgr.wizards.push(Box::new(EncryptionWizard));
        mgr
    }

    pub fn list_wizards(&self) {
        println!("{}", "Available Wizards:".cyan().bold());
        println!();
        for (i, w) in self.wizards.iter().enumerate() {
            println!("  {}. {}", (i + 1).to_string().green(), w.name().bold());
            println!("     {}", w.description());
        }
        println!();
    }

    pub fn run_wizard(&self, index: usize) -> Result<()> {
        let wizard = self
            .wizards
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("Wizard index out of range"))?;

        println!();
        println!("{}", format!("Starting: {}", wizard.name()).cyan().bold());
        println!("{}", wizard.description().dimmed());
        println!("{}", "Press Ctrl+C at any time to cancel.".dimmed());
        println!();

        let steps = wizard.steps();
        let total = steps.len();
        let mut answers = HashMap::new();

        for (i, step) in steps.iter().enumerate() {
            let progress_bar = ProgressBar::new(total as u64);
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("[{bar:30}] {pos}/{len} {msg}")
                    .unwrap()
                    .progress_chars("=>-"),
            );
            progress_bar.set_position(i as u64);
            progress_bar.set_message(format!("Step {}/{}: {}", i + 1, total, step.prompt));

            println!(
                "\n{}",
                format!("Step {}/{}: {}", i + 1, total, step.prompt).yellow()
            );

            if let Some(opts) = &step.options {
                let selection = Select::new()
                    .with_prompt(&step.prompt)
                    .items(opts)
                    .default(0)
                    .interact()?;
                answers.insert(step.prompt.clone(), opts[selection].clone());
            } else {
                let mut builder = Input::<String>::new();
                builder = builder.with_prompt(&step.prompt);
                if let Some(def) = &step.default {
                    builder = builder.default(def.clone());
                }
                if !step.required {
                    builder = builder.allow_empty(true);
                }

                let value = builder.interact_text()?;

                if let Some(validator) = &step.validator {
                    if let Err(msg) = validator(&value) {
                        println!("{}", format!("  Validation warning: {}", msg).red());
                    }
                }

                answers.insert(step.prompt.clone(), value);
            }
        }

        println!();
        println!("{}", "Summary of your choices:".cyan().bold());
        for (key, val) in &answers {
            println!("  {} : {}", key, val.green());
        }
        println!();

        let confirm = Confirm::new()
            .with_prompt("Proceed with these settings?")
            .default(true)
            .interact()?;

        if confirm {
            println!();
            wizard.execute(&answers)?;
        } else {
            println!("{}", "Wizard cancelled.".yellow());
        }

        Ok(())
    }

    pub fn run_interactive(&self) -> Result<()> {
        self.list_wizards();

        let names: Vec<String> = self.wizards.iter().map(|w| w.name().to_string()).collect();

        let selection = Select::new()
            .with_prompt("Select a wizard")
            .items(&names)
            .default(0)
            .interact()?;

        self.run_wizard(selection)
    }
}

struct RecoveryWizard;

impl Wizard for RecoveryWizard {
    fn name(&self) -> &str {
        "Data Recovery Wizard"
    }

    fn description(&self) -> &str {
        "Step-by-step guided data recovery workflow"
    }

    fn steps(&self) -> Vec<Step> {
        vec![
            Step::new("Enter the device path or name to recover from")
                .required()
                .with_validator(|v| {
                    if v.is_empty() {
                        Err("Device path cannot be empty".to_string())
                    } else {
                        Ok(())
                    }
                }),
            Step::new("Select recovery mode")
                .with_options(vec!["quick", "deep", "signature", "filesystem", "raw"])
                .with_default("signature"),
            Step::new("Enter output directory for recovered files")
                .with_default("./recovered")
                .required(),
            Step::new("Enable write protection on source device?")
                .with_options(vec!["yes", "no"])
                .with_default("yes"),
            Step::new("Generate a recovery report after completion?")
                .with_options(vec!["yes", "no"])
                .with_default("yes"),
        ]
    }

    fn execute(&self, answers: &HashMap<String, String>) -> Result<()> {
        let steps_keys: Vec<String> = self.steps().iter().map(|s| s.prompt.clone()).collect();

        let device = answers.get(&steps_keys[0]).cloned().unwrap_or_default();
        let mode = answers.get(&steps_keys[1]).cloned().unwrap_or_else(|| "signature".to_string());
        let output = answers.get(&steps_keys[2]).cloned().unwrap_or_else(|| "./recovered".to_string());
        let write_protect = answers.get(&steps_keys[3]).cloned().unwrap_or_else(|| "yes".to_string());
        let report = answers.get(&steps_keys[4]).cloned().unwrap_or_else(|| "yes".to_string());

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        if write_protect == "yes" {
            pb.set_message("Enabling write protection...");
            let mut protector = datadoctor_core::WriteProtector::new();
            match protector.verify_device(&device) {
                Ok(status) => {
                    if !status.is_write_protected {
                        println!(
                            "{}",
                            "  Warning: Device is NOT write-protected".yellow()
                        );
                    } else {
                        println!("{}", "  Write protection verified".green());
                    }
                }
                Err(e) => {
                    println!("{}: {}", "  Write protect check failed".yellow(), e);
                }
            }
        }

        pb.set_message("Initializing recovery engine...");
        let data_dir = PathBuf::from("./datadoctor_data");
        let engine = datadoctor_core::RecoveryEngine::new(&data_dir)?;
        let devices = engine.get_all_devices()?;

        let target = devices
            .iter()
            .find(|d| d.path == device || d.name == device);

        match target {
            Some(device_info) => {
                let scan_type = match mode.as_str() {
                    "quick" => datadoctor_core::ScanType::Quick,
                    "deep" => datadoctor_core::ScanType::Deep,
                    "signature" => datadoctor_core::ScanType::Signature,
                    "filesystem" => datadoctor_core::ScanType::FileSystem,
                    "raw" => datadoctor_core::ScanType::Raw,
                    _ => datadoctor_core::ScanType::Signature,
                };

                pb.set_message("Running recovery scan...");
                let output_path = PathBuf::from(&output);
                let session_id = engine.start_recovery(device_info, scan_type, &output_path)?;

                pb.finish_with_message("Recovery complete".to_string());
                println!("{}", format!("  Session ID: {}", session_id).green());

                if report == "yes" {
                    println!("{}", "  Generating report...".cyan());
                    let session_data = engine.get_session(&session_id)?;
                    let files = engine.get_recovered_files(&session_id)?;
                    if let Some(sess) = session_data {
                        let generator = datadoctor_core::ReportGenerator::new();
                        let data = generator.generate_report_data(&sess, &files);
                        let report_path = output_path.join("report.txt");
                        let _ = generator.generate_text(&data, &report_path);
                        println!(
                            "{}",
                            format!("  Report: {}", report_path.display()).green()
                        );
                    }
                }
            }
            None => {
                pb.finish_with_message("Device not found".to_string());
                println!("{}", format!("  Device not found: {}", device).red());
            }
        }

        Ok(())
    }
}

struct DeviceScanWizard;

impl Wizard for DeviceScanWizard {
    fn name(&self) -> &str {
        "Device Scan Wizard"
    }

    fn description(&self) -> &str {
        "Detect and analyze connected storage devices"
    }

    fn steps(&self) -> Vec<Step> {
        vec![
            Step::new("Scan type")
                .with_options(vec!["all devices", "removable only", "network devices"])
                .with_default("all devices"),
            Step::new("Show detailed device information?")
                .with_options(vec!["yes", "no"])
                .with_default("yes"),
            Step::new("Check for encryption on detected devices?")
                .with_options(vec!["yes", "no"])
                .with_default("no"),
            Step::new("Check write protection status?")
                .with_options(vec!["yes", "no"])
                .with_default("yes"),
            Step::new("Output format")
                .with_options(vec!["table", "json"])
                .with_default("table"),
        ]
    }

    fn execute(&self, answers: &HashMap<String, String>) -> Result<()> {
        let steps_keys: Vec<String> = self.steps().iter().map(|s| s.prompt.clone()).collect();

        let _scan_type = answers.get(&steps_keys[0]).cloned().unwrap_or_else(|| "all devices".to_string());
        let detailed = answers.get(&steps_keys[1]).cloned().unwrap_or_else(|| "yes".to_string());
        let check_encryption = answers.get(&steps_keys[2]).cloned().unwrap_or_else(|| "no".to_string());
        let check_wp = answers.get(&steps_keys[3]).cloned().unwrap_or_else(|| "yes".to_string());
        let format = answers.get(&steps_keys[4]).cloned().unwrap_or_else(|| "table".to_string());

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        pb.set_message("Detecting devices...");
        let detector = datadoctor_devices::DeviceDetector::new();
        let devices = detector.detect_all_devices()?;

        pb.finish_with_message(format!("Found {} devices", devices.len()));

        if devices.is_empty() {
            println!("{}", "  No devices found".yellow());
            return Ok(());
        }

        println!();

        if format == "json" {
            let json = serde_json::to_string_pretty(&devices)?;
            println!("{}", json);
        } else {
            println!("{}", "Detected Devices:".cyan().bold());
            println!();
            for (i, device) in devices.iter().enumerate() {
                println!(
                    "  {}. {} - {}",
                    (i + 1).to_string().green(),
                    device.name.bold(),
                    device.path.dimmed()
                );
                println!("     Type: {:?}", device.device_type);

                if detailed == "yes" {
                    println!("     File System: {:?}", device.file_system);
                    println!("     Total Size : {} bytes", device.total_size);
                    println!("     Free Space : {} bytes", device.free_space);
                    if let Some(vendor) = &device.vendor {
                        println!("     Vendor     : {}", vendor);
                    }
                    if let Some(model) = &device.model {
                        println!("     Model      : {}", model);
                    }
                    if let Some(mount) = &device.mount_point {
                        println!("     Mount Point: {}", mount);
                    }
                }

                if check_encryption == "yes" {
                    let mut enc_detected = false;
                    if datadoctor_encryption::bitlocker::BitLockerVolume::detect(&device.path)
                        .unwrap_or(false)
                    {
                        println!("     Encryption : {} (BitLocker)", "YES".red());
                        enc_detected = true;
                    }
                    if datadoctor_encryption::filevault::FileVaultVolume::detect(&device.path)
                        .unwrap_or(false)
                    {
                        println!("     Encryption : {} (FileVault)", "YES".red());
                        enc_detected = true;
                    }
                    if datadoctor_encryption::luks::LuksVolume::detect(&device.path)
                        .unwrap_or(false)
                    {
                        println!("     Encryption : {} (LUKS)", "YES".red());
                        enc_detected = true;
                    }
                    if datadoctor_encryption::veracrypt::VeraCryptVolume::detect(&device.path)
                        .unwrap_or(false)
                    {
                        println!("     Encryption : {} (VeraCrypt)", "YES".red());
                        enc_detected = true;
                    }
                    if !enc_detected {
                        println!("     Encryption : {}", "None detected".green());
                    }
                }

                if check_wp == "yes" {
                    let mut protector = datadoctor_core::WriteProtector::new();
                    match protector.verify_device(&device.path) {
                        Ok(status) => {
                            let wp = if status.is_write_protected {
                                "YES".green()
                            } else {
                                "NO".red()
                            };
                            println!("     Write Prot : {}", wp);
                        }
                        Err(_) => {
                            println!("     Write Prot : {}", "unknown".yellow());
                        }
                    }
                }

                println!();
            }
        }

        Ok(())
    }
}

struct EncryptionWizard;

impl Wizard for EncryptionWizard {
    fn name(&self) -> &str {
        "Encryption Analysis Wizard"
    }

    fn description(&self) -> &str {
        "Detect, analyze, and decrypt encrypted volumes"
    }

    fn steps(&self) -> Vec<Step> {
        vec![
            Step::new("Enter device or image path to analyze")
                .required()
                .with_validator(|v| {
                    if v.is_empty() {
                        Err("Path cannot be empty".to_string())
                    } else {
                        Ok(())
                    }
                }),
            Step::new("Select encryption types to check")
                .with_options(vec![
                    "all (BitLocker, FileVault, LUKS, VeraCrypt)",
                    "BitLocker only",
                    "FileVault only",
                    "LUKS only",
                    "VeraCrypt only",
                ])
                .with_default("all (BitLocker, FileVault, LUKS, VeraCrypt)"),
            Step::new("Attempt decryption if encryption is found?")
                .with_options(vec!["yes", "no"])
                .with_default("no"),
            Step::new("Output path for decrypted data (if applicable)")
                .with_default("./decrypted_output"),
            Step::new("Generate encryption analysis report?")
                .with_options(vec!["yes", "no"])
                .with_default("yes"),
        ]
    }

    fn execute(&self, answers: &HashMap<String, String>) -> Result<()> {
        let steps_keys: Vec<String> = self.steps().iter().map(|s| s.prompt.clone()).collect();

        let device = answers.get(&steps_keys[0]).cloned().unwrap_or_default();
        let enc_types = answers
            .get(&steps_keys[1])
            .cloned()
            .unwrap_or_else(|| "all (BitLocker, FileVault, LUKS, VeraCrypt)".to_string());
        let attempt_decrypt = answers
            .get(&steps_keys[2])
            .cloned()
            .unwrap_or_else(|| "no".to_string());
        let output = answers
            .get(&steps_keys[3])
            .cloned()
            .unwrap_or_else(|| "./decrypted_output".to_string());
        let gen_report = answers
            .get(&steps_keys[4])
            .cloned()
            .unwrap_or_else(|| "yes".to_string());

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        pb.set_message("Analyzing encryption...");

        let check_all = enc_types.starts_with("all");
        let mut detected: Vec<(String, datadoctor_encryption::VolumeType)> = Vec::new();

        if check_all || enc_types.contains("BitLocker") {
            pb.set_message("Checking BitLocker...");
            if datadoctor_encryption::bitlocker::BitLockerVolume::detect(&device).unwrap_or(false) {
                detected.push(("BitLocker".to_string(), datadoctor_encryption::VolumeType::BitLocker));
            }
        }

        if check_all || enc_types.contains("FileVault") {
            pb.set_message("Checking FileVault...");
            if datadoctor_encryption::filevault::FileVaultVolume::detect(&device).unwrap_or(false) {
                detected.push(("FileVault".to_string(), datadoctor_encryption::VolumeType::FileVault));
            }
        }

        if check_all || enc_types.contains("LUKS") {
            pb.set_message("Checking LUKS...");
            if datadoctor_encryption::luks::LuksVolume::detect(&device).unwrap_or(false) {
                detected.push(("LUKS".to_string(), datadoctor_encryption::VolumeType::LUKS));
            }
        }

        if check_all || enc_types.contains("VeraCrypt") {
            pb.set_message("Checking VeraCrypt...");
            if datadoctor_encryption::veracrypt::VeraCryptVolume::detect(&device).unwrap_or(false) {
                detected.push(("VeraCrypt".to_string(), datadoctor_encryption::VolumeType::VeraCrypt));
            }
        }

        pb.finish_with_message("Analysis complete");

        println!();
        if detected.is_empty() {
            println!("{}", "  No encryption detected on this device.".green());
        } else {
            println!("{}", "  Encryption Detected:".red().bold());
            for (name, vol_type) in &detected {
                println!("    - {} ({})", name.red(), vol_type);
            }

            if attempt_decrypt == "yes" {
                println!();
                let password: String = Input::new()
                    .with_prompt("Enter decryption password")
                    .interact_text()?;

                let output_path = PathBuf::from(&output);
                std::fs::create_dir_all(&output_path)?;

                let decryptor = datadoctor_crypto::decryptor::FileDecryptor::new();
                let input_path = PathBuf::from(&device);
                let decrypted_file = output_path.join("decrypted_data");

                match decryptor.decrypt_file(&input_path, &decrypted_file, &password) {
                    Ok(_) => {
                        println!(
                            "{}",
                            format!("  Decrypted data written to {}", decrypted_file.display())
                                .green()
                        );
                    }
                    Err(e) => {
                        println!("{}", format!("  Decryption failed: {}", e).red());
                    }
                }
            }
        }

        if gen_report == "yes" {
            println!();
            println!("{}", "  Encryption Analysis Report:".cyan().bold());
            println!("    Device     : {}", device);
            println!("    Types Check: {}", enc_types);
            println!(
                "    Found      : {} encryption type(s)",
                detected.len()
            );
            for (name, _) in &detected {
                println!("      - {}", name);
            }
            if detected.is_empty() {
                println!("      (none)");
            }
        }

        Ok(())
    }
}
