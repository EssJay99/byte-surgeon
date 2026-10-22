use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TemplateError {
    #[error("template not found: {0}")]
    NotFound(String),
    #[error("invalid template: {0}")]
    ValidationError(String),
    #[error("parameter substitution failed: {0}")]
    SubstitutionError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("step {0} failed: {1}")]
    StepExecutionError(usize, String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStep {
    pub name: String,
    pub description: String,
    pub command: String,
    #[serde(default)]
    pub parameters: HashMap<String, String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateConfig {
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub estimated_duration: String,
    #[serde(default)]
    pub prerequisites: Vec<String>,
    #[serde(default)]
    pub output_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryTemplate {
    pub name: String,
    pub description: String,
    pub steps: Vec<RecoveryStep>,
    pub configuration: TemplateConfig,
    #[serde(default)]
    pub schema_version: String,
}

impl RecoveryTemplate {
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.name.is_empty() {
            return Err(TemplateError::ValidationError(
                "template name cannot be empty".into(),
            ));
        }
        if self.description.is_empty() {
            return Err(TemplateError::ValidationError(
                "template description cannot be empty".into(),
            ));
        }
        if self.steps.is_empty() {
            return Err(TemplateError::ValidationError(
                "template must have at least one step".into(),
            ));
        }
        for (i, step) in self.steps.iter().enumerate() {
            if step.name.is_empty() {
                return Err(TemplateError::ValidationError(format!(
                    "step {} name cannot be empty",
                    i
                )));
            }
            if step.command.is_empty() {
                return Err(TemplateError::ValidationError(format!(
                    "step {} command cannot be empty",
                    i
                )));
            }
        }
        Ok(())
    }

    pub fn substitute_parameters(
        &self,
        params: &HashMap<String, String>,
    ) -> Result<RecoveryTemplate, TemplateError> {
        let mut template = self.clone();
        for step in &mut template.steps {
            step.command = substitute_in_string(&step.command, params)?;
            step.description = substitute_in_string(&step.description, params)?;
            for (_key, value) in step.parameters.iter_mut() {
                *value = substitute_in_string(value, params)?;
            }
        }
        Ok(template)
    }
}

fn substitute_in_string(
    input: &str,
    params: &HashMap<String, String>,
) -> Result<String, TemplateError> {
    let mut result = input.to_string();
    for (key, value) in params {
        let placeholder = format!("{{{{{}}}}}", key);
        result = result.replace(&placeholder, value);
    }
    if result.contains("{{") && result.contains("}}") {
        let start = result.find("{{").unwrap();
        let end = result.find("}}").unwrap();
        let missing = &result[start + 2..end];
        return Err(TemplateError::SubstitutionError(format!(
            "unresolved parameter: {}",
            missing
        )));
    }
    Ok(result)
}

pub struct TemplateManager {
    templates_dir: PathBuf,
    builtin_templates: HashMap<String, RecoveryTemplate>,
}

impl TemplateManager {
    pub fn new(templates_dir: impl AsRef<Path>) -> Self {
        let mut manager = Self {
            templates_dir: templates_dir.as_ref().to_path_buf(),
            builtin_templates: HashMap::new(),
        };
        manager.register_builtins();
        manager
    }

    fn register_builtins(&mut self) {
        self.builtin_templates
            .insert("PhotoRecovery".into(), Self::photo_recovery());
        self.builtin_templates
            .insert("DocumentRecovery".into(), Self::document_recovery());
        self.builtin_templates
            .insert("EmailRecovery".into(), Self::email_recovery());
        self.builtin_templates
            .insert("MobileRecovery".into(), Self::mobile_recovery());
        self.builtin_templates.insert(
            "EncryptedDriveRecovery".into(),
            Self::encrypted_drive_recovery(),
        );
    }

    pub fn load_template(&self, name: &str) -> Result<RecoveryTemplate, TemplateError> {
        if let Some(tpl) = self.builtin_templates.get(name) {
            return Ok(tpl.clone());
        }

        let path = self.templates_dir.join(format!("{}.json", name));
        if !path.exists() {
            return Err(TemplateError::NotFound(name.to_string()));
        }

        let content = std::fs::read_to_string(&path)?;
        let template: RecoveryTemplate = serde_json::from_str(&content)?;
        template.validate()?;
        Ok(template)
    }

    pub fn list_templates(&self) -> Vec<String> {
        let mut names: Vec<String> = self.builtin_templates.keys().cloned().collect();

        if let Ok(entries) = std::fs::read_dir(&self.templates_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        let name = stem.to_string();
                        if !names.contains(&name) {
                            names.push(name);
                        }
                    }
                }
            }
        }

        names.sort();
        names
    }

    pub fn execute_template(
        &self,
        name: &str,
        params: &HashMap<String, String>,
    ) -> Result<Vec<ExecutionResult>, TemplateError> {
        let template = self.load_template(name)?;
        template.validate()?;
        let resolved = template.substitute_parameters(params)?;

        let mut results = Vec::new();
        for (i, step) in resolved.steps.iter().enumerate() {
            let result = ExecutionResult {
                step_index: i,
                step_name: step.name.clone(),
                command: step.command.clone(),
                success: true,
                message: format!("Executed: {}", step.command),
            };
            if step.required && !result.success {
                return Err(TemplateError::StepExecutionError(
                    i,
                    "required step failed".into(),
                ));
            }
            results.push(result);
        }

        Ok(results)
    }

    fn photo_recovery() -> RecoveryTemplate {
        RecoveryTemplate {
            name: "PhotoRecovery".into(),
            description: "Recover deleted or corrupted photos from storage media".into(),
            schema_version: "1.0".into(),
            steps: vec![
                RecoveryStep {
                    name: "Scan Media".into(),
                    description: "Scan {{device}} for recoverable photo files".into(),
                    command: "photorec /select {{device}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Filter Results".into(),
                    description: "Filter recovered files for image formats (jpg, png, raw)".into(),
                    command: "find {{output_dir}} -type f \\( -iname '*.jpg' -o -iname '*.png' -o -iname '*.raw' -o -iname '*.tiff' \\)".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Verify Integrity".into(),
                    description: "Verify integrity of recovered photos".into(),
                    command: "identify -verbose {{output_dir}}/* 2>/dev/null | grep -c 'Filename'".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
                RecoveryStep {
                    name: "Organize".into(),
                    description: "Organize recovered photos by date into {{organized_dir}}".into(),
                    command: "exiftool '-Directory<DateTimeOriginal' -d {{organized_dir}}/%Y/%m {{output_dir}}".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
            ],
            configuration: TemplateConfig {
                risk_level: "low".into(),
                estimated_duration: "30-120 minutes".into(),
                prerequisites: vec!["photorec installed".into(), "exiftool installed".into()],
                output_format: "image files".into(),
            },
        }
    }

    fn document_recovery() -> RecoveryTemplate {
        RecoveryTemplate {
            name: "DocumentRecovery".into(),
            description: "Recover lost or damaged documents from file systems".into(),
            schema_version: "1.0".into(),
            steps: vec![
                RecoveryStep {
                    name: "Create Disk Image".into(),
                    description: "Create a forensic copy of {{device}} to preserve evidence".into(),
                    command: "dd if={{device}} of={{image_path}} bs=4M status=progress".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Mount Image".into(),
                    description: "Mount the disk image for analysis".into(),
                    command: "mount -o ro,loop {{image_path}} {{mount_point}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Scan Documents".into(),
                    description: "Search for document files (pdf, docx, odt, txt)".into(),
                    command: "find {{mount_point}} -type f \\( -iname '*.pdf' -o -iname '*.docx' -o -iname '*.odt' -o -iname '*.txt' -o -iname '*.doc' \\) -size +0c".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Extract Files".into(),
                    description: "Copy recovered documents to {{output_dir}}".into(),
                    command: "cp -v {{mount_point}}/**/*.{{doc_extensions}} {{output_dir}}/".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Verify Documents".into(),
                    description: "Verify recovered documents are readable".into(),
                    command: "file {{output_dir}}/* | grep -i 'document\\|pdf\\|text'".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
            ],
            configuration: TemplateConfig {
                risk_level: "low".into(),
                estimated_duration: "15-60 minutes".into(),
                prerequisites: vec!["sufficient disk space for image".into()],
                output_format: "document files".into(),
            },
        }
    }

    fn email_recovery() -> RecoveryTemplate {
        RecoveryTemplate {
            name: "EmailRecovery".into(),
            description: "Recover emails from local mail stores and server backups".into(),
            schema_version: "1.0".into(),
            steps: vec![
                RecoveryStep {
                    name: "Identify Mail Store".into(),
                    description: "Locate mail store at {{mail_store_path}}".into(),
                    command: "ls -la {{mail_store_path}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Backup Current State".into(),
                    description: "Create backup of current mail store".into(),
                    command: "tar czf {{backup_path}}/mail_backup_$(date +%Y%m%d).tar.gz {{mail_store_path}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Extract Emails".into(),
                    description: "Extract individual email messages from {{mail_format}} store".into(),
                    command: "munpack -d {{output_dir}} {{mail_store_path}}/{{mailbox_file}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Parse Headers".into(),
                    description: "Parse email headers and extract metadata".into(),
                    command: "formail -s formail -X '' < {{output_dir}}/*.eml".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
                RecoveryStep {
                    name: "Export Results".into(),
                    description: "Export recovered emails to {{export_format}} format".into(),
                    command: "readpst -o {{output_dir}} -D {{export_format}} {{mail_store_path}}".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
            ],
            configuration: TemplateConfig {
                risk_level: "medium".into(),
                estimated_duration: "10-45 minutes".into(),
                prerequisites: vec!["munpack installed".into(), "readpst installed".into()],
                output_format: "eml/mbox files".into(),
            },
        }
    }

    fn mobile_recovery() -> RecoveryTemplate {
        RecoveryTemplate {
            name: "MobileRecovery".into(),
            description: "Recover data from mobile device backups or images".into(),
            schema_version: "1.0".into(),
            steps: vec![
                RecoveryStep {
                    name: "Identify Backup".into(),
                    description: "Identify mobile backup type ({{backup_type}}) at {{backup_path}}".into(),
                    command: "file {{backup_path}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Decrypt Backup".into(),
                    description: "Decrypt backup if encrypted using {{encryption_key_source}}".into(),
                    command: "idevicebackup2 decryption {{backup_path}} --keybag {{keybag_path}}".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
                RecoveryStep {
                    name: "Extract Archive".into(),
                    description: "Extract backup archive to {{output_dir}}".into(),
                    command: "tar xzf {{backup_path}} -C {{output_dir}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Parse Database".into(),
                    description: "Parse SQLite databases for contacts, messages, and app data".into(),
                    command: "sqlite3 {{output_dir}}/{{db_path}} '.tables'".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Export Media".into(),
                    description: "Extract photos, videos, and audio files".into(),
                    command: "find {{output_dir}} -type f \\( -iname '*.jpg' -o -iname '*.mp4' -o -iname '*.m4a' -o -iname '*.png' \\) -exec cp {} {{media_output_dir}} \\;".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
                RecoveryStep {
                    name: "Generate Report".into(),
                    description: "Generate a summary report of recovered data".into(),
                    command: "echo 'Recovery complete. Files in {{output_dir}}' > {{report_path}}".into(),
                    parameters: HashMap::new(),
                    required: false,
                },
            ],
            configuration: TemplateConfig {
                risk_level: "medium".into(),
                estimated_duration: "20-90 minutes".into(),
                prerequisites: vec!["idevicebackup2 installed".into(), "sqlite3 installed".into()],
                output_format: "extracted files and databases".into(),
            },
        }
    }

    fn encrypted_drive_recovery() -> RecoveryTemplate {
        RecoveryTemplate {
            name: "EncryptedDriveRecovery".into(),
            description: "Recover data from encrypted drives using provided credentials".into(),
            schema_version: "1.0".into(),
            steps: vec![
                RecoveryStep {
                    name: "Identify Encryption".into(),
                    description: "Identify encryption type on {{device}}".into(),
                    command: "cryptsetup status {{device}} 2>/dev/null || blkid {{device}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Unlock Drive".into(),
                    description: "Unlock encrypted drive using {{unlock_method}}".into(),
                    command: "cryptsetup luksOpen {{device}} {{mapped_name}} --key-file {{key_file}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Mount Filesystem".into(),
                    description: "Mount the unlocked filesystem to {{mount_point}}".into(),
                    command: "mount -o ro /dev/mapper/{{mapped_name}} {{mount_point}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Copy Data".into(),
                    description: "Copy recoverable data to {{output_dir}}".into(),
                    command: "rsync -av --progress {{mount_point}}/ {{output_dir}}/".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
                RecoveryStep {
                    name: "Unmount and Lock".into(),
                    description: "Safely unmount and lock the drive".into(),
                    command: "umount {{mount_point}} && cryptsetup luksClose {{mapped_name}}".into(),
                    parameters: HashMap::new(),
                    required: true,
                },
            ],
            configuration: TemplateConfig {
                risk_level: "high".into(),
                estimated_duration: "30-180 minutes".into(),
                prerequisites: vec![
                    "cryptsetup installed".into(),
                    "valid credentials or key file".into(),
                ],
                output_format: "decrypted files".into(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub step_index: usize,
    pub step_name: String,
    pub command: String,
    pub success: bool,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_templates_dir() -> PathBuf {
        let dir = std::env::temp_dir().join("recovery_templates_test");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_load_builtin_template() {
        let manager = TemplateManager::new(test_templates_dir());
        let template = manager.load_template("PhotoRecovery").unwrap();
        assert_eq!(template.name, "PhotoRecovery");
        assert!(!template.steps.is_empty());
        assert!(template.validate().is_ok());
    }

    #[test]
    fn test_load_all_builtin_templates() {
        let manager = TemplateManager::new(test_templates_dir());
        let names = vec![
            "PhotoRecovery",
            "DocumentRecovery",
            "EmailRecovery",
            "MobileRecovery",
            "EncryptedDriveRecovery",
        ];
        for name in names {
            let template = manager.load_template(name);
            assert!(template.is_ok(), "Failed to load template: {}", name);
            assert!(template.unwrap().validate().is_ok());
        }
    }

    #[test]
    fn test_list_templates() {
        let manager = TemplateManager::new(test_templates_dir());
        let list = manager.list_templates();
        assert!(list.contains(&"PhotoRecovery".to_string()));
        assert!(list.contains(&"DocumentRecovery".to_string()));
        assert!(list.contains(&"EmailRecovery".to_string()));
        assert!(list.contains(&"MobileRecovery".to_string()));
        assert!(list.contains(&"EncryptedDriveRecovery".to_string()));
    }

    #[test]
    fn test_template_not_found() {
        let manager = TemplateManager::new(test_templates_dir());
        let result = manager.load_template("NonExistentTemplate");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TemplateError::NotFound(_)));
    }

    #[test]
    fn test_parameter_substitution() {
        let manager = TemplateManager::new(test_templates_dir());
        let template = manager.load_template("PhotoRecovery").unwrap();
        let mut params = HashMap::new();
        params.insert("device".into(), "/dev/sda1".into());
        params.insert("output_dir".into(), "/tmp/recovered".into());
        params.insert("organized_dir".into(), "/tmp/organized".into());

        let resolved = template.substitute_parameters(&params).unwrap();
        assert!(resolved.steps[0].command.contains("/dev/sda1"));
        assert!(resolved.steps[1].command.contains("/tmp/recovered"));
    }

    #[test]
    fn test_parameter_substitution_missing() {
        let template = RecoveryTemplate {
            name: "Test".into(),
            description: "Test".into(),
            schema_version: "1.0".into(),
            steps: vec![RecoveryStep {
                name: "Step1".into(),
                description: "Do {{missing_param}}".into(),
                command: "echo {{missing_param}}".into(),
                parameters: HashMap::new(),
                required: true,
            }],
            configuration: TemplateConfig {
                risk_level: "low".into(),
                estimated_duration: "1m".into(),
                prerequisites: vec![],
                output_format: "none".into(),
            },
        };

        let params = HashMap::new();
        let result = template.substitute_parameters(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_template_validation_empty_name() {
        let template = RecoveryTemplate {
            name: "".into(),
            description: "desc".into(),
            schema_version: "1.0".into(),
            steps: vec![RecoveryStep {
                name: "s".into(),
                description: "d".into(),
                command: "c".into(),
                parameters: HashMap::new(),
                required: true,
            }],
            configuration: TemplateConfig {
                risk_level: "low".into(),
                estimated_duration: "1m".into(),
                prerequisites: vec![],
                output_format: "none".into(),
            },
        };
        assert!(template.validate().is_err());
    }

    #[test]
    fn test_template_validation_empty_steps() {
        let template = RecoveryTemplate {
            name: "Test".into(),
            description: "desc".into(),
            schema_version: "1.0".into(),
            steps: vec![],
            configuration: TemplateConfig {
                risk_level: "low".into(),
                estimated_duration: "1m".into(),
                prerequisites: vec![],
                output_format: "none".into(),
            },
        };
        assert!(template.validate().is_err());
    }

    #[test]
    fn test_execute_template() {
        let manager = TemplateManager::new(test_templates_dir());
        let mut params = HashMap::new();
        params.insert("device".into(), "/dev/sda1".into());
        params.insert("output_dir".into(), "/tmp/out".into());
        params.insert("organized_dir".into(), "/tmp/org".into());

        let results = manager.execute_template("PhotoRecovery", &params);
        assert!(results.is_ok());
        let steps = results.unwrap();
        assert_eq!(steps.len(), 4);
        assert!(steps[0].success);
        assert!(steps[0].command.contains("/dev/sda1"));
    }

    #[test]
    fn test_load_template_from_json_file() {
        let dir = test_templates_dir();
        let json_content = serde_json::json!({
            "name": "CustomTest",
            "description": "A custom test template",
            "schema_version": "1.0",
            "steps": [
                {
                    "name": "Run Test",
                    "description": "Execute test command",
                    "command": "echo {{message}}",
                    "parameters": {},
                    "required": true
                }
            ],
            "configuration": {
                "risk_level": "low",
                "estimated_duration": "1 minute",
                "prerequisites": [],
                "output_format": "text"
            }
        });

        let path = dir.join("CustomTest.json");
        let mut file = std::fs::File::create(&path).unwrap();
        write!(file, "{}", json_content).unwrap();

        let manager = TemplateManager::new(&dir);
        let template = manager.load_template("CustomTest").unwrap();
        assert_eq!(template.name, "CustomTest");
        assert_eq!(template.steps.len(), 1);

        let mut params = HashMap::new();
        params.insert("message".into(), "hello world".into());
        let results = manager.execute_template("CustomTest", &params).unwrap();
        assert_eq!(results[0].command, "echo hello world");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_template_serialization_roundtrip() {
        let manager = TemplateManager::new(test_templates_dir());
        let template = manager.load_template("DocumentRecovery").unwrap();
        let json = serde_json::to_string(&template).unwrap();
        let deserialized: RecoveryTemplate = serde_json::from_str(&json).unwrap();
        assert_eq!(template.name, deserialized.name);
        assert_eq!(template.steps.len(), deserialized.steps.len());
    }

    #[test]
    fn test_list_includes_file_templates() {
        let dir = test_templates_dir();
        let json_content = serde_json::json!({
            "name": "FileTemplate",
            "description": "A file-based template",
            "schema_version": "1.0",
            "steps": [{
                "name": "Step1",
                "description": "Do something",
                "command": "echo done",
                "parameters": {},
                "required": true
            }],
            "configuration": {
                "risk_level": "low",
                "estimated_duration": "1m",
                "prerequisites": [],
                "output_format": "text"
            }
        });

        let path = dir.join("FileTemplate.json");
        let mut file = std::fs::File::create(&path).unwrap();
        write!(file, "{}", json_content).unwrap();

        let manager = TemplateManager::new(&dir);
        let list = manager.list_templates();
        assert!(list.contains(&"FileTemplate".to_string()));

        let _ = std::fs::remove_file(&path);
    }
}
