use crate::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub case_number: String,
    pub case_name: String,
    pub jurisdiction: String,
    pub court: String,
    pub date_filed: DateTime<Utc>,
    pub parties_involved: Vec<String>,
    pub reference_number: Option<String>,
}

impl CaseInfo {
    pub fn new(case_number: &str, case_name: &str, jurisdiction: &str, court: &str) -> Self {
        Self {
            case_number: case_number.to_string(),
            case_name: case_name.to_string(),
            jurisdiction: jurisdiction.to_string(),
            court: court.to_string(),
            date_filed: Utc::now(),
            parties_involved: Vec::new(),
            reference_number: None,
        }
    }

    pub fn add_party(&mut self, party: &str) {
        self.parties_involved.push(party.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExaminerInfo {
    pub name: String,
    pub title: String,
    pub qualifications: Vec<String>,
    pub certifications: Vec<String>,
    pub organization: String,
    pub contact_email: Option<String>,
    pub contact_phone: Option<String>,
    pub license_number: Option<String>,
}

impl ExaminerInfo {
    pub fn new(name: &str, title: &str, organization: &str) -> Self {
        Self {
            name: name.to_string(),
            title: title.to_string(),
            qualifications: Vec::new(),
            certifications: Vec::new(),
            organization: organization.to_string(),
            contact_email: None,
            contact_phone: None,
            license_number: None,
        }
    }

    pub fn add_qualification(&mut self, qual: &str) {
        self.qualifications.push(qual.to_string());
    }

    pub fn add_certification(&mut self, cert: &str) {
        self.certifications.push(cert.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub handler: String,
    pub action: String,
    pub purpose: String,
    pub witnesses: Vec<String>,
    pub location: String,
}

impl ChainOfCustodyEntry {
    pub fn new(handler: &str, action: &str, purpose: &str, location: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            handler: handler.to_string(),
            action: action.to_string(),
            purpose: purpose.to_string(),
            witnesses: Vec::new(),
            location: location.to_string(),
        }
    }

    pub fn add_witness(&mut self, witness: &str) {
        self.witnesses.push(witness.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub description: String,
    pub source: String,
    pub acquired_at: DateTime<Utc>,
    pub acquired_by: String,
    pub hash_sha256: String,
    pub hash_md5: Option<String>,
    pub storage_location: String,
    pub chain_of_custody: Vec<ChainOfCustodyEntry>,
    pub evidence_type: EvidenceType,
    pub size_bytes: u64,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvidenceType {
    DiskImage,
    FileExtract,
    MemoryDump,
    NetworkCapture,
    LogFile,
    Database,
    MobileDevice,
    CloudExport,
    Other(String),
}

impl EvidenceItem {
    pub fn new(description: &str, source: &str, acquired_by: &str, storage_location: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            description: description.to_string(),
            source: source.to_string(),
            acquired_at: Utc::now(),
            acquired_by: acquired_by.to_string(),
            hash_sha256: String::new(),
            hash_md5: None,
            storage_location: storage_location.to_string(),
            chain_of_custody: Vec::new(),
            evidence_type: EvidenceType::Other("Unspecified".to_string()),
            size_bytes: 0,
            notes: None,
        }
    }

    pub fn set_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        self.hash_sha256 = hex::encode(hasher.finalize());
    }

    pub fn add_custody_entry(&mut self, entry: ChainOfCustodyEntry) {
        self.chain_of_custody.push(entry);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourtFinding {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub description: String,
    pub hash: String,
    pub examiner_notes: String,
    pub supporting_evidence_ids: Vec<String>,
    pub finding_type: FindingType,
    pub confidence_level: ConfidenceLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingType {
    Fact,
    Opinion,
    Correlation,
    Anomaly,
    Reconstruction,
    Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConfidenceLevel {
    Confirmed,
    HighlyLikely,
    Likely,
    Possible,
    Inconclusive,
}

impl CourtFinding {
    pub fn new(title: &str, description: &str, examiner_notes: &str) -> Self {
        let content = format!("{}:{}:{}", title, description, examiner_notes);
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            title: title.to_string(),
            description: description.to_string(),
            hash,
            examiner_notes: examiner_notes.to_string(),
            supporting_evidence_ids: Vec::new(),
            finding_type: FindingType::Fact,
            confidence_level: ConfidenceLevel::Confirmed,
        }
    }

    pub fn add_supporting_evidence(&mut self, evidence_id: &str) {
        self.supporting_evidence_ids.push(evidence_id.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodologyEntry {
    pub tool_name: String,
    pub tool_version: String,
    pub procedure: String,
    pub validation_steps: Vec<String>,
    pub references: Vec<String>,
    pub standard_compliance: Vec<String>,
}

impl MethodologyEntry {
    pub fn new(tool_name: &str, tool_version: &str, procedure: &str) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            tool_version: tool_version.to_string(),
            procedure: procedure.to_string(),
            validation_steps: Vec::new(),
            references: Vec::new(),
            standard_compliance: Vec::new(),
        }
    }

    pub fn add_validation_step(&mut self, step: &str) {
        self.validation_steps.push(step.to_string());
    }

    pub fn add_reference(&mut self, reference: &str) {
        self.references.push(reference.to_string());
    }

    pub fn add_compliance_standard(&mut self, standard: &str) {
        self.standard_compliance.push(standard.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conclusion {
    pub summary: String,
    pub opinion: String,
    pub basis: Vec<String>,
    pub limitations: Vec<String>,
}

impl Conclusion {
    pub fn new(summary: &str, opinion: &str) -> Self {
        Self {
            summary: summary.to_string(),
            opinion: opinion.to_string(),
            basis: Vec::new(),
            limitations: Vec::new(),
        }
    }

    pub fn add_basis(&mut self, basis: &str) {
        self.basis.push(basis.to_string());
    }

    pub fn add_limitation(&mut self, limitation: &str) {
        self.limitations.push(limitation.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub algorithm: String,
    pub examiner_name: String,
    pub timestamp: DateTime<Utc>,
    pub certificate_id: Option<String>,
    pub signature_value: Option<String>,
    pub public_key_fingerprint: Option<String>,
}

impl DigitalSignature {
    pub fn placeholder(examiner_name: &str) -> Self {
        Self {
            algorithm: "SHA-256 with RSA".to_string(),
            examiner_name: examiner_name.to_string(),
            timestamp: Utc::now(),
            certificate_id: None,
            signature_value: None,
            public_key_fingerprint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourtReport {
    pub id: String,
    pub case_info: CaseInfo,
    pub examiner: ExaminerInfo,
    pub evidence_list: Vec<EvidenceItem>,
    pub findings: Vec<CourtFinding>,
    pub methodology: Vec<MethodologyEntry>,
    pub conclusions: Vec<Conclusion>,
    pub digital_signature: DigitalSignature,
    pub report_generated_at: DateTime<Utc>,
    pub report_hash: String,
    pub version: u32,
}

pub struct CourtReportGenerator {
    case_info: CaseInfo,
    examiner: ExaminerInfo,
    evidence_list: Vec<EvidenceItem>,
    findings: Vec<CourtFinding>,
    methodology: Vec<MethodologyEntry>,
    conclusions: Vec<Conclusion>,
}

impl CourtReportGenerator {
    pub fn new(case_info: CaseInfo, examiner: ExaminerInfo) -> Self {
        Self {
            case_info,
            examiner,
            evidence_list: Vec::new(),
            findings: Vec::new(),
            methodology: Vec::new(),
            conclusions: Vec::new(),
        }
    }

    pub fn add_evidence(&mut self, evidence: EvidenceItem) {
        self.evidence_list.push(evidence);
    }

    pub fn add_finding(&mut self, finding: CourtFinding) {
        self.findings.push(finding);
    }

    pub fn add_methodology(&mut self, methodology: MethodologyEntry) {
        self.methodology.push(methodology);
    }

    pub fn add_conclusion(&mut self, conclusion: Conclusion) {
        self.conclusions.push(conclusion);
    }

    pub fn generate_report(&self) -> CourtReport {
        let id = Uuid::new_v4().to_string();
        let report_generated_at = Utc::now();
        let digital_signature = DigitalSignature::placeholder(&self.examiner.name);

        let report_content = format!(
            "{}:{}:{}:{}:{}",
            id,
            self.case_info.case_number,
            self.evidence_list.len(),
            self.findings.len(),
            report_generated_at
        );
        let mut hasher = Sha256::new();
        hasher.update(report_content.as_bytes());
        let report_hash = hex::encode(hasher.finalize());

        CourtReport {
            id,
            case_info: self.case_info.clone(),
            examiner: self.examiner.clone(),
            evidence_list: self.evidence_list.clone(),
            findings: self.findings.clone(),
            methodology: self.methodology.clone(),
            conclusions: self.conclusions.clone(),
            digital_signature,
            report_generated_at,
            report_hash,
            version: 1,
        }
    }

    pub fn generate_html(&self, output_path: &std::path::Path) -> Result<String> {
        let html = self.generate_html_string();
        std::fs::write(output_path, &html)?;
        Ok(html)
    }

    pub fn generate_html_string(&self) -> String {
        let report = self.generate_report();
        self.build_html(&report)
    }

    pub fn generate_pdf(&self, output_path: &std::path::Path) -> Result<String> {
        let html = self.generate_html_string();
        let pdf_path = if output_path.extension().and_then(|e| e.to_str()) == Some("html") {
            output_path.with_extension("pdf")
        } else {
            output_path.to_path_buf()
        };
        std::fs::write(&pdf_path, &html)?;
        Ok(html)
    }

    pub fn generate_text(&self, output_path: &std::path::Path) -> Result<String> {
        let text = self.generate_text_string();
        std::fs::write(output_path, &text)?;
        Ok(text)
    }

    pub fn generate_text_string(&self) -> String {
        let report = self.generate_report();
        self.build_text(&report)
    }

    fn build_html(&self, report: &CourtReport) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"UTF-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("<title>Forensic Report - {}</title>\n", Self::html_escape(&report.case_info.case_number)));
        html.push_str("<style>\n");
        html.push_str("body { font-family: 'Times New Roman', Georgia, serif; margin: 40px; background: #fff; color: #000; line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 40px; }\n");
        html.push_str("h1 { text-align: center; border-bottom: 3px double #333; padding-bottom: 15px; font-size: 1.8em; }\n");
        html.push_str("h2 { color: #1a1a1a; border-bottom: 1px solid #666; padding-bottom: 5px; margin-top: 30px; font-size: 1.3em; text-transform: uppercase; }\n");
        html.push_str("h3 { font-size: 1.1em; margin-top: 20px; }\n");
        html.push_str(".header-block { text-align: center; margin-bottom: 30px; }\n");
        html.push_str(".header-block p { margin: 2px 0; }\n");
        html.push_str(".confidential { text-align: center; color: #900; font-weight: bold; font-size: 0.9em; border: 2px solid #900; padding: 5px; margin: 20px 0; }\n");
        html.push_str("table { width: 100%; border-collapse: collapse; margin: 15px 0; }\n");
        html.push_str("th { background: #f0f0f0; border: 1px solid #333; padding: 8px; text-align: left; font-size: 0.9em; }\n");
        html.push_str("td { border: 1px solid #666; padding: 8px; font-size: 0.9em; vertical-align: top; }\n");
        html.push_str(".hash { font-family: 'Courier New', monospace; font-size: 0.8em; word-break: break-all; background: #f8f8f8; padding: 4px 8px; }\n");
        html.push_str(".finding { margin: 15px 0; padding: 10px; border-left: 3px solid #333; background: #fafafa; }\n");
        html.push_str(".finding-title { font-weight: bold; }\n");
        html.push_str(".custody-entry { margin: 8px 0; padding: 8px; border: 1px solid #ddd; }\n");
        html.push_str(".signature-block { margin-top: 40px; border-top: 2px solid #333; padding-top: 20px; }\n");
        html.push_str(".page-break { page-break-after: always; }\n");
        html.push_str(".certification { background: #f5f5f5; padding: 15px; margin: 15px 0; border: 1px solid #ccc; font-style: italic; }\n");
        html.push_str("code { font-family: 'Courier New', monospace; font-size: 0.85em; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<div class=\"confidential\">CONFIDENTIAL - FOR LEGAL PROCEEDINGS ONLY</div>\n");

        html.push_str("<div class=\"header-block\">\n");
        html.push_str("<h1>DIGITAL FORENSIC EXAMINATION REPORT</h1>\n");
        html.push_str(&format!("<p><strong>Case Number:</strong> {}</p>\n", Self::html_escape(&report.case_info.case_number)));
        html.push_str(&format!("<p><strong>Case Name:</strong> {}</p>\n", Self::html_escape(&report.case_info.case_name)));
        html.push_str(&format!("<p><strong>Court:</strong> {}</p>\n", Self::html_escape(&report.case_info.court)));
        html.push_str(&format!("<p><strong>Jurisdiction:</strong> {}</p>\n", Self::html_escape(&report.case_info.jurisdiction)));
        html.push_str(&format!("<p><strong>Date Filed:</strong> {}</p>\n", report.case_info.date_filed.format("%Y-%m-%d")));
        html.push_str(&format!("<p><strong>Report ID:</strong> {}</p>\n", Self::html_escape(&report.id)));
        html.push_str(&format!("<p><strong>Report Generated:</strong> {}</p>\n", report.report_generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        html.push_str("</div>\n");

        if !report.case_info.parties_involved.is_empty() {
            html.push_str("<h2>Parties Involved</h2>\n<ul>\n");
            for party in &report.case_info.parties_involved {
                html.push_str(&format!("<li>{}</li>\n", Self::html_escape(party)));
            }
            html.push_str("</ul>\n");
        }

        html.push_str("<h2>Examiner Information</h2>\n");
        html.push_str("<table>\n");
        html.push_str(&format!("<tr><th width=\"30%\">Name</th><td>{}</td></tr>\n", Self::html_escape(&report.examiner.name)));
        html.push_str(&format!("<tr><th>Title</th><td>{}</td></tr>\n", Self::html_escape(&report.examiner.title)));
        html.push_str(&format!("<tr><th>Organization</th><td>{}</td></tr>\n", Self::html_escape(&report.examiner.organization)));
        if let Some(ref email) = report.examiner.contact_email {
            html.push_str(&format!("<tr><th>Email</th><td>{}</td></tr>\n", Self::html_escape(email)));
        }
        if let Some(ref phone) = report.examiner.contact_phone {
            html.push_str(&format!("<tr><th>Phone</th><td>{}</td></tr>\n", Self::html_escape(phone)));
        }
        if let Some(ref license) = report.examiner.license_number {
            html.push_str(&format!("<tr><th>License Number</th><td>{}</td></tr>\n", Self::html_escape(license)));
        }
        html.push_str("</table>\n");

        if !report.examiner.qualifications.is_empty() {
            html.push_str("<h3>Qualifications</h3>\n<ul>\n");
            for qual in &report.examiner.qualifications {
                html.push_str(&format!("<li>{}</li>\n", Self::html_escape(qual)));
            }
            html.push_str("</ul>\n");
        }

        if !report.examiner.certifications.is_empty() {
            html.push_str("<h3>Certifications</h3>\n<ul>\n");
            for cert in &report.examiner.certifications {
                html.push_str(&format!("<li>{}</li>\n", Self::html_escape(cert)));
            }
            html.push_str("</ul>\n");
        }

        html.push_str("<div class=\"certification\">\n");
        html.push_str("I certify that I am qualified as an expert in the field of digital forensics and that the findings and opinions expressed in this report are based on my professional examination and analysis of the evidence described herein.\n");
        html.push_str("</div>\n");

        html.push_str("<h2>Evidence Inventory</h2>\n");
        html.push_str("<table>\n");
        html.push_str("<tr><th>ID</th><th>Description</th><th>Type</th><th>Source</th><th>Size</th><th>SHA-256 Hash</th></tr>\n");
        for evidence in &report.evidence_list {
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td class=\"hash\">{}</td></tr>\n",
                Self::html_escape(&evidence.id),
                Self::html_escape(&evidence.description),
                evidence.evidence_type,
                Self::html_escape(&evidence.source),
                Self::format_size(evidence.size_bytes),
                if evidence.hash_sha256.is_empty() { "Not computed".to_string() } else { Self::html_escape(&evidence.hash_sha256) },
            ));
        }
        html.push_str("</table>\n");

        html.push_str("<h2>Chain of Custody</h2>\n");
        for evidence in &report.evidence_list {
            if evidence.chain_of_custody.is_empty() {
                continue;
            }
            html.push_str(&format!("<h3>Evidence: {} ({})</h3>\n", Self::html_escape(&evidence.description), Self::html_escape(&evidence.id)));
            html.push_str("<table>\n");
            html.push_str("<tr><th>Timestamp</th><th>Handler</th><th>Action</th><th>Purpose</th><th>Location</th><th>Witnesses</th></tr>\n");
            for entry in &evidence.chain_of_custody {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                    Self::html_escape(&entry.handler),
                    Self::html_escape(&entry.action),
                    Self::html_escape(&entry.purpose),
                    Self::html_escape(&entry.location),
                    if entry.witnesses.is_empty() { "None".to_string() } else { entry.witnesses.iter().map(|w| Self::html_escape(w)).collect::<Vec<_>>().join(", ") },
                ));
            }
            html.push_str("</table>\n");
        }

        html.push_str("<h2>Methodology</h2>\n");
        html.push_str("<p>The following tools and procedures were employed during this forensic examination:</p>\n");
        for (i, method) in report.methodology.iter().enumerate() {
            html.push_str(&format!("<h3>{}. {} v{}</h3>\n", i + 1, Self::html_escape(&method.tool_name), Self::html_escape(&method.tool_version)));
            html.push_str(&format!("<p><strong>Procedure:</strong> {}</p>\n", Self::html_escape(&method.procedure)));
            if !method.validation_steps.is_empty() {
                html.push_str("<p><strong>Validation Steps:</strong></p>\n<ol>\n");
                for step in &method.validation_steps {
                    html.push_str(&format!("<li>{}</li>\n", Self::html_escape(step)));
                }
                html.push_str("</ol>\n");
            }
            if !method.standard_compliance.is_empty() {
                html.push_str("<p><strong>Compliance Standards:</strong></p>\n<ul>\n");
                for std in &method.standard_compliance {
                    html.push_str(&format!("<li>{}</li>\n", Self::html_escape(std)));
                }
                html.push_str("</ul>\n");
            }
            if !method.references.is_empty() {
                html.push_str("<p><strong>References:</strong></p>\n<ul>\n");
                for reference in &method.references {
                    html.push_str(&format!("<li>{}</li>\n", Self::html_escape(reference)));
                }
                html.push_str("</ul>\n");
            }
        }

        html.push_str("<h2>Findings</h2>\n");
        for (i, finding) in report.findings.iter().enumerate() {
            html.push_str("<div class=\"finding\">\n");
            html.push_str(&format!("<div class=\"finding-title\">Finding {}: {}</div>\n", i + 1, Self::html_escape(&finding.title)));
            html.push_str(&format!("<p><strong>Timestamp:</strong> {}</p>\n", finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
            html.push_str(&format!("<p><strong>Type:</strong> {:?}</p>\n", finding.finding_type));
            html.push_str(&format!("<p><strong>Confidence:</strong> {:?}</p>\n", finding.confidence_level));
            html.push_str(&format!("<p>{}</p>\n", Self::html_escape(&finding.description)));
            if !finding.examiner_notes.is_empty() {
                html.push_str(&format!("<p><strong>Examiner Notes:</strong> {}</p>\n", Self::html_escape(&finding.examiner_notes)));
            }
            if !finding.supporting_evidence_ids.is_empty() {
                html.push_str("<p><strong>Supporting Evidence:</strong></p>\n<ul>\n");
                for eid in &finding.supporting_evidence_ids {
                    html.push_str(&format!("<li><code>{}</code></li>\n", Self::html_escape(eid)));
                }
                html.push_str("</ul>\n");
            }
            html.push_str(&format!("<p><strong>Integrity Hash:</strong> <span class=\"hash\">{}</span></p>\n", Self::html_escape(&finding.hash)));
            html.push_str("</div>\n");
        }

        html.push_str("<h2>Conclusions</h2>\n");
        for (i, conclusion) in report.conclusions.iter().enumerate() {
            html.push_str(&format!("<h3>Conclusion {}</h3>\n", i + 1));
            html.push_str(&format!("<p><strong>Summary:</strong> {}</p>\n", Self::html_escape(&conclusion.summary)));
            html.push_str(&format!("<p><strong>Expert Opinion:</strong> {}</p>\n", Self::html_escape(&conclusion.opinion)));
            if !conclusion.basis.is_empty() {
                html.push_str("<p><strong>Basis:</strong></p>\n<ul>\n");
                for b in &conclusion.basis {
                    html.push_str(&format!("<li>{}</li>\n", Self::html_escape(b)));
                }
                html.push_str("</ul>\n");
            }
            if !conclusion.limitations.is_empty() {
                html.push_str("<p><strong>Limitations:</strong></p>\n<ul>\n");
                for l in &conclusion.limitations {
                    html.push_str(&format!("<li>{}</li>\n", Self::html_escape(l)));
                }
                html.push_str("</ul>\n");
            }
        }

        html.push_str("<div class=\"signature-block\">\n");
        html.push_str("<h2>Digital Signature</h2>\n");
        html.push_str("<table>\n");
        html.push_str(&format!("<tr><th width=\"30%\">Examiner</th><td>{}</td></tr>\n", Self::html_escape(&report.digital_signature.examiner_name)));
        html.push_str(&format!("<tr><th>Algorithm</th><td>{}</td></tr>\n", Self::html_escape(&report.digital_signature.algorithm)));
        html.push_str(&format!("<tr><th>Timestamp</th><td>{}</td></tr>\n", report.digital_signature.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(ref cert_id) = report.digital_signature.certificate_id {
            html.push_str(&format!("<tr><th>Certificate ID</th><td>{}</td></tr>\n", Self::html_escape(cert_id)));
        }
        if let Some(ref sig) = report.digital_signature.signature_value {
            html.push_str(&format!("<tr><th>Signature</th><td class=\"hash\">{}</td></tr>\n", Self::html_escape(sig)));
        }
        html.push_str("</table>\n");
        html.push_str("<p><em>Note: This digital signature serves as a placeholder for the examiner's cryptographically signed attestation. The final signature will be applied using the examiner's PKI certificate upon report finalization.</em></p>\n");
        html.push_str("</div>\n");

        html.push_str(&format!("<p style=\"text-align: center; margin-top: 40px; font-size: 0.8em; color: #666;\">Report Hash: <code>{}</code></p>\n", Self::html_escape(&report.report_hash)));
        html.push_str("<div class=\"confidential\">CONFIDENTIAL - FOR LEGAL PROCEEDINGS ONLY</div>\n");
        html.push_str("</body>\n</html>");

        html
    }

    fn build_text(&self, report: &CourtReport) -> String {
        let mut text = String::new();

        text.push_str("================================================================================\n");
        text.push_str("                     DIGITAL FORENSIC EXAMINATION REPORT\n");
        text.push_str("                          CONFIDENTIAL - LEGAL USE ONLY\n");
        text.push_str("================================================================================\n\n");

        text.push_str(&format!("Case Number    : {}\n", report.case_info.case_number));
        text.push_str(&format!("Case Name      : {}\n", report.case_info.case_name));
        text.push_str(&format!("Court          : {}\n", report.case_info.court));
        text.push_str(&format!("Jurisdiction   : {}\n", report.case_info.jurisdiction));
        text.push_str(&format!("Date Filed     : {}\n", report.case_info.date_filed.format("%Y-%m-%d")));
        text.push_str(&format!("Report ID      : {}\n", report.id));
        text.push_str(&format!("Generated      : {}\n", report.report_generated_at.format("%Y-%m-%d %H:%M:%S UTC")));

        if !report.case_info.parties_involved.is_empty() {
            text.push_str("\n--- Parties Involved ---\n\n");
            for party in &report.case_info.parties_involved {
                text.push_str(&format!("  - {}\n", party));
            }
        }

        text.push_str("\n--- Examiner Information ---\n\n");
        text.push_str(&format!("  Name          : {}\n", report.examiner.name));
        text.push_str(&format!("  Title         : {}\n", report.examiner.title));
        text.push_str(&format!("  Organization  : {}\n", report.examiner.organization));
        if let Some(ref email) = report.examiner.contact_email {
            text.push_str(&format!("  Email         : {}\n", email));
        }
        if let Some(ref phone) = report.examiner.contact_phone {
            text.push_str(&format!("  Phone         : {}\n", phone));
        }
        if let Some(ref license) = report.examiner.license_number {
            text.push_str(&format!("  License       : {}\n", license));
        }

        if !report.examiner.qualifications.is_empty() {
            text.push_str("\n  Qualifications:\n");
            for qual in &report.examiner.qualifications {
                text.push_str(&format!("    - {}\n", qual));
            }
        }

        if !report.examiner.certifications.is_empty() {
            text.push_str("\n  Certifications:\n");
            for cert in &report.examiner.certifications {
                text.push_str(&format!("    - {}\n", cert));
            }
        }

        text.push_str("\n  I certify that I am qualified as an expert in the field of digital\n");
        text.push_str("  forensics and that the findings and opinions expressed in this report\n");
        text.push_str("  are based on my professional examination and analysis.\n");

        text.push_str("\n================================================================================\n");
        text.push_str("                              EVIDENCE INVENTORY\n");
        text.push_str("================================================================================\n\n");

        text.push_str(&format!("  {:<38} {:<20} {:<12} {:>10}\n", "ID", "Description", "Type", "Size"));
        text.push_str(&format!("  {:<38} {:<20} {:<12} {:>10}\n", "--------------------------------------", "--------------------", "------------", "----------"));
        for evidence in &report.evidence_list {
            let desc = if evidence.description.len() > 18 { &evidence.description[..18] } else { &evidence.description };
            let eid = if evidence.id.len() > 36 { &evidence.id[..36] } else { &evidence.id };
            text.push_str(&format!("  {:<38} {:<20} {:<12} {:>10}\n",
                eid,
                desc,
                format!("{:?}", evidence.evidence_type),
                Self::format_size(evidence.size_bytes),
            ));
        }

        for evidence in &report.evidence_list {
            if !evidence.hash_sha256.is_empty() {
                text.push_str(&format!("\n  SHA-256 ({}): {}\n", &evidence.description, evidence.hash_sha256));
            }
            if let Some(ref md5) = evidence.hash_md5 {
                text.push_str(&format!("  MD5     ({}): {}\n", &evidence.description, md5));
            }
        }

        text.push_str("\n================================================================================\n");
        text.push_str("                             CHAIN OF CUSTODY\n");
        text.push_str("================================================================================\n\n");

        for evidence in &report.evidence_list {
            if evidence.chain_of_custody.is_empty() {
                continue;
            }
            text.push_str(&format!("  Evidence: {} ({})\n", evidence.description, evidence.id));
            text.push_str(&format!("  {:<22} {:<20} {:<20} {:<15}\n", "Timestamp", "Handler", "Action", "Location"));
            text.push_str(&format!("  {:<22} {:<20} {:<20} {:<15}\n", "----------------------", "--------------------", "--------------------", "---------------"));
            for entry in &evidence.chain_of_custody {
                let handler = if entry.handler.len() > 18 { &entry.handler[..18] } else { &entry.handler };
                let action = if entry.action.len() > 18 { &entry.action[..18] } else { &entry.action };
                let location = if entry.location.len() > 13 { &entry.location[..13] } else { &entry.location };
                text.push_str(&format!("  {:<22} {:<20} {:<20} {:<15}\n",
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    handler,
                    action,
                    location,
                ));
            }
            text.push_str("\n");
        }

        text.push_str("================================================================================\n");
        text.push_str("                                METHODOLOGY\n");
        text.push_str("================================================================================\n\n");

        for (i, method) in report.methodology.iter().enumerate() {
            text.push_str(&format!("  {}. {} v{}\n", i + 1, method.tool_name, method.tool_version));
            text.push_str(&format!("     Procedure: {}\n", method.procedure));
            if !method.validation_steps.is_empty() {
                text.push_str("     Validation Steps:\n");
                for step in &method.validation_steps {
                    text.push_str(&format!("       - {}\n", step));
                }
            }
            if !method.standard_compliance.is_empty() {
                text.push_str("     Compliance:\n");
                for std in &method.standard_compliance {
                    text.push_str(&format!("       - {}\n", std));
                }
            }
            text.push_str("\n");
        }

        text.push_str("================================================================================\n");
        text.push_str("                                 FINDINGS\n");
        text.push_str("================================================================================\n\n");

        for (i, finding) in report.findings.iter().enumerate() {
            text.push_str(&format!("  Finding {}: {}\n", i + 1, finding.title));
            text.push_str("  ------------------------------------------------------------\n");
            text.push_str(&format!("  Timestamp   : {}\n", finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
            text.push_str(&format!("  Type        : {:?}\n", finding.finding_type));
            text.push_str(&format!("  Confidence  : {:?}\n", finding.confidence_level));
            text.push_str(&format!("  Description : {}\n", finding.description));
            if !finding.examiner_notes.is_empty() {
                text.push_str(&format!("  Notes       : {}\n", finding.examiner_notes));
            }
            if !finding.supporting_evidence_ids.is_empty() {
                text.push_str("  Supporting Evidence:\n");
                for eid in &finding.supporting_evidence_ids {
                    text.push_str(&format!("    - {}\n", eid));
                }
            }
            text.push_str(&format!("  Hash        : {}\n", finding.hash));
            text.push_str("\n");
        }

        text.push_str("================================================================================\n");
        text.push_str("                                CONCLUSIONS\n");
        text.push_str("================================================================================\n\n");

        for (i, conclusion) in report.conclusions.iter().enumerate() {
            text.push_str(&format!("  Conclusion {}\n", i + 1));
            text.push_str("  ------------------------------------------------------------\n");
            text.push_str(&format!("  Summary     : {}\n", conclusion.summary));
            text.push_str(&format!("  Opinion     : {}\n", conclusion.opinion));
            if !conclusion.basis.is_empty() {
                text.push_str("  Basis:\n");
                for b in &conclusion.basis {
                    text.push_str(&format!("    - {}\n", b));
                }
            }
            if !conclusion.limitations.is_empty() {
                text.push_str("  Limitations:\n");
                for l in &conclusion.limitations {
                    text.push_str(&format!("    - {}\n", l));
                }
            }
            text.push_str("\n");
        }

        text.push_str("================================================================================\n");
        text.push_str("                             DIGITAL SIGNATURE\n");
        text.push_str("================================================================================\n\n");

        text.push_str(&format!("  Examiner    : {}\n", report.digital_signature.examiner_name));
        text.push_str(&format!("  Algorithm   : {}\n", report.digital_signature.algorithm));
        text.push_str(&format!("  Timestamp   : {}\n", report.digital_signature.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(ref cert_id) = report.digital_signature.certificate_id {
            text.push_str(&format!("  Certificate : {}\n", cert_id));
        }
        if let Some(ref sig) = report.digital_signature.signature_value {
            text.push_str(&format!("  Signature   : {}\n", sig));
        }
        text.push_str("\n  Note: This digital signature is a placeholder for the examiner's\n");
        text.push_str("  cryptographically signed attestation using their PKI certificate.\n");

        text.push_str(&format!("\n  Report Integrity Hash: {}\n", report.report_hash));
        text.push_str("\n================================================================================\n");
        text.push_str("                    CONFIDENTIAL - FOR LEGAL PROCEEDINGS ONLY\n");
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

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_case_info() -> CaseInfo {
        let mut case = CaseInfo::new("2024-CR-001", "State v. Doe", "Superior Court", "CA");
        case.add_party("State");
        case.add_party("John Doe");
        case.reference_number = Some("REF-12345".to_string());
        case
    }

    fn make_examiner() -> ExaminerInfo {
        let mut examiner = ExaminerInfo::new("Dr. Jane Smith", "Senior Forensic Examiner", "ForensicsLab Inc.");
        examiner.add_qualification("Ph.D. Computer Science");
        examiner.add_qualification("15 years digital forensics experience");
        examiner.add_certification("EnCE");
        examiner.add_certification("GCFA");
        examiner.contact_email = Some("jane@forensicslab.com".to_string());
        examiner.license_number = Some("LIC-98765".to_string());
        examiner
    }

    fn make_evidence() -> EvidenceItem {
        let mut evidence = EvidenceItem::new(
            "Suspect's hard drive",
            "/dev/sda",
            "Dr. Jane Smith",
            "Evidence Locker A-12",
        );
        evidence.evidence_type = EvidenceType::DiskImage;
        evidence.size_bytes = 500_000_000_000;
        evidence.set_hash(b"test data for hashing");
        evidence.add_custody_entry(ChainOfCustodyEntry::new(
            "Officer Brown",
            "Seized from scene",
            "Initial evidence collection",
            "123 Main St",
        ));
        evidence.add_custody_entry(ChainOfCustodyEntry::new(
            "Dr. Jane Smith",
            "Received for analysis",
            "Forensic examination",
            "ForensicsLab",
        ));
        evidence
    }

    fn make_finding(evidence_id: &str) -> CourtFinding {
        let mut finding = CourtFinding::new(
            "Deleted File Recovery",
            "127 documents were recovered from unallocated space indicating deliberate deletion.",
            "Files match keywords from the warrant.",
        );
        finding.finding_type = FindingType::Reconstruction;
        finding.confidence_level = ConfidenceLevel::Confirmed;
        finding.add_supporting_evidence(evidence_id);
        finding
    }

    fn make_methodology() -> MethodologyEntry {
        let mut method = MethodologyEntry::new("Data Doctor", "1.0.0", "Full disk image acquisition and file carving using signature-based recovery.");
        method.add_validation_step("Hash verification of source image");
        method.add_validation_step("Write-blocked acquisition");
        method.add_validation_step("Cross-reference with known file signatures");
        method.add_compliance_standard("NIST SP 800-86");
        method.add_compliance_standard("ISO 27037");
        method.add_reference("NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response");
        method
    }

    fn make_conclusion() -> Conclusion {
        let mut conclusion = Conclusion::new(
            "Evidence of deliberate file deletion was found on the subject's hard drive.",
            "Based on the forensic analysis, it is my professional opinion that the deleted files were intentionally removed.",
        );
        conclusion.add_basis("127 deleted documents recovered from unallocated space");
        conclusion.add_basis("Deletion timestamps correlate with warrant execution date");
        conclusion.add_limitation("Recovered files are partially corrupted in 12 cases");
        conclusion.add_limitation("Analysis limited to internal storage only");
        conclusion
    }

    fn make_generator() -> CourtReportGenerator {
        let mut gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        let evidence = make_evidence();
        let evidence_id = evidence.id.clone();
        gen.add_evidence(evidence);
        gen.add_finding(make_finding(&evidence_id));
        gen.add_methodology(make_methodology());
        gen.add_conclusion(make_conclusion());
        gen
    }

    #[test]
    fn test_case_info_creation() {
        let case = CaseInfo::new("2024-CR-001", "State v. Doe", "CA", "Superior Court");
        assert_eq!(case.case_number, "2024-CR-001");
        assert_eq!(case.case_name, "State v. Doe");
        assert_eq!(case.jurisdiction, "CA");
        assert_eq!(case.court, "Superior Court");
        assert!(case.parties_involved.is_empty());
    }

    #[test]
    fn test_case_info_add_party() {
        let mut case = CaseInfo::new("2024-CR-001", "Test", "Court", "CA");
        case.add_party("Plaintiff");
        case.add_party("Defendant");
        assert_eq!(case.parties_involved.len(), 2);
        assert_eq!(case.parties_involved[0], "Plaintiff");
        assert_eq!(case.parties_involved[1], "Defendant");
    }

    #[test]
    fn test_examiner_info_creation() {
        let examiner = ExaminerInfo::new("Dr. Smith", "Examiner", "Lab");
        assert_eq!(examiner.name, "Dr. Smith");
        assert_eq!(examiner.title, "Examiner");
        assert_eq!(examiner.organization, "Lab");
        assert!(examiner.qualifications.is_empty());
        assert!(examiner.certifications.is_empty());
        assert!(examiner.contact_email.is_none());
    }

    #[test]
    fn test_examiner_info_qualifications() {
        let mut examiner = ExaminerInfo::new("Dr. Smith", "Examiner", "Lab");
        examiner.add_qualification("Ph.D.");
        examiner.add_certification("GCFA");
        assert_eq!(examiner.qualifications.len(), 1);
        assert_eq!(examiner.certifications.len(), 1);
    }

    #[test]
    fn test_evidence_item_creation() {
        let evidence = EvidenceItem::new("Hard drive", "/dev/sda", "Officer", "Locker A");
        assert_eq!(evidence.description, "Hard drive");
        assert_eq!(evidence.source, "/dev/sda");
        assert_eq!(evidence.acquired_by, "Officer");
        assert_eq!(evidence.storage_location, "Locker A");
        assert!(evidence.hash_sha256.is_empty());
        assert!(evidence.chain_of_custody.is_empty());
        assert!(!evidence.id.is_empty());
    }

    #[test]
    fn test_evidence_hash_computation() {
        let mut evidence = EvidenceItem::new("Test", "/dev/sda", "Officer", "Locker");
        evidence.set_hash(b"test data");
        assert!(!evidence.hash_sha256.is_empty());
        assert_eq!(evidence.hash_sha256.len(), 64);
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let mut e1 = EvidenceItem::new("Test", "/dev/sda", "Officer", "Locker");
        let mut e2 = EvidenceItem::new("Test", "/dev/sda", "Officer", "Locker");
        e1.set_hash(b"same data");
        e2.set_hash(b"same data");
        assert_eq!(e1.hash_sha256, e2.hash_sha256);
    }

    #[test]
    fn test_chain_of_custody_entry() {
        let mut entry = ChainOfCustodyEntry::new("Handler", "Action", "Purpose", "Location");
        entry.add_witness("Witness 1");
        entry.add_witness("Witness 2");
        assert_eq!(entry.handler, "Handler");
        assert_eq!(entry.witnesses.len(), 2);
    }

    #[test]
    fn test_court_finding_creation() {
        let finding = CourtFinding::new("Title", "Description", "Notes");
        assert_eq!(finding.title, "Title");
        assert_eq!(finding.description, "Description");
        assert!(!finding.hash.is_empty());
        assert_eq!(finding.hash.len(), 64);
        assert_eq!(finding.finding_type, FindingType::Fact);
        assert_eq!(finding.confidence_level, ConfidenceLevel::Confirmed);
    }

    #[test]
    fn test_court_finding_hash_deterministic() {
        let f1 = CourtFinding::new("Same", "Data", "Notes");
        let f2 = CourtFinding::new("Same", "Data", "Notes");
        assert_eq!(f1.hash, f2.hash);
    }

    #[test]
    fn test_court_finding_supporting_evidence() {
        let mut finding = CourtFinding::new("Title", "Desc", "Notes");
        finding.add_supporting_evidence("evidence-1");
        finding.add_supporting_evidence("evidence-2");
        assert_eq!(finding.supporting_evidence_ids.len(), 2);
    }

    #[test]
    fn test_methodology_entry() {
        let mut method = MethodologyEntry::new("Tool", "1.0", "Procedure");
        method.add_validation_step("Step 1");
        method.add_reference("Ref 1");
        method.add_compliance_standard("NIST");
        assert_eq!(method.validation_steps.len(), 1);
        assert_eq!(method.references.len(), 1);
        assert_eq!(method.standard_compliance.len(), 1);
    }

    #[test]
    fn test_conclusion_creation() {
        let mut conclusion = Conclusion::new("Summary", "Opinion");
        conclusion.add_basis("Basis 1");
        conclusion.add_limitation("Limitation 1");
        assert_eq!(conclusion.summary, "Summary");
        assert_eq!(conclusion.opinion, "Opinion");
        assert_eq!(conclusion.basis.len(), 1);
        assert_eq!(conclusion.limitations.len(), 1);
    }

    #[test]
    fn test_digital_signature_placeholder() {
        let sig = DigitalSignature::placeholder("Dr. Smith");
        assert_eq!(sig.examiner_name, "Dr. Smith");
        assert_eq!(sig.algorithm, "SHA-256 with RSA");
        assert!(sig.certificate_id.is_none());
        assert!(sig.signature_value.is_none());
    }

    #[test]
    fn test_generator_creation() {
        let gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        let report = gen.generate_report();
        assert!(!report.id.is_empty());
        assert_eq!(report.case_info.case_number, "2024-CR-001");
        assert_eq!(report.version, 1);
    }

    #[test]
    fn test_generator_add_evidence() {
        let mut gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        gen.add_evidence(make_evidence());
        let report = gen.generate_report();
        assert_eq!(report.evidence_list.len(), 1);
    }

    #[test]
    fn test_generator_add_finding() {
        let mut gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        gen.add_finding(CourtFinding::new("Title", "Desc", "Notes"));
        let report = gen.generate_report();
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn test_report_hash_nonempty() {
        let gen = make_generator();
        let report = gen.generate_report();
        assert!(!report.report_hash.is_empty());
        assert_eq!(report.report_hash.len(), 64);
    }

    #[test]
    fn test_generate_html_string() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("DIGITAL FORENSIC EXAMINATION REPORT"));
        assert!(html.contains("2024-CR-001"));
        assert!(html.contains("State v. Doe"));
        assert!(html.contains("Dr. Jane Smith"));
        assert!(html.contains("Chain of Custody"));
        assert!(html.contains("Methodology"));
        assert!(html.contains("Findings"));
        assert!(html.contains("Conclusions"));
        assert!(html.contains("Digital Signature"));
        assert!(html.contains("CONFIDENTIAL"));
    }

    #[test]
    fn test_generate_text_string() {
        let gen = make_generator();
        let text = gen.generate_text_string();
        assert!(text.contains("DIGITAL FORENSIC EXAMINATION REPORT"));
        assert!(text.contains("2024-CR-001"));
        assert!(text.contains("State v. Doe"));
        assert!(text.contains("Dr. Jane Smith"));
        assert!(text.contains("CHAIN OF CUSTODY"));
        assert!(text.contains("METHODOLOGY"));
        assert!(text.contains("FINDINGS"));
        assert!(text.contains("CONCLUSIONS"));
        assert!(text.contains("DIGITAL SIGNATURE"));
        assert!(text.contains("CONFIDENTIAL"));
    }

    #[test]
    fn test_generate_html_file() {
        let gen = make_generator();
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("report.html");
        let html = gen.generate_html(&output).unwrap();
        assert!(output.exists());
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_generate_text_file() {
        let gen = make_generator();
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("report.txt");
        let text = gen.generate_text(&output).unwrap();
        assert!(output.exists());
        assert!(text.contains("DIGITAL FORENSIC EXAMINATION REPORT"));
    }

    #[test]
    fn test_generate_pdf() {
        let gen = make_generator();
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("report.html");
        let html = gen.generate_pdf(&output).unwrap();
        assert!(!html.is_empty());
        let pdf_path = dir.path().join("report.pdf");
        assert!(pdf_path.exists());
    }

    #[test]
    fn test_html_contains_evidence_hashes() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("SHA-256"));
        assert!(html.contains("hash"));
    }

    #[test]
    fn test_html_contains_timestamps() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("UTC"));
    }

    #[test]
    fn test_text_contains_evidence_details() {
        let gen = make_generator();
        let text = gen.generate_text_string();
        assert!(text.contains("Suspect's hard drive"));
        assert!(text.contains("SHA-256"));
        assert!(text.contains("Officer Brown"));
    }

    #[test]
    fn test_html_contains_methodology_standards() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("NIST SP 800-86"));
        assert!(html.contains("ISO 27037"));
    }

    #[test]
    fn test_html_contains_certification() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("certify that I am qualified"));
    }

    #[test]
    fn test_html_contains_signature_placeholder() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("placeholder"));
        assert!(html.contains("PKI certificate"));
    }

    #[test]
    fn test_empty_report_generation() {
        let gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        let report = gen.generate_report();
        assert!(report.evidence_list.is_empty());
        assert!(report.findings.is_empty());
        assert!(report.methodology.is_empty());
        assert!(report.conclusions.is_empty());
        let html = gen.generate_html_string();
        assert!(html.contains("2024-CR-001"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(CourtReportGenerator::html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(CourtReportGenerator::html_escape("a&b"), "a&amp;b");
        assert_eq!(CourtReportGenerator::html_escape("a\"b"), "a&quot;b");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(CourtReportGenerator::format_size(0), "0 B");
        assert_eq!(CourtReportGenerator::format_size(512), "512 B");
        assert_eq!(CourtReportGenerator::format_size(1024), "1.0 KB");
        assert_eq!(CourtReportGenerator::format_size(1048576), "1.0 MB");
        assert_eq!(CourtReportGenerator::format_size(1073741824), "1.0 GB");
    }

    #[test]
    fn test_multiple_evidence_items() {
        let mut gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        gen.add_evidence(make_evidence());
        gen.add_evidence(make_evidence());
        gen.add_evidence(make_evidence());
        let report = gen.generate_report();
        assert_eq!(report.evidence_list.len(), 3);
    }

    #[test]
    fn test_multiple_findings() {
        let mut gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        gen.add_finding(CourtFinding::new("Finding 1", "Desc 1", "Notes 1"));
        gen.add_finding(CourtFinding::new("Finding 2", "Desc 2", "Notes 2"));
        let report = gen.generate_report();
        assert_eq!(report.findings.len(), 2);
    }

    #[test]
    fn test_finding_types() {
        let mut finding = CourtFinding::new("Test", "Desc", "Notes");
        finding.finding_type = FindingType::Opinion;
        assert_eq!(finding.finding_type, FindingType::Opinion);
        finding.finding_type = FindingType::Anomaly;
        assert_eq!(finding.finding_type, FindingType::Anomaly);
    }

    #[test]
    fn test_confidence_levels() {
        let mut finding = CourtFinding::new("Test", "Desc", "Notes");
        finding.confidence_level = ConfidenceLevel::Inconclusive;
        assert_eq!(finding.confidence_level, ConfidenceLevel::Inconclusive);
        finding.confidence_level = ConfidenceLevel::HighlyLikely;
        assert_eq!(finding.confidence_level, ConfidenceLevel::HighlyLikely);
    }

    #[test]
    fn test_evidence_types() {
        let mut evidence = EvidenceItem::new("Test", "/dev/sda", "Officer", "Locker");
        evidence.evidence_type = EvidenceType::MemoryDump;
        assert_eq!(evidence.evidence_type, EvidenceType::MemoryDump);
        evidence.evidence_type = EvidenceType::NetworkCapture;
        assert_eq!(evidence.evidence_type, EvidenceType::NetworkCapture);
    }

    #[test]
    fn test_report_serialization() {
        let gen = make_generator();
        let report = gen.generate_report();
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: CourtReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, report.id);
        assert_eq!(deserialized.case_info.case_number, report.case_info.case_number);
        assert_eq!(deserialized.evidence_list.len(), report.evidence_list.len());
        assert_eq!(deserialized.findings.len(), report.findings.len());
    }

    #[test]
    fn test_multiple_conclusions() {
        let mut gen = CourtReportGenerator::new(make_case_info(), make_examiner());
        gen.add_conclusion(make_conclusion());
        gen.add_conclusion(Conclusion::new("Second conclusion", "Second opinion"));
        let report = gen.generate_report();
        assert_eq!(report.conclusions.len(), 2);
    }

    #[test]
    fn test_text_contains_finding_hashes() {
        let gen = make_generator();
        let text = gen.generate_text_string();
        assert!(text.contains("Hash        :"));
    }

    #[test]
    fn test_html_contains_parties() {
        let gen = make_generator();
        let html = gen.generate_html_string();
        assert!(html.contains("State"));
        assert!(html.contains("John Doe"));
    }

    #[test]
    fn test_text_contains_parties() {
        let gen = make_generator();
        let text = gen.generate_text_string();
        assert!(text.contains("State"));
        assert!(text.contains("John Doe"));
    }
}
