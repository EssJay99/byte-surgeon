use crate::{Error, Result};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    LeadExaminer,
    AssistantExaminer,
    Reviewer,
    Witness,
}

impl Role {
    pub fn permission_level(&self) -> u8 {
        match self {
            Role::LeadExaminer => 100,
            Role::AssistantExaminer => 75,
            Role::Reviewer => 50,
            Role::Witness => 25,
        }
    }

    pub fn can_perform(&self, operation: &ExaminerOper) -> bool {
        match (self, operation) {
            (Role::LeadExaminer, _) => true,
            (Role::AssistantExaminer, ExaminerOper::RecoverFile) => true,
            (Role::AssistantExaminer, ExaminerOper::ScanDisk) => true,
            (Role::AssistantExaminer, ExaminerOper::PreviewFile) => true,
            (Role::AssistantExaminer, ExaminerOper::ExportReport) => false,
            (Role::AssistantExaminer, ExaminerOper::DeleteEvidence) => false,
            (Role::Reviewer, ExaminerOper::RecoverFile) => false,
            (Role::Reviewer, ExaminerOper::ScanDisk) => false,
            (Role::Reviewer, ExaminerOper::PreviewFile) => true,
            (Role::Reviewer, ExaminerOper::ExportReport) => true,
            (Role::Reviewer, ExaminerOper::DeleteEvidence) => false,
            (Role::Witness, ExaminerOper::RecoverFile) => false,
            (Role::Witness, ExaminerOper::ScanDisk) => false,
            (Role::Witness, ExaminerOper::PreviewFile) => true,
            (Role::Witness, ExaminerOper::ExportReport) => false,
            (Role::Witness, ExaminerOper::DeleteEvidence) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExaminerOper {
    RecoverFile,
    ScanDisk,
    PreviewFile,
    ExportReport,
    DeleteEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Examiner {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub credentials: String,
    pub contact: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLogEntry {
    pub examiner_id: String,
    pub operation: ExaminerOper,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub examiner_id: String,
    pub operation: ExaminerOper,
    pub target: String,
    pub assigned_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: AssignmentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AssignmentStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

pub struct ExaminerManager {
    examiners: Mutex<HashMap<String, Examiner>>,
    activity_logs: Mutex<Vec<ActivityLogEntry>>,
    assignments: Mutex<HashMap<String, Assignment>>,
}

impl ExaminerManager {
    pub fn new() -> Self {
        info!("ExaminerManager initialized");
        Self {
            examiners: Mutex::new(HashMap::new()),
            activity_logs: Mutex::new(Vec::new()),
            assignments: Mutex::new(HashMap::new()),
        }
    }

    pub fn add_examiner(&self, examiner: Examiner) -> Result<()> {
        let mut examiners = self.examiners.lock();
        if examiners.contains_key(&examiner.id) {
            return Err(Error::Other(format!("Examiner with id {} already exists", examiner.id)));
        }
        info!("Added examiner: {} ({})", examiner.name, examiner.id);
        examiners.insert(examiner.id.clone(), examiner);
        Ok(())
    }

    pub fn list_examiners(&self) -> Vec<Examiner> {
        self.examiners.lock().values().cloned().collect()
    }

    pub fn get_examiner(&self, id: &str) -> Result<Examiner> {
        self.examiners
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::Other(format!("Examiner {} not found", id)))
    }

    pub fn remove_examiner(&self, id: &str) -> Result<()> {
        let mut examiners = self.examiners.lock();
        if examiners.remove(id).is_none() {
            return Err(Error::Other(format!("Examiner {} not found", id)));
        }
        info!("Removed examiner: {}", id);
        Ok(())
    }

    pub fn authenticate(&self, id: &str, password: &str) -> Result<bool> {
        let examiners = self.examiners.lock();
        let examiner = examiners
            .get(id)
            .ok_or_else(|| Error::Other(format!("Examiner {} not found", id)))?;

        if !examiner.is_active {
            warn!("Authentication attempt for inactive examiner: {}", id);
            return Ok(false);
        }

        Ok(Self::hash_password(password) == examiner.password_hash)
    }

    pub fn log_activity(&self, examiner_id: &str, operation: ExaminerOper, target: &str, success: bool, details: &str) -> Result<()> {
        {
            let examiners = self.examiners.lock();
            if !examiners.contains_key(examiner_id) {
                return Err(Error::Other(format!("Examiner {} not found", examiner_id)));
            }
        }

        let entry = ActivityLogEntry {
            examiner_id: examiner_id.to_string(),
            operation,
            target: target.to_string(),
            timestamp: Utc::now(),
            success,
            details: details.to_string(),
        };
        self.activity_logs.lock().push(entry);
        Ok(())
    }

    pub fn get_activity_log(&self, examiner_id: &str) -> Vec<ActivityLogEntry> {
        self.activity_logs
            .lock()
            .iter()
            .filter(|e| e.examiner_id == examiner_id)
            .cloned()
            .collect()
    }

    pub fn get_all_activity_logs(&self) -> Vec<ActivityLogEntry> {
        self.activity_logs.lock().clone()
    }

    pub fn assign_operation(&self, examiner_id: &str, operation: ExaminerOper, target: &str) -> Result<String> {
        {
            let examiners = self.examiners.lock();
            let examiner = examiners
                .get(examiner_id)
                .ok_or_else(|| Error::Other(format!("Examiner {} not found", examiner_id)))?;

            if !examiner.role.can_perform(&operation) {
                return Err(Error::PermissionDenied(format!(
                    "Examiner {} with role {:?} cannot perform {:?}",
                    examiner_id, examiner.role, operation
                )));
            }
        }

        info!("Assigned operation to examiner {}: {:?}", examiner_id, operation);
        let assignment_id = uuid::Uuid::new_v4().to_string();
        let assignment = Assignment {
            id: assignment_id.clone(),
            examiner_id: examiner_id.to_string(),
            operation,
            target: target.to_string(),
            assigned_at: Utc::now(),
            completed_at: None,
            status: AssignmentStatus::Pending,
        };
        self.assignments.lock().insert(assignment_id.clone(), assignment);
        Ok(assignment_id)
    }

    pub fn complete_assignment(&self, assignment_id: &str, success: bool) -> Result<()> {
        let mut assignments = self.assignments.lock();
        let assignment = assignments
            .get_mut(assignment_id)
            .ok_or_else(|| Error::Other(format!("Assignment {} not found", assignment_id)))?;

        assignment.completed_at = Some(Utc::now());
        assignment.status = if success {
            AssignmentStatus::Completed
        } else {
            AssignmentStatus::Failed
        };
        Ok(())
    }

    pub fn get_assignment(&self, assignment_id: &str) -> Result<Assignment> {
        self.assignments
            .lock()
            .get(assignment_id)
            .cloned()
            .ok_or_else(|| Error::Other(format!("Assignment {} not found", assignment_id)))
    }

    pub fn get_examiner_assignments(&self, examiner_id: &str) -> Vec<Assignment> {
        self.assignments
            .lock()
            .values()
            .filter(|a| a.examiner_id == examiner_id)
            .cloned()
            .collect()
    }

    pub fn execute_operation(&self, examiner_id: &str, operation: ExaminerOper, target: &str) -> Result<String> {
        let examiner = self.get_examiner(examiner_id)?;

        if !examiner.role.can_perform(&operation) {
            self.log_activity(examiner_id, operation.clone(), target, false, "Permission denied")?;
            return Err(Error::PermissionDenied(format!(
                "Examiner {} with role {:?} cannot perform {:?}",
                examiner_id, examiner.role, operation
            )));
        }

        let assignment_id = self.assign_operation(examiner_id, operation.clone(), target)?;
        {
            let mut assignments = self.assignments.lock();
            if let Some(a) = assignments.get_mut(&assignment_id) {
                a.status = AssignmentStatus::InProgress;
            }
        }

        self.log_activity(examiner_id, operation, target, true, "Operation executed")?;
        self.complete_assignment(&assignment_id, true)?;
        Ok(assignment_id)
    }

    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn create_examiner(id: &str, name: &str, role: Role, credentials: &str, contact: &str, password: &str) -> Examiner {
        Examiner {
            id: id.to_string(),
            name: name.to_string(),
            role,
            credentials: credentials.to_string(),
            contact: contact.to_string(),
            password_hash: Self::hash_password(password),
            created_at: Utc::now(),
            is_active: true,
        }
    }
}

impl Default for ExaminerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> ExaminerManager {
        ExaminerManager::new()
    }

    fn make_examiner(id: &str, role: Role) -> Examiner {
        ExaminerManager::create_examiner(id, &format!("Examiner {}", id), role, "cert-001", "test@example.com", "password123")
    }

    #[test]
    fn test_add_and_get_examiner() {
        let mgr = make_manager();
        let ex = make_examiner("ex-1", Role::LeadExaminer);
        mgr.add_examiner(ex.clone()).unwrap();

        let fetched = mgr.get_examiner("ex-1").unwrap();
        assert_eq!(fetched.id, "ex-1");
        assert_eq!(fetched.name, "Examiner ex-1");
        assert_eq!(fetched.role, Role::LeadExaminer);
    }

    #[test]
    fn test_add_duplicate_examiner() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();
        assert!(mgr.add_examiner(make_examiner("ex-1", Role::Reviewer)).is_err());
    }

    #[test]
    fn test_list_examiners() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();
        mgr.add_examiner(make_examiner("ex-2", Role::Reviewer)).unwrap();
        mgr.add_examiner(make_examiner("ex-3", Role::Witness)).unwrap();

        let list = mgr.list_examiners();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_remove_examiner() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();
        assert_eq!(mgr.list_examiners().len(), 1);

        mgr.remove_examiner("ex-1").unwrap();
        assert_eq!(mgr.list_examiners().len(), 0);
        assert!(mgr.get_examiner("ex-1").is_err());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mgr = make_manager();
        assert!(mgr.remove_examiner("nope").is_err());
    }

    #[test]
    fn test_authentication() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();

        assert!(mgr.authenticate("ex-1", "password123").unwrap());
        assert!(!mgr.authenticate("ex-1", "wrong").unwrap());
        assert!(mgr.authenticate("nonexistent", "password123").is_err());
    }

    #[test]
    fn test_authentication_inactive() {
        let mgr = make_manager();
        let mut ex = make_examiner("ex-1", Role::LeadExaminer);
        ex.is_active = false;
        mgr.add_examiner(ex).unwrap();

        assert!(!mgr.authenticate("ex-1", "password123").unwrap());
    }

    #[test]
    fn test_role_permissions() {
        assert!(Role::LeadExaminer.can_perform(&ExaminerOper::RecoverFile));
        assert!(Role::LeadExaminer.can_perform(&ExaminerOper::DeleteEvidence));

        assert!(Role::AssistantExaminer.can_perform(&ExaminerOper::RecoverFile));
        assert!(!Role::AssistantExaminer.can_perform(&ExaminerOper::DeleteEvidence));

        assert!(!Role::Reviewer.can_perform(&ExaminerOper::RecoverFile));
        assert!(Role::Reviewer.can_perform(&ExaminerOper::PreviewFile));

        assert!(!Role::Witness.can_perform(&ExaminerOper::RecoverFile));
        assert!(Role::Witness.can_perform(&ExaminerOper::PreviewFile));
    }

    #[test]
    fn test_permission_levels() {
        assert!(Role::LeadExaminer.permission_level() > Role::AssistantExaminer.permission_level());
        assert!(Role::AssistantExaminer.permission_level() > Role::Reviewer.permission_level());
        assert!(Role::Reviewer.permission_level() > Role::Witness.permission_level());
    }

    #[test]
    fn test_activity_log() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();

        mgr.log_activity("ex-1", ExaminerOper::ScanDisk, "/dev/sda", true, "Scan completed").unwrap();
        mgr.log_activity("ex-1", ExaminerOper::RecoverFile, "/lost/file.txt", true, "File recovered").unwrap();

        let logs = mgr.get_activity_log("ex-1");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].operation, ExaminerOper::ScanDisk);
        assert_eq!(logs[1].operation, ExaminerOper::RecoverFile);
    }

    #[test]
    fn test_activity_log_nonexistent_examiner() {
        let mgr = make_manager();
        assert!(mgr.log_activity("nope", ExaminerOper::ScanDisk, "/dev/sda", true, "test").is_err());
    }

    #[test]
    fn test_assign_operation() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();

        let aid = mgr.assign_operation("ex-1", ExaminerOper::RecoverFile, "/file.txt").unwrap();
        let assignment = mgr.get_assignment(&aid).unwrap();
        assert_eq!(assignment.examiner_id, "ex-1");
        assert_eq!(assignment.status, AssignmentStatus::Pending);
        assert!(assignment.completed_at.is_none());
    }

    #[test]
    fn test_assign_operation_permission_denied() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::Witness)).unwrap();

        assert!(mgr.assign_operation("ex-1", ExaminerOper::RecoverFile, "/file.txt").is_err());
    }

    #[test]
    fn test_complete_assignment() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();

        let aid = mgr.assign_operation("ex-1", ExaminerOper::ScanDisk, "/dev/sda").unwrap();
        mgr.complete_assignment(&aid, true).unwrap();

        let assignment = mgr.get_assignment(&aid).unwrap();
        assert_eq!(assignment.status, AssignmentStatus::Completed);
        assert!(assignment.completed_at.is_some());
    }

    #[test]
    fn test_execute_operation() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::AssistantExaminer)).unwrap();

        let aid = mgr.execute_operation("ex-1", ExaminerOper::RecoverFile, "/file.txt").unwrap();
        let assignment = mgr.get_assignment(&aid).unwrap();
        assert_eq!(assignment.status, AssignmentStatus::Completed);

        let logs = mgr.get_activity_log("ex-1");
        assert_eq!(logs.len(), 1);
        assert!(logs[0].success);
    }

    #[test]
    fn test_execute_operation_permission_denied() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::Witness)).unwrap();

        assert!(mgr.execute_operation("ex-1", ExaminerOper::DeleteEvidence, "/evidence").is_err());
    }

    #[test]
    fn test_get_examiner_assignments() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();

        mgr.assign_operation("ex-1", ExaminerOper::ScanDisk, "/dev/sda").unwrap();
        mgr.assign_operation("ex-1", ExaminerOper::RecoverFile, "/file.txt").unwrap();

        let assignments = mgr.get_examiner_assignments("ex-1");
        assert_eq!(assignments.len(), 2);
    }

    #[test]
    fn test_get_all_activity_logs() {
        let mgr = make_manager();
        mgr.add_examiner(make_examiner("ex-1", Role::LeadExaminer)).unwrap();
        mgr.add_examiner(make_examiner("ex-2", Role::Reviewer)).unwrap();

        mgr.log_activity("ex-1", ExaminerOper::ScanDisk, "/dev/sda", true, "scan").unwrap();
        mgr.log_activity("ex-2", ExaminerOper::PreviewFile, "/file.txt", true, "preview").unwrap();

        let all = mgr.get_all_activity_logs();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_password_hash_deterministic() {
        let h1 = ExaminerManager::hash_password("test");
        let h2 = ExaminerManager::hash_password("test");
        assert_eq!(h1, h2);
        assert_ne!(h1, ExaminerManager::hash_password("other"));
    }

    #[test]
    fn test_create_examiner() {
        let ex = ExaminerManager::create_examiner("id-1", "Alice", Role::LeadExaminer, "cert-A", "alice@example.com", "secret");
        assert_eq!(ex.id, "id-1");
        assert_eq!(ex.name, "Alice");
        assert_eq!(ex.role, Role::LeadExaminer);
        assert!(ex.is_active);
        assert!(!ex.password_hash.is_empty());
    }
}
