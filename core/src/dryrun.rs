use crate::{Result, Error};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;
use tracing::{info, warn, debug};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationType {
    Recovery,
    Deletion,
    Modification,
    Deduplication,
    Scan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationKind {
    RecoverFile,
    RecoverSession,
    CarveFile,
    DeleteFile,
    SecureWipe,
    RemoveDuplicate,
    RenameFile,
    MoveFile,
    ChangePermissions,
    PreserveMetadata,
    ThreatScan,
    IntegrityCheck,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedOperation {
    pub id: String,
    pub operation_type: OperationType,
    pub kind: OperationKind,
    pub description: String,
    pub source_path: Option<PathBuf>,
    pub target_path: Option<PathBuf>,
    pub size: u64,
    pub risk_level: RiskLevel,
    pub reversible: bool,
    pub estimated_time_ms: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl PlannedOperation {
    pub fn new(
        operation_type: OperationType,
        kind: OperationKind,
        description: &str,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            operation_type,
            kind,
            description: description.to_string(),
            source_path: None,
            target_path: None,
            size: 0,
            risk_level: RiskLevel::Low,
            reversible: true,
            estimated_time_ms: 0,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn with_source(mut self, path: PathBuf) -> Self {
        self.source_path = Some(path);
        self
    }

    pub fn with_target(mut self, path: PathBuf) -> Self {
        self.target_path = Some(path);
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk_level = risk;
        self
    }

    pub fn with_reversible(mut self, reversible: bool) -> Self {
        self.reversible = reversible;
        self
    }

    pub fn with_time_estimate(mut self, ms: u64) -> Self {
        self.estimated_time_ms = ms;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
}

impl RiskSummary {
    pub fn new() -> Self {
        Self {
            low: 0,
            medium: 0,
            high: 0,
            critical: 0,
        }
    }

    pub fn record(&mut self, level: RiskLevel) {
        match level {
            RiskLevel::Low => self.low += 1,
            RiskLevel::Medium => self.medium += 1,
            RiskLevel::High => self.high += 1,
            RiskLevel::Critical => self.critical += 1,
        }
    }

    pub fn total(&self) -> u32 {
        self.low + self.medium + self.high + self.critical
    }

    pub fn max_risk(&self) -> RiskLevel {
        if self.critical > 0 {
            RiskLevel::Critical
        } else if self.high > 0 {
            RiskLevel::High
        } else if self.medium > 0 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactEstimate {
    pub total_files_affected: u64,
    pub total_space_required: u64,
    pub total_space_freed: u64,
    pub estimated_time_ms: u64,
    pub risk_summary: RiskSummary,
    pub irreversible_operations: u32,
    pub operation_breakdown: OperationBreakdown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationBreakdown {
    pub recovery_ops: u32,
    pub deletion_ops: u32,
    pub modification_ops: u32,
    pub deduplication_ops: u32,
    pub scan_ops: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunContext {
    pub enabled: bool,
    pub planned_operations: Vec<PlannedOperation>,
    pub estimated_impact: ImpactEstimate,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl DryRunContext {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            planned_operations: Vec::new(),
            estimated_impact: ImpactEstimate {
                total_files_affected: 0,
                total_space_required: 0,
                total_space_freed: 0,
                estimated_time_ms: 0,
                risk_summary: RiskSummary::new(),
                irreversible_operations: 0,
                operation_breakdown: OperationBreakdown::default(),
            },
            created_at: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResult {
    pub operations_to_execute: Vec<PlannedOperation>,
    pub files_affected: Vec<PathBuf>,
    pub space_required: u64,
    pub time_estimate: Duration,
    pub impact: ImpactEstimate,
    pub summary: String,
}

impl DryRunResult {
    pub fn has_critical_risk(&self) -> bool {
        self.impact.risk_summary.critical > 0
    }

    pub fn has_irreversible_operations(&self) -> bool {
        self.operations_to_execute.iter().any(|op| !op.reversible)
    }

    pub fn total_operations(&self) -> usize {
        self.operations_to_execute.len()
    }

    pub fn unique_files_affected(&self) -> usize {
        let mut unique = std::collections::HashSet::new();
        for op in &self.operations_to_execute {
            if let Some(ref src) = op.source_path {
                unique.insert(src.clone());
            }
            if let Some(ref tgt) = op.target_path {
                unique.insert(tgt.clone());
            }
        }
        unique.len()
    }
}

pub struct DryRunExecutor {
    context: DryRunContext,
}

impl DryRunExecutor {
    pub fn new() -> Self {
        Self {
            context: DryRunContext::new(true),
        }
    }

    pub fn with_context(context: DryRunContext) -> Self {
        Self { context }
    }

    pub fn context(&self) -> &DryRunContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut DryRunContext {
        &mut self.context
    }

    pub fn is_enabled(&self) -> bool {
        self.context.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.context.enabled = enabled;
    }

    pub fn plan_operation(&mut self, operation: PlannedOperation) -> Result<()> {
        if !self.context.enabled {
            return Err(Error::Other("Dry-run mode is disabled".to_string()));
        }

        debug!(
            "Planning operation: {} [{}] risk={:?}",
            operation.description, operation.id, operation.risk_level
        );

        self.context.planned_operations.push(operation);
        self.recalculate_impact();
        Ok(())
    }

    pub fn plan_recovery(&mut self, source: PathBuf, target: PathBuf, size: u64) -> Result<String> {
        let op = PlannedOperation::new(
            OperationType::Recovery,
            OperationKind::RecoverFile,
            &format!("Recover {} -> {}", source.display(), target.display()),
        )
        .with_source(source)
        .with_target(target)
        .with_size(size)
        .with_risk(RiskLevel::Low)
        .with_reversible(true)
        .with_time_estimate(Self::estimate_recovery_time(size));

        let id = op.id.clone();
        self.plan_operation(op)?;
        Ok(id)
    }

    pub fn plan_deletion(&mut self, path: PathBuf, size: u64, secure: bool) -> Result<String> {
        let kind = if secure {
            OperationKind::SecureWipe
        } else {
            OperationKind::DeleteFile
        };
        let risk = if secure {
            RiskLevel::Critical
        } else {
            RiskLevel::High
        };

        let op = PlannedOperation::new(
            OperationType::Deletion,
            kind,
            &format!(
                "{} {}",
                if secure { "Secure wipe" } else { "Delete" },
                path.display()
            ),
        )
        .with_source(path)
        .with_size(size)
        .with_risk(risk)
        .with_reversible(false)
        .with_time_estimate(if secure { size / 1024 } else { 10 });

        let id = op.id.clone();
        self.plan_operation(op)?;
        Ok(id)
    }

    pub fn plan_modification(
        &mut self,
        kind: OperationKind,
        source: PathBuf,
        target: Option<PathBuf>,
        description: &str,
    ) -> Result<String> {
        let mut op = PlannedOperation::new(OperationType::Modification, kind, description)
            .with_source(source)
            .with_risk(RiskLevel::Medium)
            .with_reversible(true)
            .with_time_estimate(50);

        if let Some(tgt) = target {
            op.target_path = Some(tgt);
        }

        let id = op.id.clone();
        self.plan_operation(op)?;
        Ok(id)
    }

    pub fn plan_deduplication(&mut self, path: PathBuf, size: u64) -> Result<String> {
        let op = PlannedOperation::new(
            OperationType::Deduplication,
            OperationKind::RemoveDuplicate,
            &format!("Remove duplicate: {}", path.display()),
        )
        .with_source(path)
        .with_size(size)
        .with_risk(RiskLevel::Medium)
        .with_reversible(false)
        .with_time_estimate(20);

        let id = op.id.clone();
        self.plan_operation(op)?;
        Ok(id)
    }

    pub fn plan_scan(&mut self, path: PathBuf, kind: OperationKind, size: u64) -> Result<String> {
        let op = PlannedOperation::new(OperationType::Scan, kind, &format!("Scan: {}", path.display()))
            .with_source(path)
            .with_size(size)
            .with_risk(RiskLevel::Low)
            .with_reversible(true)
            .with_time_estimate(size / 2048);

        let id = op.id.clone();
        self.plan_operation(op)?;
        Ok(id)
    }

    pub fn execute_dry_run(&self) -> Result<DryRunResult> {
        if !self.context.enabled {
            return Err(Error::Other("Dry-run mode is disabled".to_string()));
        }

        info!("Executing dry-run analysis for {} operations", self.context.planned_operations.len());

        let mut files_affected = Vec::new();
        let mut space_required: u64 = 0;
        let mut total_time_ms: u64 = 0;

        for op in &self.context.planned_operations {
            if let Some(ref src) = op.source_path {
                files_affected.push(src.clone());
            }
            if let Some(ref tgt) = op.target_path {
                files_affected.push(tgt.clone());
            }

            match op.operation_type {
                OperationType::Recovery => {
                    space_required += op.size;
                }
                OperationType::Deletion | OperationType::Deduplication => {}
                OperationType::Modification => {
                    space_required += op.size;
                }
                OperationType::Scan => {}
            }

            total_time_ms += op.estimated_time_ms;
        }

        files_affected.sort();
        files_affected.dedup();

        let summary = self.generate_summary(
            self.context.planned_operations.len(),
            files_affected.len(),
            space_required,
            total_time_ms,
        );

        Ok(DryRunResult {
            operations_to_execute: self.context.planned_operations.clone(),
            files_affected,
            space_required,
            time_estimate: Duration::from_millis(total_time_ms),
            impact: self.context.estimated_impact.clone(),
            summary,
        })
    }

    pub fn apply_plan(self) -> Result<Vec<PlannedOperation>> {
        if !self.context.enabled {
            return Err(Error::Other("Dry-run mode is disabled".to_string()));
        }

        if self.context.planned_operations.is_empty() {
            warn!("apply_plan called with empty plan");
            return Ok(Vec::new());
        }

        info!(
            "Applying dry-run plan: {} operations ready for execution",
            self.context.planned_operations.len()
        );

        let mut validated = Vec::with_capacity(self.context.planned_operations.len());
        for op in &self.context.planned_operations {
            Self::validate_operation(op)?;
            validated.push(op.clone());
        }

        Ok(validated)
    }

    pub fn remove_operation(&mut self, operation_id: &str) -> Result<bool> {
        let initial_len = self.context.planned_operations.len();
        self.context.planned_operations.retain(|op| op.id != operation_id);
        let removed = self.context.planned_operations.len() < initial_len;

        if removed {
            self.recalculate_impact();
        }

        Ok(removed)
    }

    pub fn clear_plan(&mut self) {
        self.context.planned_operations.clear();
        self.recalculate_impact();
    }

    pub fn operation_count(&self) -> usize {
        self.context.planned_operations.len()
    }

    fn recalculate_impact(&mut self) {
        let mut risk_summary = RiskSummary::new();
        let mut breakdown = OperationBreakdown::default();
        let mut total_files: u64 = 0;
        let mut space_required: u64 = 0;
        let mut space_freed: u64 = 0;
        let mut total_time_ms: u64 = 0;
        let mut irreversible: u32 = 0;

        for op in &self.context.planned_operations {
            risk_summary.record(op.risk_level);
            total_files += 1;
            total_time_ms += op.estimated_time_ms;

            if !op.reversible {
                irreversible += 1;
            }

            match op.operation_type {
                OperationType::Recovery => {
                    breakdown.recovery_ops += 1;
                    space_required += op.size;
                }
                OperationType::Deletion => {
                    breakdown.deletion_ops += 1;
                    space_freed += op.size;
                }
                OperationType::Modification => {
                    breakdown.modification_ops += 1;
                }
                OperationType::Deduplication => {
                    breakdown.deduplication_ops += 1;
                    space_freed += op.size;
                }
                OperationType::Scan => {
                    breakdown.scan_ops += 1;
                }
            }
        }

        self.context.estimated_impact = ImpactEstimate {
            total_files_affected: total_files,
            total_space_required: space_required,
            total_space_freed: space_freed,
            estimated_time_ms: total_time_ms,
            risk_summary,
            irreversible_operations: irreversible,
            operation_breakdown: breakdown,
        };
    }

    fn validate_operation(op: &PlannedOperation) -> Result<()> {
        if op.description.is_empty() {
            return Err(Error::Other(format!(
                "Operation {} has empty description",
                op.id
            )));
        }

        if op.operation_type == OperationType::Recovery && op.target_path.is_none() {
            return Err(Error::Other(format!(
                "Recovery operation {} missing target path",
                op.id
            )));
        }

        if op.source_path.is_none() {
            return Err(Error::Other(format!(
                "Operation {} missing source path",
                op.id
            )));
        }

        Ok(())
    }

    fn estimate_recovery_time(size: u64) -> u64 {
        let bytes_per_ms = 10 * 1024 * 1024;
        std::cmp::max(1, size / bytes_per_ms)
    }

    fn generate_summary(
        &self,
        op_count: usize,
        file_count: usize,
        space_required: u64,
        time_ms: u64,
    ) -> String {
        let impact = &self.context.estimated_impact;
        format!(
            "Dry-run summary: {} operations affecting {} files, \
            space required: {} bytes, space freed: {} bytes, \
            estimated time: {}ms, irreversible ops: {}, max risk: {:?}",
            op_count,
            file_count,
            space_required,
            impact.total_space_freed,
            time_ms,
            impact.irreversible_operations,
            impact.risk_summary.max_risk(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_path(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn test_dry_run_executor_creation() {
        let executor = DryRunExecutor::new();
        assert!(executor.is_enabled());
        assert_eq!(executor.operation_count(), 0);
    }

    #[test]
    fn test_context_disabled_by_default_when_specified() {
        let ctx = DryRunContext::new(false);
        let executor = DryRunExecutor::with_context(ctx);
        assert!(!executor.is_enabled());
    }

    #[test]
    fn test_plan_operation() {
        let mut executor = DryRunExecutor::new();
        let op = PlannedOperation::new(
            OperationType::Recovery,
            OperationKind::RecoverFile,
            "Test recovery",
        )
        .with_source(test_path("/source/file.dat"))
        .with_target(test_path("/target/file.dat"))
        .with_size(1024);

        let result = executor.plan_operation(op);
        assert!(result.is_ok());
        assert_eq!(executor.operation_count(), 1);
    }

    #[test]
    fn test_plan_operation_disabled() {
        let mut executor = DryRunExecutor::new();
        executor.set_enabled(false);

        let op = PlannedOperation::new(
            OperationType::Recovery,
            OperationKind::RecoverFile,
            "Test",
        );

        let result = executor.plan_operation(op);
        assert!(result.is_err());
    }

    #[test]
    fn test_plan_recovery() {
        let mut executor = DryRunExecutor::new();
        let result = executor.plan_recovery(
            test_path("/dev/sda"),
            test_path("/output/recovered.dat"),
            1024 * 1024,
        );
        assert!(result.is_ok());
        assert_eq!(executor.operation_count(), 1);

        let op = &executor.context().planned_operations[0];
        assert_eq!(op.operation_type, OperationType::Recovery);
        assert_eq!(op.kind, OperationKind::RecoverFile);
        assert!(op.reversible);
        assert_eq!(op.risk_level, RiskLevel::Low);
        assert_eq!(op.size, 1024 * 1024);
    }

    #[test]
    fn test_plan_deletion() {
        let mut executor = DryRunExecutor::new();
        let result = executor.plan_deletion(test_path("/tmp/junk.dat"), 2048, false);
        assert!(result.is_ok());

        let op = &executor.context().planned_operations[0];
        assert_eq!(op.operation_type, OperationType::Deletion);
        assert_eq!(op.kind, OperationKind::DeleteFile);
        assert!(!op.reversible);
        assert_eq!(op.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_plan_secure_wipe() {
        let mut executor = DryRunExecutor::new();
        let result = executor.plan_deletion(test_path("/tmp/secret.dat"), 4096, true);
        assert!(result.is_ok());

        let op = &executor.context().planned_operations[0];
        assert_eq!(op.kind, OperationKind::SecureWipe);
        assert_eq!(op.risk_level, RiskLevel::Critical);
        assert!(!op.reversible);
    }

    #[test]
    fn test_plan_modification() {
        let mut executor = DryRunExecutor::new();
        let result = executor.plan_modification(
            OperationKind::RenameFile,
            test_path("/old/name.dat"),
            Some(test_path("/new/name.dat")),
            "Rename file",
        );
        assert!(result.is_ok());

        let op = &executor.context().planned_operations[0];
        assert_eq!(op.operation_type, OperationType::Modification);
        assert_eq!(op.kind, OperationKind::RenameFile);
        assert!(op.reversible);
    }

    #[test]
    fn test_plan_deduplication() {
        let mut executor = DryRunExecutor::new();
        let result = executor.plan_deduplication(test_path("/dup/file.dat"), 8192);
        assert!(result.is_ok());

        let op = &executor.context().planned_operations[0];
        assert_eq!(op.operation_type, OperationType::Deduplication);
        assert!(!op.reversible);
    }

    #[test]
    fn test_plan_scan() {
        let mut executor = DryRunExecutor::new();
        let result = executor.plan_scan(
            test_path("/scan/target"),
            OperationKind::ThreatScan,
            50000,
        );
        assert!(result.is_ok());

        let op = &executor.context().planned_operations[0];
        assert_eq!(op.operation_type, OperationType::Scan);
        assert_eq!(op.kind, OperationKind::ThreatScan);
    }

    #[test]
    fn test_execute_dry_run() {
        let mut executor = DryRunExecutor::new();

        executor
            .plan_recovery(
                test_path("/dev/sda"),
                test_path("/out/file1.dat"),
                1024,
            )
            .unwrap();
        executor
            .plan_deletion(test_path("/tmp/junk.dat"), 2048, false)
            .unwrap();
        executor.plan_deduplication(test_path("/dup/a.dat"), 512).unwrap();

        let result = executor.execute_dry_run();
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.total_operations(), 3);
        assert!(result.space_required > 0);
        assert!(!result.files_affected.is_empty());
        assert!(!result.summary.is_empty());
    }

    #[test]
    fn test_execute_dry_run_disabled() {
        let mut executor = DryRunExecutor::new();
        executor.set_enabled(false);
        let result = executor.execute_dry_run();
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_plan() {
        let mut executor = DryRunExecutor::new();

        executor
            .plan_recovery(
                test_path("/dev/sda"),
                test_path("/out/file.dat"),
                1024,
            )
            .unwrap();

        let operations = executor.apply_plan();
        assert!(operations.is_ok());
        assert_eq!(operations.unwrap().len(), 1);
    }

    #[test]
    fn test_apply_plan_empty() {
        let executor = DryRunExecutor::new();
        let operations = executor.apply_plan();
        assert!(operations.is_ok());
        assert!(operations.unwrap().is_empty());
    }

    #[test]
    fn test_apply_plan_disabled() {
        let mut executor = DryRunExecutor::new();
        executor.set_enabled(false);
        let result = executor.apply_plan();
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_plan_validates_operations() {
        let mut executor = DryRunExecutor::new();

        let op = PlannedOperation::new(
            OperationType::Recovery,
            OperationKind::RecoverFile,
            "Missing target",
        )
        .with_source(test_path("/source"));

        executor.plan_operation(op).unwrap();

        let result = executor.apply_plan();
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_operation() {
        let mut executor = DryRunExecutor::new();

        let id = executor
            .plan_deletion(test_path("/tmp/file.dat"), 1024, false)
            .unwrap();
        assert_eq!(executor.operation_count(), 1);

        let removed = executor.remove_operation(&id).unwrap();
        assert!(removed);
        assert_eq!(executor.operation_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_operation() {
        let mut executor = DryRunExecutor::new();
        let removed = executor.remove_operation("nonexistent-id").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_clear_plan() {
        let mut executor = DryRunExecutor::new();

        executor.plan_recovery(test_path("/src"), test_path("/tgt"), 100).unwrap();
        executor.plan_deletion(test_path("/tmp/x"), 200, false).unwrap();
        assert_eq!(executor.operation_count(), 2);

        executor.clear_plan();
        assert_eq!(executor.operation_count(), 0);
    }

    #[test]
    fn test_impact_recalculation() {
        let mut executor = DryRunExecutor::new();

        executor
            .plan_recovery(test_path("/src"), test_path("/tgt"), 1024)
            .unwrap();
        executor
            .plan_deletion(test_path("/tmp/x"), 2048, false)
            .unwrap();

        let impact = &executor.context().estimated_impact;
        assert_eq!(impact.total_files_affected, 2);
        assert_eq!(impact.total_space_required, 1024);
        assert_eq!(impact.total_space_freed, 2048);
        assert_eq!(impact.irreversible_operations, 1);
        assert_eq!(impact.operation_breakdown.recovery_ops, 1);
        assert_eq!(impact.operation_breakdown.deletion_ops, 1);
    }

    #[test]
    fn test_risk_summary() {
        let mut summary = RiskSummary::new();
        summary.record(RiskLevel::Low);
        summary.record(RiskLevel::Low);
        summary.record(RiskLevel::High);
        summary.record(RiskLevel::Critical);

        assert_eq!(summary.low, 2);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.total(), 4);
        assert_eq!(summary.max_risk(), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_summary_max_risk_levels() {
        let mut summary = RiskSummary::new();
        assert_eq!(summary.max_risk(), RiskLevel::Low);

        summary.record(RiskLevel::Medium);
        assert_eq!(summary.max_risk(), RiskLevel::Medium);

        summary.record(RiskLevel::High);
        assert_eq!(summary.max_risk(), RiskLevel::High);
    }

    #[test]
    fn test_dry_run_result_helpers() {
        let mut executor = DryRunExecutor::new();

        executor
            .plan_recovery(test_path("/src"), test_path("/tgt"), 1024)
            .unwrap();
        executor
            .plan_deletion(test_path("/tmp/x"), 2048, true)
            .unwrap();

        let result = executor.execute_dry_run().unwrap();
        assert!(result.has_critical_risk());
        assert!(result.has_irreversible_operations());
        assert_eq!(result.total_operations(), 2);
        assert!(result.unique_files_affected() > 0);
    }

    #[test]
    fn test_planned_operation_builder() {
        let op = PlannedOperation::new(
            OperationType::Modification,
            OperationKind::MoveFile,
            "Move file to new location",
        )
        .with_source(test_path("/old/path"))
        .with_target(test_path("/new/path"))
        .with_size(4096)
        .with_risk(RiskLevel::Medium)
        .with_reversible(true)
        .with_time_estimate(100);

        assert_eq!(op.operation_type, OperationType::Modification);
        assert_eq!(op.kind, OperationKind::MoveFile);
        assert_eq!(op.description, "Move file to new location");
        assert_eq!(op.source_path, Some(test_path("/old/path")));
        assert_eq!(op.target_path, Some(test_path("/new/path")));
        assert_eq!(op.size, 4096);
        assert_eq!(op.risk_level, RiskLevel::Medium);
        assert!(op.reversible);
        assert_eq!(op.estimated_time_ms, 100);
        assert!(!op.id.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let op = PlannedOperation::new(
            OperationType::Recovery,
            OperationKind::RecoverFile,
            "Test op",
        )
        .with_source(test_path("/src"))
        .with_target(test_path("/tgt"))
        .with_size(512);

        let json = serde_json::to_string(&op).unwrap();
        let deserialized: PlannedOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, op.id);
        assert_eq!(deserialized.description, "Test op");
        assert_eq!(deserialized.size, 512);
    }

    #[test]
    fn test_dry_run_result_serialization() {
        let mut executor = DryRunExecutor::new();
        executor
            .plan_recovery(test_path("/src"), test_path("/tgt"), 1024)
            .unwrap();

        let result = executor.execute_dry_run().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DryRunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_operations(), 1);
        assert_eq!(deserialized.space_required, 1024);
    }

    #[test]
    fn test_multiple_operations_same_file() {
        let mut executor = DryRunExecutor::new();

        executor
            .plan_scan(test_path("/file.dat"), OperationKind::ThreatScan, 100)
            .unwrap();
        executor
            .plan_scan(test_path("/file.dat"), OperationKind::IntegrityCheck, 100)
            .unwrap();

        let result = executor.execute_dry_run().unwrap();
        assert_eq!(result.total_operations(), 2);
        assert_eq!(result.unique_files_affected(), 1);
    }

    #[test]
    fn test_recovery_time_estimation() {
        let small = DryRunExecutor::estimate_recovery_time(1024);
        let large = DryRunExecutor::estimate_recovery_time(100 * 1024 * 1024);
        assert!(large > small);
        assert!(small >= 1);
    }
}
