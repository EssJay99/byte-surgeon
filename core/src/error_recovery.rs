use crate::error::Error;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult<T> {
    pub success_items: Vec<T>,
    pub failed_items: Vec<String>,
    pub partial_results: Vec<T>,
    pub error_log: Vec<ErrorEntry>,
}

impl<T> RecoveryResult<T> {
    pub fn new() -> Self {
        Self {
            success_items: Vec::new(),
            failed_items: Vec::new(),
            partial_results: Vec::new(),
            error_log: Vec::new(),
        }
    }

    pub fn total_attempted(&self) -> usize {
        self.success_items.len() + self.failed_items.len()
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_attempted();
        if total == 0 {
            return 0.0;
        }
        self.success_items.len() as f64 / total as f64
    }

    pub fn has_failures(&self) -> bool {
        !self.failed_items.is_empty()
    }
}

impl<T> Default for RecoveryResult<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorRecoveryStrategy {
    Skip,
    Retry,
    Abort,
    BestEffort,
}

impl fmt::Display for ErrorRecoveryStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Skip => write!(f, "Skip"),
            Self::Retry => write!(f, "Retry"),
            Self::Abort => write!(f, "Abort"),
            Self::BestEffort => write!(f, "BestEffort"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEntry {
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub error_message: String,
    pub retry_attempt: usize,
}

impl ErrorEntry {
    pub fn new(operation: &str, error: &Error, retry_attempt: usize) -> Self {
        Self {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            error_message: error.to_string(),
            retry_attempt,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryContext {
    pub current_operation: String,
    pub retry_count: usize,
    pub max_retries: usize,
    pub strategy: ErrorRecoveryStrategy,
    pub base_delay: Duration,
}

impl RecoveryContext {
    pub fn new(operation: &str, strategy: ErrorRecoveryStrategy) -> Self {
        Self {
            current_operation: operation.to_string(),
            retry_count: 0,
            max_retries: 3,
            strategy,
            base_delay: Duration::from_millis(100),
        }
    }

    pub fn with_strategy(mut self, strategy: ErrorRecoveryStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_base_delay(mut self, base_delay: Duration) -> Self {
        self.base_delay = base_delay;
        self
    }

    pub fn backoff_duration(&self) -> Duration {
        self.base_delay.mul_f64(2.0f64.powi(self.retry_count as i32))
    }
}

#[derive(Debug)]
pub struct ErrorRecovery {
    context: RecoveryContext,
}

impl ErrorRecovery {
    pub fn new(context: RecoveryContext) -> Self {
        Self { context }
    }

    pub fn with_strategy(strategy: ErrorRecoveryStrategy) -> Self {
        Self {
            context: RecoveryContext::new("default", strategy),
        }
    }

    pub fn execute_with_recovery<T, F>(
        &mut self,
        operation: &str,
        mut items: Vec<String>,
        mut process_fn: F,
    ) -> RecoveryResult<T>
    where
        F: FnMut(&str) -> std::result::Result<T, Error>,
    {
        let mut result = RecoveryResult::new();
        self.context.current_operation = operation.to_string();

        info!(
            "Starting operation '{}' with strategy={}, items={}",
            operation,
            self.context.strategy,
            items.len()
        );

        let mut aborted = false;

        while let Some(item) = items.pop() {
            self.context.retry_count = 0;

            loop {
                match process_fn(&item) {
                    Ok(value) => {
                        if self.context.retry_count > 0 {
                            info!(
                                "Item '{}' succeeded after {} retries",
                                item, self.context.retry_count
                            );
                        }
                        result.success_items.push(value);
                        break;
                    }
                    Err(e) => {
                        let entry = ErrorEntry::new(operation, &e, self.context.retry_count);
                        result.error_log.push(entry);

                        match self.context.strategy {
                            ErrorRecoveryStrategy::Abort => {
                                warn!(
                                    "Abort strategy: stopping after error on '{}'",
                                    item
                                );
                                result.failed_items.push(item);
                                aborted = true;
                                break;
                            }
                            ErrorRecoveryStrategy::Retry => {
                                if self.context.retry_count < self.context.max_retries {
                                    let delay = self.context.backoff_duration();
                                    info!(
                                        "Retry {}/{} for '{}' after {:?}",
                                        self.context.retry_count + 1,
                                        self.context.max_retries,
                                        item,
                                        delay
                                    );
                                    std::thread::sleep(delay);
                                    self.context.retry_count += 1;
                                    continue;
                                }
                                warn!(
                                    "Item '{}' failed after {} retries",
                                    item, self.context.max_retries
                                );
                                result.failed_items.push(item);
                                break;
                            }
                            ErrorRecoveryStrategy::Skip => {
                                warn!("Skipping failed item '{}': {}", item, e);
                                result.failed_items.push(item);
                                break;
                            }
                            ErrorRecoveryStrategy::BestEffort => {
                                warn!("Best-effort: recording failure for '{}'", item);
                                result.failed_items.push(item);
                                break;
                            }
                        }
                    }
                }
            }

            if aborted {
                for remaining in items {
                    result.failed_items.push(remaining);
                }
                break;
            }
        }

        info!(
            "Operation '{}' complete: {} succeeded, {} failed, {} errors logged",
            operation,
            result.success_items.len(),
            result.failed_items.len(),
            result.error_log.len()
        );

        result
    }

    pub fn get_partial_results<'a, T>(result: &'a RecoveryResult<T>) -> Vec<&'a T> {
        result.partial_results.iter().collect()
    }

    pub fn export_error_log<T>(result: &RecoveryResult<T>) -> String {
        serde_json::to_string_pretty(&result.error_log).unwrap_or_else(|_| "[]".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn make_error(msg: &str) -> Error {
        Error::RecoveryFailed(msg.to_string())
    }

    #[test]
    fn test_recovery_result_default() {
        let result: RecoveryResult<i32> = RecoveryResult::new();
        assert!(result.success_items.is_empty());
        assert!(result.failed_items.is_empty());
        assert!(result.partial_results.is_empty());
        assert!(result.error_log.is_empty());
        assert_eq!(result.success_rate(), 0.0);
        assert!(!result.has_failures());
    }

    #[test]
    fn test_recovery_result_success_rate() {
        let mut result = RecoveryResult::<i32>::new();
        result.success_items.push(1);
        result.success_items.push(2);
        result.success_items.push(3);
        result.failed_items.push("a".to_string());
        assert_eq!(result.total_attempted(), 4);
        assert!((result.success_rate() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_strategy_display() {
        assert_eq!(ErrorRecoveryStrategy::Skip.to_string(), "Skip");
        assert_eq!(ErrorRecoveryStrategy::Retry.to_string(), "Retry");
        assert_eq!(ErrorRecoveryStrategy::Abort.to_string(), "Abort");
        assert_eq!(ErrorRecoveryStrategy::BestEffort.to_string(), "BestEffort");
    }

    #[test]
    fn test_recovery_context_builder() {
        let ctx = RecoveryContext::new("op", ErrorRecoveryStrategy::Skip)
            .with_max_retries(5)
            .with_base_delay(Duration::from_millis(50));
        assert_eq!(ctx.current_operation, "op");
        assert_eq!(ctx.max_retries, 5);
        assert_eq!(ctx.base_delay, Duration::from_millis(50));
        assert_eq!(ctx.strategy, ErrorRecoveryStrategy::Skip);
    }

    #[test]
    fn test_backoff_exponential() {
        let mut ctx = RecoveryContext::new("op", ErrorRecoveryStrategy::Retry)
            .with_base_delay(Duration::from_millis(100));
        assert_eq!(ctx.backoff_duration(), Duration::from_millis(100));
        ctx.retry_count = 1;
        assert_eq!(ctx.backoff_duration(), Duration::from_millis(200));
        ctx.retry_count = 2;
        assert_eq!(ctx.backoff_duration(), Duration::from_millis(400));
        ctx.retry_count = 3;
        assert_eq!(ctx.backoff_duration(), Duration::from_millis(800));
    }

    #[test]
    fn test_all_succeed() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::Skip);
        let mut recovery = ErrorRecovery::new(ctx);
        let items = vec!["a".into(), "b".into(), "c".into()];
        let result = recovery.execute_with_recovery("test", items, |item| {
            Ok(format!("done-{}", item))
        });
        assert_eq!(result.success_items.len(), 3);
        assert!(result.failed_items.is_empty());
        assert!(result.error_log.is_empty());
        assert_eq!(result.success_rate(), 1.0);
    }

    #[test]
    fn test_skip_strategy_continues_on_failure() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::Skip);
        let mut recovery = ErrorRecovery::new(ctx);
        let items = vec!["a".into(), "b".into(), "c".into()];
        let result = recovery.execute_with_recovery("test", items, |item| {
            if item == "b" {
                Err(make_error("b failed"))
            } else {
                Ok(format!("done-{}", item))
            }
        });
        assert_eq!(result.success_items.len(), 2);
        assert_eq!(result.failed_items.len(), 1);
        assert_eq!(result.failed_items[0], "b");
        assert_eq!(result.error_log.len(), 1);
    }

    #[test]
    fn test_abort_strategy_stops_immediately() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::Abort);
        let mut recovery = ErrorRecovery::new(ctx);
        let items = vec!["a".into(), "b".into(), "c".into()];
        let result = recovery.execute_with_recovery("test", items, |item| {
            if item == "b" {
                Err(make_error("b failed"))
            } else {
                Ok(format!("done-{}", item))
            }
        });
        assert_eq!(result.success_items.len(), 1);
        assert!(result.failed_items.len() >= 1);
        assert!(result.failed_items.contains(&"b".to_string()));
    }

    #[test]
    fn test_retry_strategy_succeeds_after_failures() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::Retry)
            .with_max_retries(3)
            .with_base_delay(Duration::from_millis(1));
        let mut recovery = ErrorRecovery::new(ctx);
        let items = vec!["a".into()];
        let attempt = Arc::new(AtomicUsize::new(0));
        let attempt_clone = attempt.clone();
        let result = recovery.execute_with_recovery("test", items, move |_item| {
            let n = attempt_clone.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err(make_error("transient"))
            } else {
                Ok("recovered".to_string())
            }
        });
        assert_eq!(result.success_items.len(), 1);
        assert_eq!(result.success_items[0], "recovered");
        assert!(result.failed_items.is_empty());
        assert_eq!(result.error_log.len(), 2);
    }

    #[test]
    fn test_retry_strategy_exhausts_retries() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::Retry)
            .with_max_retries(2)
            .with_base_delay(Duration::from_millis(1));
        let mut recovery = ErrorRecovery::new(ctx);
        let items = vec!["a".into()];
        let result: RecoveryResult<String> = recovery.execute_with_recovery("test", items, |_| {
            Err::<String, _>(make_error("always fails"))
        });
        assert!(result.success_items.is_empty());
        assert_eq!(result.failed_items.len(), 1);
        assert_eq!(result.error_log.len(), 3);
    }

    #[test]
    fn test_best_effort_collects_all() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::BestEffort);
        let mut recovery = ErrorRecovery::new(ctx);
        let items = vec!["a".into(), "b".into(), "c".into()];
        let result = recovery.execute_with_recovery("test", items, |item| {
            if item == "b" {
                Err(make_error("b failed"))
            } else {
                Ok(format!("done-{}", item))
            }
        });
        assert_eq!(result.success_items.len(), 2);
        assert_eq!(result.failed_items.len(), 1);
    }

    #[test]
    fn test_get_partial_results() {
        let mut result = RecoveryResult::new();
        result.partial_results.push(10);
        result.partial_results.push(20);
        let partials = ErrorRecovery::get_partial_results(&result);
        assert_eq!(partials.len(), 2);
        assert_eq!(*partials[0], 10);
        assert_eq!(*partials[1], 20);
    }

    #[test]
    fn test_export_error_log() {
        let mut result: RecoveryResult<i32> = RecoveryResult::new();
        let err = make_error("test error");
        result.error_log.push(ErrorEntry::new("op", &err, 0));
        let json = ErrorRecovery::export_error_log(&result);
        assert!(json.contains("test error"));
        assert!(json.contains("op"));
    }

    #[test]
    fn test_export_error_log_empty() {
        let result: RecoveryResult<i32> = RecoveryResult::new();
        let json = ErrorRecovery::export_error_log(&result);
        assert_eq!(json, "[]");
    }

    #[test]
    fn test_with_strategy_constructor() {
        let recovery = ErrorRecovery::with_strategy(ErrorRecoveryStrategy::BestEffort);
        assert_eq!(recovery.context.strategy, ErrorRecoveryStrategy::BestEffort);
    }

    #[test]
    fn test_error_entry_fields() {
        let err = make_error("something broke");
        let entry = ErrorEntry::new("my_op", &err, 2);
        assert_eq!(entry.operation, "my_op");
        assert_eq!(entry.retry_attempt, 2);
        assert!(entry.error_message.contains("something broke"));
    }

    #[test]
    fn test_empty_items_succeeds() {
        let ctx = RecoveryContext::new("test", ErrorRecoveryStrategy::Retry)
            .with_base_delay(Duration::from_millis(1));
        let mut recovery = ErrorRecovery::new(ctx);
        let items: Vec<String> = vec![];
        let result: RecoveryResult<String> = recovery.execute_with_recovery("test", items, |_| {
            Err::<String, _>(make_error("should not run"))
        });
        assert!(result.success_items.is_empty());
        assert!(result.failed_items.is_empty());
        assert!(result.error_log.is_empty());
    }

    #[test]
    fn test_has_failures() {
        let mut result: RecoveryResult<i32> = RecoveryResult::new();
        assert!(!result.has_failures());
        result.failed_items.push("x".to_string());
        assert!(result.has_failures());
    }
}
