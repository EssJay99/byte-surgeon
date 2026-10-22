use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, error};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryJob {
    pub id: String,
    pub name: String,
    pub device_path: String,
    pub output_dir: String,
    pub scan_type: String,
    pub priority: i32,
    pub dependencies: Vec<String>,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub files_found: usize,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReport {
    pub batch_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub cancelled_jobs: usize,
    pub pending_jobs: usize,
    pub total_files_found: usize,
    pub job_summaries: Vec<JobSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSummary {
    pub job_id: String,
    pub job_name: String,
    pub status: JobStatus,
    pub files_found: usize,
    pub duration_seconds: Option<i64>,
}

pub struct BatchQueue {
    jobs: Arc<RwLock<HashMap<String, RecoveryJob>>>,
    running_jobs: Arc<Mutex<Vec<String>>>,
    execution_mode: ExecutionMode,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionMode {
    Sequential,
    Parallel { max_concurrent: usize },
}

impl BatchQueue {
    pub fn new(execution_mode: ExecutionMode) -> Self {
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            running_jobs: Arc::new(Mutex::new(Vec::new())),
            execution_mode,
        }
    }

    pub async fn add_job(&self, mut job: RecoveryJob) -> Result<String> {
        let job_id = job.id.clone();
        
        for dep in &job.dependencies {
            let jobs = self.jobs.read().await;
            if !jobs.contains_key(dep) {
                anyhow::bail!("Dependency not found: {}", dep);
            }
        }
        
        job.status = JobStatus::Pending;
        job.created_at = Utc::now();
        
        let mut jobs = self.jobs.write().await;
        jobs.insert(job_id.clone(), job);
        
        info!("Added job to batch queue: {}", job_id);
        Ok(job_id)
    }

    pub async fn start_batch(&self) -> Result<()> {
        info!("Starting batch execution");
        
        match self.execution_mode {
            ExecutionMode::Sequential => {
                self.execute_sequential().await?;
            }
            ExecutionMode::Parallel { max_concurrent } => {
                self.execute_parallel(max_concurrent).await?;
            }
        }
        
        Ok(())
    }

    async fn execute_sequential(&self) -> Result<()> {
        let job_ids = self.get_execution_order().await?;
        
        for job_id in job_ids {
            if let Err(e) = self.execute_job(&job_id).await {
                error!("Job {} failed: {}", job_id, e);
            }
        }
        
        Ok(())
    }

    async fn execute_parallel(&self, max_concurrent: usize) -> Result<()> {
        let job_ids = self.get_execution_order().await?;
        let mut handles = Vec::new();
        
        for job_id in job_ids {
            while self.running_jobs.lock().await.len() >= max_concurrent {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            
            let jobs_clone = Arc::clone(&self.jobs);
            let running_clone = Arc::clone(&self.running_jobs);
            
            let handle = tokio::spawn(async move {
                running_clone.lock().await.push(job_id.clone());
                
                let result = Self::run_job(jobs_clone, &job_id).await;
                
                running_clone.lock().await.retain(|id| id != &job_id);
                result
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            let _ = handle.await;
        }
        
        Ok(())
    }

    async fn get_execution_order(&self) -> Result<Vec<String>> {
        let jobs = self.jobs.read().await;
        let mut order = Vec::new();
        let mut visited = HashMap::new();
        
        for job_id in jobs.keys() {
            self.topological_sort(job_id, &jobs, &mut visited, &mut order)?;
        }
        
        Ok(order)
    }

    fn topological_sort(
        &self,
        job_id: &str,
        jobs: &HashMap<String, RecoveryJob>,
        visited: &mut HashMap<String, bool>,
        order: &mut Vec<String>,
    ) -> Result<()> {
        if visited.contains_key(job_id) {
            return Ok(());
        }
        
        visited.insert(job_id.to_string(), true);
        
        if let Some(job) = jobs.get(job_id) {
            for dep in &job.dependencies {
                self.topological_sort(dep, jobs, visited, order)?;
            }
            order.push(job_id.to_string());
        }
        
        Ok(())
    }

    async fn execute_job(&self, job_id: &str) -> Result<()> {
        Self::run_job(Arc::clone(&self.jobs), job_id).await
    }

    async fn run_job(jobs: Arc<RwLock<HashMap<String, RecoveryJob>>>, job_id: &str) -> Result<()> {
        {
            let mut jobs = jobs.write().await;
            if let Some(job) = jobs.get_mut(job_id) {
                if job.status == JobStatus::Cancelled {
                    return Ok(());
                }
                job.status = JobStatus::Running;
                job.started_at = Some(Utc::now());
            }
        }
        
        let result = Self::simulate_job_execution().await;
        
        let mut jobs = jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            match result {
                Ok(files_found) => {
                    job.status = JobStatus::Completed;
                    job.completed_at = Some(Utc::now());
                    job.files_found = files_found;
                    info!("Job {} completed: {} files found", job_id, files_found);
                }
                Err(e) => {
                    job.status = JobStatus::Failed;
                    job.completed_at = Some(Utc::now());
                    job.error_message = Some(e.to_string());
                    error!("Job {} failed: {}", job_id, e);
                }
            }
        }
        
        Ok(())
    }

    async fn simulate_job_execution() -> Result<usize> {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(42)
    }

    pub async fn get_job_status(&self, job_id: &str) -> Result<JobStatus> {
        let jobs = self.jobs.read().await;
        jobs.get(job_id)
            .map(|j| j.status.clone())
            .ok_or_else(|| anyhow::anyhow!("Job not found: {}", job_id))
    }

    pub async fn cancel_job(&self, job_id: &str) -> Result<()> {
        let mut jobs = self.jobs.write().await;
        if let Some(job) = jobs.get_mut(job_id) {
            if job.status == JobStatus::Pending || job.status == JobStatus::Running {
                job.status = JobStatus::Cancelled;
                job.completed_at = Some(Utc::now());
                info!("Cancelled job: {}", job_id);
            }
        }
        Ok(())
    }

    pub async fn generate_report(&self) -> Result<BatchReport> {
        let jobs = self.jobs.read().await;
        
        let mut report = BatchReport {
            batch_id: uuid::Uuid::new_v4().to_string(),
            started_at: Utc::now(),
            completed_at: None,
            total_jobs: jobs.len(),
            completed_jobs: 0,
            failed_jobs: 0,
            cancelled_jobs: 0,
            pending_jobs: 0,
            total_files_found: 0,
            job_summaries: Vec::new(),
        };
        
        for job in jobs.values() {
            match job.status {
                JobStatus::Completed => report.completed_jobs += 1,
                JobStatus::Failed => report.failed_jobs += 1,
                JobStatus::Cancelled => report.cancelled_jobs += 1,
                JobStatus::Pending => report.pending_jobs += 1,
                JobStatus::Running => {},
            }
            
            report.total_files_found += job.files_found;
            
            let duration = if let (Some(start), Some(end)) = (job.started_at, job.completed_at) {
                Some((end - start).num_seconds())
            } else {
                None
            };
            
            report.job_summaries.push(JobSummary {
                job_id: job.id.clone(),
                job_name: job.name.clone(),
                status: job.status.clone(),
                files_found: job.files_found,
                duration_seconds: duration,
            });
        }
        
        if report.completed_jobs + report.failed_jobs + report.cancelled_jobs == report.total_jobs {
            report.completed_at = Some(Utc::now());
        }
        
        Ok(report)
    }

    pub async fn get_all_jobs(&self) -> Result<Vec<RecoveryJob>> {
        let jobs = self.jobs.read().await;
        Ok(jobs.values().cloned().collect())
    }
}

impl RecoveryJob {
    pub fn new(
        name: String,
        device_path: String,
        output_dir: String,
        scan_type: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            device_path,
            output_dir,
            scan_type,
            priority: 0,
            dependencies: Vec::new(),
            status: JobStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            files_found: 0,
            error_message: None,
        }
    }

    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_dependencies(mut self, dependencies: Vec<String>) -> Self {
        self.dependencies = dependencies;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_job() -> Result<()> {
        let queue = BatchQueue::new(ExecutionMode::Sequential);
        
        let job = RecoveryJob::new(
            "Test Job".to_string(),
            "/dev/sda".to_string(),
            "/output".to_string(),
            "deep".to_string(),
        );
        
        let job_id = queue.add_job(job).await?;
        let status = queue.get_job_status(&job_id).await?;
        
        assert_eq!(status, JobStatus::Pending);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_cancel_job() -> Result<()> {
        let queue = BatchQueue::new(ExecutionMode::Sequential);
        
        let job = RecoveryJob::new(
            "Test Job".to_string(),
            "/dev/sda".to_string(),
            "/output".to_string(),
            "deep".to_string(),
        );
        
        let job_id = queue.add_job(job).await?;
        queue.cancel_job(&job_id).await?;
        
        let status = queue.get_job_status(&job_id).await?;
        assert_eq!(status, JobStatus::Cancelled);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_report() -> Result<()> {
        let queue = BatchQueue::new(ExecutionMode::Sequential);
        
        let job1 = RecoveryJob::new(
            "Job 1".to_string(),
            "/dev/sda".to_string(),
            "/output1".to_string(),
            "deep".to_string(),
        );
        
        let job2 = RecoveryJob::new(
            "Job 2".to_string(),
            "/dev/sdb".to_string(),
            "/output2".to_string(),
            "quick".to_string(),
        );
        
        queue.add_job(job1).await?;
        queue.add_job(job2).await?;
        
        let report = queue.generate_report().await?;
        assert_eq!(report.total_jobs, 2);
        assert_eq!(report.pending_jobs, 2);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_job_with_priority() {
        let job = RecoveryJob::new(
            "Test".to_string(),
            "/dev/sda".to_string(),
            "/output".to_string(),
            "deep".to_string(),
        ).with_priority(10);
        
        assert_eq!(job.priority, 10);
    }

    #[tokio::test]
    async fn test_job_with_dependencies() -> Result<()> {
        let queue = BatchQueue::new(ExecutionMode::Sequential);
        
        let job1 = RecoveryJob::new(
            "Job 1".to_string(),
            "/dev/sda".to_string(),
            "/output1".to_string(),
            "deep".to_string(),
        );
        
        let job1_id = queue.add_job(job1).await?;
        
        let job2 = RecoveryJob::new(
            "Job 2".to_string(),
            "/dev/sdb".to_string(),
            "/output2".to_string(),
            "quick".to_string(),
        ).with_dependencies(vec![job1_id.clone()]);
        
        queue.add_job(job2).await?;
        
        Ok(())
    }

    #[tokio::test]
    async fn test_get_all_jobs() -> Result<()> {
        let queue = BatchQueue::new(ExecutionMode::Sequential);
        
        let job1 = RecoveryJob::new(
            "Job 1".to_string(),
            "/dev/sda".to_string(),
            "/output1".to_string(),
            "deep".to_string(),
        );
        
        let job2 = RecoveryJob::new(
            "Job 2".to_string(),
            "/dev/sdb".to_string(),
            "/output2".to_string(),
            "quick".to_string(),
        );
        
        queue.add_job(job1).await?;
        queue.add_job(job2).await?;
        
        let jobs = queue.get_all_jobs().await?;
        assert_eq!(jobs.len(), 2);
        
        Ok(())
    }
}
