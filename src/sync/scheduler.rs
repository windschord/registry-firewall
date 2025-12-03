//! Sync scheduler for automatic security source synchronization
//!
//! This module provides a scheduler that periodically triggers
//! synchronization of security data sources with configurable
//! intervals and jitter to prevent thundering herd effects.

use crate::error::SyncError;
use async_trait::async_trait;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::{interval_at, Instant};
use tracing::{debug, error, info, warn};

/// Configuration for the sync scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Initial delay before first sync (seconds) - for startup load distribution
    pub initial_delay_secs: u64,
    /// Jitter range (seconds) - randomization added to sync intervals
    pub jitter_secs: u64,
    /// Sync operation timeout (seconds)
    pub sync_timeout_secs: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            initial_delay_secs: 5,
            jitter_secs: 60,
            sync_timeout_secs: 300,
        }
    }
}

/// Result of a sync operation
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncResult {
    /// Number of records updated
    pub records_updated: u64,
    /// Whether the sync was skipped (e.g., data not modified)
    pub skipped: bool,
}

/// Status of a sync operation
#[derive(Debug, Clone, Default)]
pub struct SyncStatus {
    /// Last successful sync time
    pub last_sync: Option<std::time::SystemTime>,
    /// Last sync result
    pub last_result: Option<Result<SyncResult, String>>,
    /// Next scheduled sync time
    pub next_sync: Option<std::time::SystemTime>,
    /// Whether sync is currently in progress
    pub in_progress: bool,
}

/// Trait for syncable sources
///
/// Any security source plugin that can be synchronized should implement this trait.
#[async_trait]
pub trait Syncable: Send + Sync {
    /// Get the name of this source
    fn name(&self) -> &str;

    /// Get the sync interval for this source
    fn sync_interval(&self) -> Duration;

    /// Perform synchronization
    async fn sync(&self) -> Result<SyncResult, SyncError>;
}

/// Manual sync request
struct ManualSyncRequest {
    source_name: String,
    response: mpsc::Sender<Result<SyncResult, SyncError>>,
}

/// Sync scheduler for security sources
///
/// Manages periodic synchronization of multiple security data sources
/// with configurable intervals and jitter.
pub struct SyncScheduler {
    config: SchedulerConfig,
    sources: Vec<Arc<dyn Syncable>>,
    status: Arc<RwLock<HashMap<String, SyncStatus>>>,
    shutdown_rx: broadcast::Receiver<()>,
    manual_sync_rx: mpsc::Receiver<ManualSyncRequest>,
    manual_sync_tx: mpsc::Sender<ManualSyncRequest>,
}

impl SyncScheduler {
    /// Create a new sync scheduler
    ///
    /// # Arguments
    ///
    /// * `config` - Scheduler configuration
    /// * `sources` - List of syncable sources to manage
    /// * `shutdown_rx` - Broadcast receiver for shutdown signal
    pub fn new(
        config: SchedulerConfig,
        sources: Vec<Arc<dyn Syncable>>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        let (manual_sync_tx, manual_sync_rx) = mpsc::channel(32);

        let status = sources
            .iter()
            .map(|s| (s.name().to_string(), SyncStatus::default()))
            .collect();

        Self {
            config,
            sources,
            status: Arc::new(RwLock::new(status)),
            shutdown_rx,
            manual_sync_rx,
            manual_sync_tx,
        }
    }

    /// Get a handle for triggering manual syncs
    pub fn manual_sync_handle(&self) -> ManualSyncHandle {
        ManualSyncHandle {
            tx: self.manual_sync_tx.clone(),
        }
    }

    /// Get the current sync status for all sources
    pub async fn get_status(&self) -> HashMap<String, SyncStatus> {
        self.status.read().await.clone()
    }

    /// Run the scheduler
    ///
    /// This will start background tasks for each source and handle
    /// shutdown gracefully when signaled.
    pub async fn run(mut self) {
        info!(sources = self.sources.len(), "Starting sync scheduler");

        // Initial delay before starting any syncs
        if self.config.initial_delay_secs > 0 {
            debug!(
                delay_secs = self.config.initial_delay_secs,
                "Waiting for initial delay"
            );
            tokio::time::sleep(Duration::from_secs(self.config.initial_delay_secs)).await;
        }

        // Spawn sync tasks for each source
        let mut handles = Vec::new();
        let (task_shutdown_tx, _) = broadcast::channel::<()>(1);

        for source in &self.sources {
            let source_clone = source.clone();
            let status = self.status.clone();
            let config = self.config.clone();
            let task_shutdown_rx = task_shutdown_tx.subscribe();

            let handle = tokio::spawn(async move {
                Self::run_source_sync(source_clone, status, config, task_shutdown_rx).await;
            });
            handles.push(handle);
        }

        // Handle shutdown signal and manual sync requests
        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping sync scheduler");
                    let _ = task_shutdown_tx.send(());
                    break;
                }
                Some(request) = self.manual_sync_rx.recv() => {
                    self.handle_manual_sync(request).await;
                }
            }
        }

        // Wait for all sync tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        info!("Sync scheduler stopped");
    }

    async fn run_source_sync(
        source: Arc<dyn Syncable>,
        status: Arc<RwLock<HashMap<String, SyncStatus>>>,
        config: SchedulerConfig,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let name = source.name().to_string();
        let interval = source.sync_interval();

        // Perform initial sync
        info!(source = name, "Performing initial sync");
        Self::perform_sync(&source, &status, &config).await;

        // Calculate next sync time with jitter
        let jitter = if config.jitter_secs > 0 {
            rand::thread_rng().gen_range(0..config.jitter_secs)
        } else {
            0
        };
        let next_sync = Instant::now() + interval + Duration::from_secs(jitter);

        debug!(
            source = name,
            interval_secs = interval.as_secs(),
            jitter_secs = jitter,
            "Scheduled next sync"
        );

        let mut interval_timer = interval_at(next_sync, interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    debug!(source = name, "Sync task shutting down");
                    break;
                }
                _ = interval_timer.tick() => {
                    // Add jitter to prevent all sources syncing at once
                    let jitter = if config.jitter_secs > 0 {
                        rand::thread_rng().gen_range(0..config.jitter_secs)
                    } else {
                        0
                    };
                    if jitter > 0 {
                        tokio::time::sleep(Duration::from_secs(jitter)).await;
                    }

                    info!(source = name, "Performing scheduled sync");
                    Self::perform_sync(&source, &status, &config).await;
                }
            }
        }
    }

    async fn perform_sync(
        source: &Arc<dyn Syncable>,
        status: &Arc<RwLock<HashMap<String, SyncStatus>>>,
        config: &SchedulerConfig,
    ) {
        let name = source.name().to_string();

        // Mark as in progress
        {
            let mut status_map = status.write().await;
            if let Some(s) = status_map.get_mut(&name) {
                s.in_progress = true;
            }
        }

        // Perform sync with timeout
        let result =
            tokio::time::timeout(Duration::from_secs(config.sync_timeout_secs), source.sync())
                .await;

        // Update status
        let mut status_map = status.write().await;
        if let Some(s) = status_map.get_mut(&name) {
            s.in_progress = false;
            s.last_sync = Some(std::time::SystemTime::now());

            match result {
                Ok(Ok(sync_result)) => {
                    if sync_result.skipped {
                        debug!(source = name, "Sync skipped (data unchanged)");
                    } else {
                        info!(
                            source = name,
                            records = sync_result.records_updated,
                            "Sync completed"
                        );
                    }
                    s.last_result = Some(Ok(sync_result));
                }
                Ok(Err(err)) => {
                    warn!(source = name, error = %err, "Sync failed");
                    s.last_result = Some(Err(err.to_string()));
                }
                Err(_) => {
                    error!(
                        source = name,
                        timeout_secs = config.sync_timeout_secs,
                        "Sync timed out"
                    );
                    s.last_result = Some(Err("Sync timed out".to_string()));
                }
            }

            // Update next sync time estimate
            s.next_sync = Some(std::time::SystemTime::now() + source.sync_interval());
        }
    }

    async fn handle_manual_sync(&self, request: ManualSyncRequest) {
        let source = self
            .sources
            .iter()
            .find(|s| s.name() == request.source_name);

        match source {
            Some(source) => {
                info!(source = request.source_name, "Manual sync triggered");
                Self::perform_sync(source, &self.status, &self.config).await;

                // Get the result from status
                let status_map = self.status.read().await;
                if let Some(status) = status_map.get(&request.source_name) {
                    let result = match &status.last_result {
                        Some(Ok(r)) => Ok(r.clone()),
                        Some(Err(e)) => Err(SyncError::Network(e.clone())),
                        None => Err(SyncError::Network("No result available".to_string())),
                    };
                    let _ = request.response.send(result).await;
                }
            }
            None => {
                warn!(
                    source = request.source_name,
                    "Manual sync requested for unknown source"
                );
                let _ = request.response.send(Err(SyncError::NotFound)).await;
            }
        }
    }
}

/// Handle for triggering manual syncs
#[derive(Clone)]
pub struct ManualSyncHandle {
    tx: mpsc::Sender<ManualSyncRequest>,
}

impl ManualSyncHandle {
    /// Trigger a manual sync for the specified source
    pub async fn trigger_sync(&self, source_name: &str) -> Result<SyncResult, SyncError> {
        let (response_tx, mut response_rx) = mpsc::channel(1);

        self.tx
            .send(ManualSyncRequest {
                source_name: source_name.to_string(),
                response: response_tx,
            })
            .await
            .map_err(|_| SyncError::Network("Scheduler not running".to_string()))?;

        response_rx
            .recv()
            .await
            .ok_or_else(|| SyncError::Network("No response from scheduler".to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::time::timeout;

    /// Test implementation of `Syncable` for testing scheduler behavior.
    ///
    /// This struct tracks sync invocations via an atomic counter and returns
    /// configurable results. Used to verify:
    /// - Sync calls are made at expected intervals
    /// - Error handling works correctly
    /// - Multiple sources sync independently
    ///
    /// # Example
    ///
    /// ```ignore
    /// let source = TestSource::new("test", 3600);
    /// let sync_count = source.sync_count();
    ///
    /// // After scheduler runs...
    /// assert_eq!(sync_count.load(Ordering::SeqCst), 1);
    /// ```
    struct TestSource {
        /// Name identifier for this source
        name: String,
        /// Interval between sync operations
        interval: Duration,
        /// Counter tracking number of sync() calls
        sync_count: Arc<AtomicU32>,
        /// Configurable result to return from sync()
        sync_result: Arc<RwLock<Result<SyncResult, SyncError>>>,
    }

    impl TestSource {
        /// Create a new test source with given name and interval
        fn new(name: &str, interval_secs: u64) -> Self {
            Self {
                name: name.to_string(),
                interval: Duration::from_secs(interval_secs),
                sync_count: Arc::new(AtomicU32::new(0)),
                sync_result: Arc::new(RwLock::new(Ok(SyncResult::default()))),
            }
        }

        /// Configure the result that sync() will return
        fn with_result(mut self, result: Result<SyncResult, SyncError>) -> Self {
            self.sync_result = Arc::new(RwLock::new(result));
            self
        }

        /// Get a handle to the sync counter for assertions
        fn sync_count(&self) -> Arc<AtomicU32> {
            self.sync_count.clone()
        }
    }

    #[async_trait]
    impl Syncable for TestSource {
        fn name(&self) -> &str {
            &self.name
        }

        fn sync_interval(&self) -> Duration {
            self.interval
        }

        async fn sync(&self) -> Result<SyncResult, SyncError> {
            self.sync_count.fetch_add(1, Ordering::SeqCst);
            self.sync_result.read().await.clone()
        }
    }

    /// Slow test source that simulates long sync times
    struct SlowTestSource {
        name: String,
        delay: Duration,
    }

    impl SlowTestSource {
        fn new(name: &str, delay_secs: u64) -> Self {
            Self {
                name: name.to_string(),
                delay: Duration::from_secs(delay_secs),
            }
        }
    }

    #[async_trait]
    impl Syncable for SlowTestSource {
        fn name(&self) -> &str {
            &self.name
        }

        fn sync_interval(&self) -> Duration {
            Duration::from_secs(3600)
        }

        async fn sync(&self) -> Result<SyncResult, SyncError> {
            tokio::time::sleep(self.delay).await;
            Ok(SyncResult::default())
        }
    }

    // Test 1: Scheduler runs initial sync on startup
    #[tokio::test]
    async fn test_initial_sync_on_startup() {
        let source = TestSource::new("test", 3600);
        let sync_count = source.sync_count();

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let handle = tokio::spawn(scheduler.run());

        // Wait a bit for initial sync
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Shutdown
        shutdown_tx.send(()).unwrap();
        let _ = timeout(Duration::from_secs(1), handle).await;

        assert_eq!(sync_count.load(Ordering::SeqCst), 1);
    }

    // Test 2: Scheduler respects sync interval
    #[tokio::test]
    async fn test_sync_interval() {
        tokio::time::pause();

        let source = TestSource::new("test", 100); // 100 second interval
        let sync_count = source.sync_count();

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 60,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let handle = tokio::spawn(scheduler.run());

        // Advance time past initial sync
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;

        // Initial sync should have happened
        assert_eq!(sync_count.load(Ordering::SeqCst), 1);

        // Advance time past interval
        tokio::time::advance(Duration::from_secs(101)).await;
        tokio::task::yield_now().await;

        // Should have done second sync
        assert_eq!(sync_count.load(Ordering::SeqCst), 2);

        shutdown_tx.send(()).unwrap();
        let _ = handle.await;
    }

    // Test 3: Graceful shutdown stops scheduler
    #[tokio::test]
    async fn test_graceful_shutdown() {
        let source = TestSource::new("test", 3600);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let handle = tokio::spawn(scheduler.run());

        // Let it start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send shutdown
        shutdown_tx.send(()).unwrap();

        // Should complete within timeout
        let result = timeout(Duration::from_secs(2), handle).await;
        assert!(result.is_ok());
    }

    // Test 4: Manual sync trigger works
    #[tokio::test]
    async fn test_manual_sync_trigger() {
        let source = TestSource::new("test_source", 3600).with_result(Ok(SyncResult {
            records_updated: 42,
            skipped: false,
        }));
        let sync_count = source.sync_count();

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let manual_handle = scheduler.manual_sync_handle();
        let scheduler_handle = tokio::spawn(scheduler.run());

        // Wait for initial sync
        tokio::time::sleep(Duration::from_millis(100)).await;
        let initial_count = sync_count.load(Ordering::SeqCst);

        // Trigger manual sync
        let result = manual_handle.trigger_sync("test_source").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().records_updated, 42);

        // Should have synced again
        assert_eq!(sync_count.load(Ordering::SeqCst), initial_count + 1);

        shutdown_tx.send(()).unwrap();
        let _ = scheduler_handle.await;
    }

    // Test 5: Manual sync for unknown source returns error
    #[tokio::test]
    async fn test_manual_sync_unknown_source() {
        let source = TestSource::new("known_source", 3600);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let manual_handle = scheduler.manual_sync_handle();
        let scheduler_handle = tokio::spawn(scheduler.run());

        // Wait for scheduler to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Try to sync unknown source
        let result = manual_handle.trigger_sync("unknown_source").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncError::NotFound));

        shutdown_tx.send(()).unwrap();
        let _ = scheduler_handle.await;
    }

    // Test 6: Status tracking
    #[tokio::test]
    async fn test_status_tracking() {
        let source = TestSource::new("tracked_source", 3600).with_result(Ok(SyncResult {
            records_updated: 10,
            skipped: false,
        }));

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let status_ref = scheduler.status.clone();
        let scheduler_handle = tokio::spawn(scheduler.run());

        // Wait for initial sync to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check status
        let status = status_ref.read().await;
        let source_status = status.get("tracked_source").unwrap();

        assert!(source_status.last_sync.is_some());
        assert!(!source_status.in_progress);
        assert_eq!(
            source_status.last_result,
            Some(Ok(SyncResult {
                records_updated: 10,
                skipped: false,
            }))
        );

        shutdown_tx.send(()).unwrap();
        let _ = scheduler_handle.await;
    }

    // Test 7: Sync timeout handling
    #[tokio::test]
    async fn test_sync_timeout() {
        let source = SlowTestSource::new("slow_source", 10);

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 1, // 1 second timeout
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let status_ref = scheduler.status.clone();
        let scheduler_handle = tokio::spawn(scheduler.run());

        // Wait for sync attempt and timeout
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Check status shows error
        let status = status_ref.read().await;
        let source_status = status.get("slow_source").unwrap();

        assert!(matches!(
            &source_status.last_result,
            Some(Err(msg)) if msg.contains("timed out")
        ));

        shutdown_tx.send(()).unwrap();
        let _ = scheduler_handle.await;
    }

    // Test 8: Multiple sources sync independently
    #[tokio::test]
    async fn test_multiple_sources() {
        let source1 = TestSource::new("source1", 3600);
        let source1_count = source1.sync_count();

        let source2 = TestSource::new("source2", 3600);
        let source2_count = source2.sync_count();

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0,
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source1), Arc::new(source2)],
            shutdown_rx,
        );

        let handle = tokio::spawn(scheduler.run());

        // Wait for initial syncs
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Both sources should have synced
        assert_eq!(source1_count.load(Ordering::SeqCst), 1);
        assert_eq!(source2_count.load(Ordering::SeqCst), 1);

        shutdown_tx.send(()).unwrap();
        let _ = handle.await;
    }

    // Test 9: Default config values
    #[test]
    fn test_default_scheduler_config() {
        let config = SchedulerConfig::default();

        assert_eq!(config.initial_delay_secs, 5);
        assert_eq!(config.jitter_secs, 60);
        assert_eq!(config.sync_timeout_secs, 300);
    }

    // Test 10: Sync result default
    #[test]
    fn test_sync_result_default() {
        let result = SyncResult::default();

        assert_eq!(result.records_updated, 0);
        assert!(!result.skipped);
    }

    // Test 11: Initial delay is respected
    #[tokio::test]
    async fn test_initial_delay() {
        let source = TestSource::new("test", 3600);
        let sync_count = source.sync_count();

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let scheduler = SyncScheduler::new(
            SchedulerConfig {
                initial_delay_secs: 0, // No delay for this test
                jitter_secs: 0,
                sync_timeout_secs: 10,
            },
            vec![Arc::new(source)],
            shutdown_rx,
        );

        let handle = tokio::spawn(scheduler.run());

        // Wait for initial sync to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Sync should have happened
        assert_eq!(sync_count.load(Ordering::SeqCst), 1);

        shutdown_tx.send(()).unwrap();
        let _ = handle.await;
    }

    // Test 12: Initial delay configuration
    #[test]
    fn test_initial_delay_config() {
        let config = SchedulerConfig {
            initial_delay_secs: 30,
            jitter_secs: 10,
            sync_timeout_secs: 60,
        };

        assert_eq!(config.initial_delay_secs, 30);
        assert_eq!(config.jitter_secs, 10);
        assert_eq!(config.sync_timeout_secs, 60);
    }
}
