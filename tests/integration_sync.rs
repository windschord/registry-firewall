//! Sync functionality integration tests
//!
//! Tests the synchronization system including:
//! - Scheduler startup and shutdown
//! - Manual sync triggering
//! - Status tracking

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use registry_firewall::error::SyncError;
use registry_firewall::sync::scheduler::{SchedulerConfig, SyncResult, SyncScheduler, Syncable};
use tokio::sync::broadcast;

/// Test syncable source for testing
struct TestSyncSource {
    name: String,
    interval: Duration,
    sync_count: Arc<AtomicU32>,
}

impl TestSyncSource {
    fn new(name: &str, interval_secs: u64) -> Self {
        Self {
            name: name.to_string(),
            interval: Duration::from_secs(interval_secs),
            sync_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn sync_count(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.sync_count)
    }
}

#[async_trait]
impl Syncable for TestSyncSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn sync_interval(&self) -> Duration {
        self.interval
    }

    async fn sync(&self) -> Result<SyncResult, SyncError> {
        self.sync_count.fetch_add(1, Ordering::SeqCst);
        Ok(SyncResult {
            records_updated: 100,
            skipped: false,
        })
    }
}

/// Test 1: Scheduler runs initial sync on startup
#[tokio::test]
async fn test_scheduler_initial_sync() {
    let source = TestSyncSource::new("test", 3600);
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

    // Wait for initial sync
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Shutdown
    shutdown_tx.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;

    assert_eq!(sync_count.load(Ordering::SeqCst), 1);
}

/// Test 2: Scheduler handles multiple sources
#[tokio::test]
async fn test_scheduler_multiple_sources() {
    let source1 = TestSyncSource::new("source1", 3600);
    let source1_count = source1.sync_count();

    let source2 = TestSyncSource::new("source2", 3600);
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

    // Shutdown
    shutdown_tx.send(()).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;

    // Both sources should have synced
    assert_eq!(source1_count.load(Ordering::SeqCst), 1);
    assert_eq!(source2_count.load(Ordering::SeqCst), 1);
}

/// Test 3: Manual sync trigger works
#[tokio::test]
async fn test_manual_sync() {
    let source = TestSyncSource::new("manual_source", 3600);
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
    let result = manual_handle.trigger_sync("manual_source").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().records_updated, 100);

    // Should have synced again
    assert_eq!(sync_count.load(Ordering::SeqCst), initial_count + 1);

    shutdown_tx.send(()).unwrap();
    let _ = scheduler_handle.await;
}

/// Test 4: Manual sync for unknown source returns error
#[tokio::test]
async fn test_manual_sync_unknown_source() {
    let source = TestSyncSource::new("known_source", 3600);

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

/// Test 5: Graceful shutdown stops scheduler
#[tokio::test]
async fn test_graceful_shutdown() {
    let source = TestSyncSource::new("test", 3600);

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
    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok());
}

/// Test 6: Status tracking
#[tokio::test]
async fn test_status_tracking() {
    let source = TestSyncSource::new("tracked_source", 3600);

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

    let status_handle = scheduler.manual_sync_handle();
    let scheduler_handle = tokio::spawn(scheduler.run());

    // Wait for initial sync
    tokio::time::sleep(Duration::from_millis(200)).await;

    // We can't directly access status from outside, but we can verify
    // the sync completed by triggering another and checking result
    let result = status_handle.trigger_sync("tracked_source").await;
    assert!(result.is_ok());

    shutdown_tx.send(()).unwrap();
    let _ = scheduler_handle.await;
}

/// Test 7: SyncResult default values
#[test]
fn test_sync_result_default() {
    let result = SyncResult::default();
    assert_eq!(result.records_updated, 0);
    assert!(!result.skipped);
}

/// Test 8: SchedulerConfig default values
#[test]
fn test_scheduler_config_default() {
    let config = SchedulerConfig::default();
    assert_eq!(config.initial_delay_secs, 5);
    assert_eq!(config.jitter_secs, 60);
    assert_eq!(config.sync_timeout_secs, 300);
}
