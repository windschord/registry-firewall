//! API handler functions
//!
//! This module contains business logic functions for the REST API endpoints.

use std::sync::Arc;

use crate::database::Database;
use crate::plugins::cache::traits::CachePlugin;
use crate::plugins::security::traits::SecuritySourcePlugin;
use crate::sync::ManualSyncHandle;

use super::types::{
    BlockLogEntry, BlockLogsResponse, CacheStatsResponse, DashboardStats, SecuritySourceInfo,
    SecuritySourceSummary, SecuritySourcesResponse, SyncTriggerResponse,
};

// =============================================================================
// API Functions
// =============================================================================

/// Build dashboard statistics from application state
pub async fn build_dashboard_stats<D: Database>(
    database: &D,
    security_plugins: &[Arc<dyn SecuritySourcePlugin>],
    cache_plugin: &Option<Arc<dyn CachePlugin>>,
) -> Result<DashboardStats, String> {
    // Get block logs count for blocked_requests
    let blocked_requests = database
        .get_block_logs_count()
        .await
        .map_err(|e| e.to_string())?;

    // Get cache stats if available
    let (cache_hit_rate, total_requests) = if let Some(cache) = cache_plugin {
        let stats = cache.stats().await;
        let total = stats.hits + stats.misses;
        let hit_rate = if total > 0 {
            stats.hits as f64 / total as f64
        } else {
            0.0
        };
        (hit_rate, total)
    } else {
        (0.0, 0)
    };

    // Build security source summaries
    let security_sources: Vec<SecuritySourceSummary> = security_plugins
        .iter()
        .map(|p| {
            let status = p.sync_status();
            SecuritySourceSummary {
                name: p.name().to_string(),
                ecosystems: p.supported_ecosystems().to_vec(),
                last_sync: status.last_sync_at,
                status: status.status.to_string(),
                records_count: status.records_count,
            }
        })
        .collect();

    // Calculate total blocked packages
    let blocked_packages_count: u64 = security_sources.iter().map(|s| s.records_count).sum();

    Ok(DashboardStats {
        total_requests,
        blocked_requests,
        cache_hit_rate,
        security_sources_count: security_plugins.len(),
        blocked_packages_count,
        security_sources,
    })
}

/// Get block logs from database
pub async fn get_block_logs<D: Database>(
    database: &D,
    limit: u32,
    offset: u32,
) -> Result<BlockLogsResponse, String> {
    let logs = database
        .get_block_logs(limit, offset)
        .await
        .map_err(|e| e.to_string())?;

    let total = database
        .get_block_logs_count()
        .await
        .map_err(|e| e.to_string())?;

    Ok(BlockLogsResponse {
        logs: logs.into_iter().map(BlockLogEntry::from).collect(),
        total,
    })
}

/// Build security sources response
pub fn build_security_sources_response(
    security_plugins: &[Arc<dyn SecuritySourcePlugin>],
) -> SecuritySourcesResponse {
    let sources: Vec<SecuritySourceInfo> = security_plugins
        .iter()
        .map(|p| {
            let status = p.sync_status();
            SecuritySourceInfo {
                name: p.name().to_string(),
                ecosystems: p.supported_ecosystems().to_vec(),
                last_sync: status.last_sync_at,
                status: status.status.to_string(),
                records_count: status.records_count,
            }
        })
        .collect();

    SecuritySourcesResponse { sources }
}

/// Trigger sync for a security source
pub async fn trigger_sync(
    sync_handle: &ManualSyncHandle,
    source_name: &str,
) -> SyncTriggerResponse {
    match sync_handle.trigger_sync(source_name).await {
        Ok(result) => SyncTriggerResponse {
            message: format!("Sync completed for {}", source_name),
            success: true,
            records_updated: Some(result.records_updated),
        },
        Err(e) => SyncTriggerResponse {
            message: format!("Sync failed for {}: {}", source_name, e),
            success: false,
            records_updated: None,
        },
    }
}

/// Get cache statistics
pub async fn get_cache_stats(cache_plugin: &Option<Arc<dyn CachePlugin>>) -> CacheStatsResponse {
    if let Some(cache) = cache_plugin {
        let stats = cache.stats().await;
        CacheStatsResponse {
            plugin: cache.name().to_string(),
            hits: stats.hits,
            misses: stats.misses,
            total_size_bytes: stats.total_size_bytes,
            entries: stats.entries,
        }
    } else {
        CacheStatsResponse {
            plugin: "none".to_string(),
            hits: 0,
            misses: 0,
            total_size_bytes: 0,
            entries: 0,
        }
    }
}

/// Clear cache
pub async fn clear_cache(cache_plugin: &Option<Arc<dyn CachePlugin>>) -> Result<(), String> {
    if let Some(cache) = cache_plugin {
        cache.purge().await.map_err(|e| e.to_string())
    } else {
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::MockDatabase;
    use crate::models::SyncStatus;
    use crate::models::{BlockLog, SyncStatusValue};
    use crate::plugins::cache::traits::MockCachePlugin;
    use crate::plugins::cache::CacheStats;
    use crate::plugins::security::traits::MockSecuritySourcePlugin;
    use chrono::Utc;

    // Test 4: Build dashboard stats with no plugins
    #[tokio::test]
    async fn test_build_dashboard_stats_empty() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_get_block_logs_count().returning(|| Ok(0));

        let stats = build_dashboard_stats(&mock_db, &[], &None::<Arc<dyn CachePlugin>>)
            .await
            .unwrap();

        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.blocked_requests, 0);
        assert_eq!(stats.security_sources_count, 0);
    }

    // Test 5: Build dashboard stats with security plugins
    #[tokio::test]
    async fn test_build_dashboard_stats_with_security_plugins() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_get_block_logs_count().returning(|| Ok(42));

        let mut mock_plugin = MockSecuritySourcePlugin::new();
        mock_plugin.expect_name().return_const("osv".to_string());
        mock_plugin
            .expect_supported_ecosystems()
            .return_const(vec!["pypi".to_string()]);
        mock_plugin.expect_sync_status().return_const(SyncStatus {
            source: "osv".to_string(),
            last_sync_at: Some(Utc::now()),
            status: SyncStatusValue::Success,
            records_count: 100,
            error_message: None,
        });

        let plugins: Vec<Arc<dyn SecuritySourcePlugin>> = vec![Arc::new(mock_plugin)];
        let stats = build_dashboard_stats(&mock_db, &plugins, &None::<Arc<dyn CachePlugin>>)
            .await
            .unwrap();

        assert_eq!(stats.blocked_requests, 42);
        assert_eq!(stats.security_sources_count, 1);
        assert_eq!(stats.blocked_packages_count, 100);
        assert_eq!(stats.security_sources.len(), 1);
        assert_eq!(stats.security_sources[0].name, "osv");
    }

    // Test 6: Build dashboard stats with cache plugin
    #[tokio::test]
    async fn test_build_dashboard_stats_with_cache() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_get_block_logs_count().returning(|| Ok(0));

        let mut mock_cache = MockCachePlugin::new();
        mock_cache.expect_stats().returning(|| CacheStats {
            hits: 80,
            misses: 20,
            total_size_bytes: 1024,
            entries: 10,
            evictions: 0,
        });

        let cache: Option<Arc<dyn CachePlugin>> = Some(Arc::new(mock_cache));
        let stats = build_dashboard_stats(&mock_db, &[], &cache).await.unwrap();

        assert_eq!(stats.total_requests, 100);
        assert!((stats.cache_hit_rate - 0.8).abs() < 0.001);
    }

    // Test 7: Get block logs
    #[tokio::test]
    async fn test_get_block_logs() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_get_block_logs().returning(|_, _| {
            Ok(vec![
                BlockLog::new("pypi", "pkg1", "1.0.0", "osv"),
                BlockLog::new("cargo", "pkg2", "2.0.0", "openssf"),
            ])
        });
        mock_db.expect_get_block_logs_count().returning(|| Ok(2));

        let result = get_block_logs(&mock_db, 10, 0).await.unwrap();

        assert_eq!(result.logs.len(), 2);
        assert_eq!(result.total, 2);
        assert_eq!(result.logs[0].ecosystem, "pypi");
        assert_eq!(result.logs[1].ecosystem, "cargo");
    }

    // Test 8: Build security sources response
    #[test]
    fn test_build_security_sources_response() {
        let mut mock_plugin = MockSecuritySourcePlugin::new();
        mock_plugin.expect_name().return_const("osv".to_string());
        mock_plugin
            .expect_supported_ecosystems()
            .return_const(vec!["pypi".to_string(), "cargo".to_string()]);
        mock_plugin.expect_sync_status().return_const(SyncStatus {
            source: "osv".to_string(),
            last_sync_at: None,
            status: SyncStatusValue::Pending,
            records_count: 0,
            error_message: None,
        });

        let plugins: Vec<Arc<dyn SecuritySourcePlugin>> = vec![Arc::new(mock_plugin)];
        let response = build_security_sources_response(&plugins);

        assert_eq!(response.sources.len(), 1);
        assert_eq!(response.sources[0].name, "osv");
        assert_eq!(response.sources[0].ecosystems.len(), 2);
        assert_eq!(response.sources[0].status, "pending");
    }

    // Test 9: Get cache stats with plugin
    #[tokio::test]
    async fn test_get_cache_stats_with_plugin() {
        let mut mock_cache = MockCachePlugin::new();
        mock_cache
            .expect_name()
            .return_const("filesystem".to_string());
        mock_cache.expect_stats().returning(|| CacheStats {
            hits: 100,
            misses: 50,
            total_size_bytes: 2048,
            entries: 25,
            evictions: 0,
        });

        let cache: Option<Arc<dyn CachePlugin>> = Some(Arc::new(mock_cache));
        let stats = get_cache_stats(&cache).await;

        assert_eq!(stats.plugin, "filesystem");
        assert_eq!(stats.hits, 100);
        assert_eq!(stats.misses, 50);
        assert_eq!(stats.total_size_bytes, 2048);
        assert_eq!(stats.entries, 25);
    }

    // Test 10: Get cache stats without plugin
    #[tokio::test]
    async fn test_get_cache_stats_no_plugin() {
        let cache: Option<Arc<dyn CachePlugin>> = None;
        let stats = get_cache_stats(&cache).await;

        assert_eq!(stats.plugin, "none");
        assert_eq!(stats.hits, 0);
    }

    // Test 11: Clear cache with plugin
    #[tokio::test]
    async fn test_clear_cache_with_plugin() {
        let mut mock_cache = MockCachePlugin::new();
        mock_cache.expect_purge().returning(|| Ok(()));

        let cache: Option<Arc<dyn CachePlugin>> = Some(Arc::new(mock_cache));
        let result = clear_cache(&cache).await;

        assert!(result.is_ok());
    }

    // Test 12: Clear cache without plugin
    #[tokio::test]
    async fn test_clear_cache_no_plugin() {
        let cache: Option<Arc<dyn CachePlugin>> = None;
        let result = clear_cache(&cache).await;

        assert!(result.is_ok());
    }
}
