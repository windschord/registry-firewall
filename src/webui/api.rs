//! Web UI API handlers
//!
//! This module provides REST API endpoints for the Web UI.
//! All endpoints require authentication unless otherwise noted.
//!
//! # Security Notes
//!
//! - Token values are never logged and only returned once at creation time
//! - Internal error details are logged but not exposed to clients
//! - All endpoints require authentication via the auth middleware
//! - Destructive operations log the action for audit purposes

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::database::Database;
use crate::models::{BlockLog, CustomRule, Token};
use crate::plugins::cache::traits::CachePlugin;
use crate::plugins::security::traits::SecuritySourcePlugin;
use crate::sync::ManualSyncHandle;

// =============================================================================
// Constants
// =============================================================================

/// Default number of items per page for pagination
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// Maximum number of items per page for pagination.
/// This limit prevents excessive database queries and memory usage.
pub const MAX_PAGE_LIMIT: u32 = 1000;

/// Maximum length for token names
pub const MAX_TOKEN_NAME_LENGTH: usize = 256;

/// Maximum length for rule patterns
pub const MAX_PATTERN_LENGTH: usize = 512;

/// Maximum length for reason text
pub const MAX_REASON_LENGTH: usize = 1024;

/// Number of characters to show in masked token prefix
pub const TOKEN_MASK_PREFIX_LENGTH: usize = 8;

// =============================================================================
// Request/Response Types
// =============================================================================

/// Dashboard statistics response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardStats {
    /// Total number of requests processed
    pub total_requests: u64,
    /// Total number of blocked requests
    pub blocked_requests: u64,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
    /// Number of security sources configured
    pub security_sources_count: usize,
    /// Number of blocked packages
    pub blocked_packages_count: u64,
    /// List of security source summaries
    pub security_sources: Vec<SecuritySourceSummary>,
}

impl Default for DashboardStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            blocked_requests: 0,
            cache_hit_rate: 0.0,
            security_sources_count: 0,
            blocked_packages_count: 0,
            security_sources: vec![],
        }
    }
}

/// Security source summary for dashboard
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecuritySourceSummary {
    /// Source name
    pub name: String,
    /// Supported ecosystems
    pub ecosystems: Vec<String>,
    /// Last sync time
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    /// Current status
    pub status: String,
    /// Number of records
    pub records_count: u64,
}

/// Block logs query parameters
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BlockLogsQuery {
    /// Number of logs to return (default: 50)
    pub limit: Option<u32>,
    /// Offset for pagination (default: 0)
    pub offset: Option<u32>,
}

/// Block logs response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockLogsResponse {
    /// Block log entries
    pub logs: Vec<BlockLogEntry>,
    /// Total count of block logs
    pub total: u64,
}

/// Block log entry for API response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockLogEntry {
    /// Log ID
    pub id: Option<i64>,
    /// Package ecosystem
    pub ecosystem: String,
    /// Package name
    pub package: String,
    /// Package version
    pub version: String,
    /// Block source
    pub source: String,
    /// Block reason
    pub reason: Option<String>,
    /// Client IP
    pub client_ip: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl From<BlockLog> for BlockLogEntry {
    fn from(log: BlockLog) -> Self {
        Self {
            id: log.id,
            ecosystem: log.ecosystem,
            package: log.package,
            version: log.version,
            source: log.source,
            reason: log.reason,
            client_ip: log.client_ip,
            timestamp: log.timestamp,
        }
    }
}

/// Security sources response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecuritySourcesResponse {
    /// List of security sources
    pub sources: Vec<SecuritySourceInfo>,
}

/// Security source information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecuritySourceInfo {
    /// Source name
    pub name: String,
    /// Supported ecosystems
    pub ecosystems: Vec<String>,
    /// Last sync time
    pub last_sync: Option<chrono::DateTime<chrono::Utc>>,
    /// Current status
    pub status: String,
    /// Number of records
    pub records_count: u64,
}

/// Sync trigger response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncTriggerResponse {
    /// Response message
    pub message: String,
    /// Whether the sync was successful
    pub success: bool,
    /// Number of records updated (if sync completed)
    pub records_updated: Option<u64>,
}

/// Cache statistics response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheStatsResponse {
    /// Cache plugin name
    pub plugin: String,
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Total cache size in bytes
    pub total_size_bytes: u64,
    /// Number of cache entries
    pub entries: u64,
}

/// Cache clear response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheClearResponse {
    /// Response message
    pub message: String,
}

/// Rules list response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulesResponse {
    /// List of custom rules
    pub rules: Vec<CustomRule>,
}

/// Token list response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokensResponse {
    /// List of tokens (without hashes)
    pub tokens: Vec<TokenInfo>,
}

/// Token information (safe to return - never exposes full token value)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenInfo {
    /// Token ID
    pub id: String,
    /// Token name
    pub name: String,
    /// Masked token prefix for identification (e.g., "rf_abc1***")
    pub token_prefix: String,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Expires at
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last used at
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Allowed ecosystems
    pub allowed_ecosystems: Vec<String>,
}

impl From<&Token> for TokenInfo {
    fn from(token: &Token) -> Self {
        // Create masked token prefix from ID (tokens start with rf_)
        let prefix = format!(
            "rf_{}***",
            &token.id[..TOKEN_MASK_PREFIX_LENGTH.min(token.id.len())]
        );
        Self {
            id: token.id.clone(),
            name: token.name.clone(),
            token_prefix: prefix,
            created_at: token.created_at,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
            allowed_ecosystems: token.allowed_ecosystems.clone(),
        }
    }
}

/// Create token request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTokenRequest {
    /// Token name
    pub name: String,
    /// Allowed ecosystems
    pub allowed_ecosystems: Option<Vec<String>>,
    /// Expiration time
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Create token response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CreateTokenResponse {
    /// Token ID
    pub id: String,
    /// Token name
    pub name: String,
    /// The actual token (only returned once)
    pub token: String,
    /// Created at
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Expires at
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Generic message response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageResponse {
    /// Response message
    pub message: String,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

// =============================================================================
// API Functions
// =============================================================================

/// Build dashboard statistics from application state
pub async fn build_dashboard_stats<D: Database>(
    database: &D,
    security_plugins: &[Arc<dyn SecuritySourcePlugin>],
    cache_plugin: &Option<Arc<dyn CachePlugin>>,
) -> DashboardStats {
    // Get block logs count for blocked_requests
    let blocked_requests = database.get_block_logs_count().await.unwrap_or(0);

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

    DashboardStats {
        total_requests,
        blocked_requests,
        cache_hit_rate,
        security_sources_count: security_plugins.len(),
        blocked_packages_count,
        security_sources,
    }
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

    // Test 1: DashboardStats default values
    #[test]
    fn test_dashboard_stats_default() {
        let stats = DashboardStats::default();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.blocked_requests, 0);
        assert_eq!(stats.cache_hit_rate, 0.0);
        assert_eq!(stats.security_sources_count, 0);
        assert_eq!(stats.blocked_packages_count, 0);
        assert!(stats.security_sources.is_empty());
    }

    // Test 2: BlockLogEntry from BlockLog conversion
    #[test]
    fn test_block_log_entry_from_block_log() {
        let log = BlockLog::new("pypi", "malicious-pkg", "1.0.0", "osv");
        let entry = BlockLogEntry::from(log.clone());

        assert_eq!(entry.ecosystem, "pypi");
        assert_eq!(entry.package, "malicious-pkg");
        assert_eq!(entry.version, "1.0.0");
        assert_eq!(entry.source, "osv");
    }

    // Test 3: TokenInfo from Token conversion
    #[test]
    fn test_token_info_from_token() {
        let token = Token::new("test-id", "test-token", "hash123");
        let info = TokenInfo::from(&token);

        assert_eq!(info.id, "test-id");
        assert_eq!(info.name, "test-token");
    }

    // Test 4: Build dashboard stats with no plugins
    #[tokio::test]
    async fn test_build_dashboard_stats_empty() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_get_block_logs_count().returning(|| Ok(0));

        let stats = build_dashboard_stats(&mock_db, &[], &None::<Arc<dyn CachePlugin>>).await;

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
        let stats = build_dashboard_stats(&mock_db, &plugins, &None::<Arc<dyn CachePlugin>>).await;

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
        let stats = build_dashboard_stats(&mock_db, &[], &cache).await;

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

    // Test 13: DashboardStats serialization
    #[test]
    fn test_dashboard_stats_serialization() {
        let stats = DashboardStats {
            total_requests: 100,
            blocked_requests: 5,
            cache_hit_rate: 0.8,
            security_sources_count: 2,
            blocked_packages_count: 50,
            security_sources: vec![],
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: DashboardStats = serde_json::from_str(&json).unwrap();

        assert_eq!(stats, deserialized);
    }

    // Test 14: BlockLogsResponse serialization
    #[test]
    fn test_block_logs_response_serialization() {
        let response = BlockLogsResponse {
            logs: vec![BlockLogEntry {
                id: Some(1),
                ecosystem: "pypi".to_string(),
                package: "malicious".to_string(),
                version: "1.0.0".to_string(),
                source: "osv".to_string(),
                reason: Some("CVE-2024-1234".to_string()),
                client_ip: Some("192.168.1.1".to_string()),
                timestamp: Utc::now(),
            }],
            total: 1,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("pypi"));
        assert!(json.contains("malicious"));
    }

    // Test 15: CacheStatsResponse serialization
    #[test]
    fn test_cache_stats_response_serialization() {
        let response = CacheStatsResponse {
            plugin: "filesystem".to_string(),
            hits: 100,
            misses: 50,
            total_size_bytes: 1024,
            entries: 10,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: CacheStatsResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response, deserialized);
    }

    // Test 16: CreateTokenRequest deserialization
    #[test]
    fn test_create_token_request_deserialization() {
        let json = r#"{"name": "test-token", "allowed_ecosystems": ["pypi", "cargo"]}"#;
        let request: CreateTokenRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.name, "test-token");
        assert_eq!(
            request.allowed_ecosystems,
            Some(vec!["pypi".to_string(), "cargo".to_string()])
        );
        assert!(request.expires_at.is_none());
    }
}
