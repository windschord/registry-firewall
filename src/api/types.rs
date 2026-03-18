//! API type definitions
//!
//! This module contains request/response types and constants for the REST API.

use serde::{Deserialize, Serialize};

use crate::models::{BlockLog, Token};

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
    pub rules: Vec<crate::models::CustomRule>,
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
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::BlockLog;
    use crate::models::Token;
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
