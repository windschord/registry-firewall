//! Database layer for registry-firewall
//!
//! This module defines the database trait and SQLite implementation.

pub mod migrations;
pub mod sqlite;

pub use sqlite::SqliteDatabase;

use async_trait::async_trait;

use crate::error::DbError;
use crate::models::{BlockLog, BlockReason, BlockedPackage, CustomRule, SyncStatus, Token};

/// Database trait for data persistence
///
/// This trait defines all database operations needed by the application.
/// It uses `async_trait` for async methods and `mockall::automock` for testing.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Database: Send + Sync {
    // =========================================================================
    // Blocked packages operations
    // =========================================================================

    /// Insert a blocked package record
    async fn insert_blocked_package(&self, pkg: &BlockedPackage) -> Result<(), DbError>;

    /// Get all blocked packages for an ecosystem
    async fn get_blocked_packages(&self, ecosystem: &str) -> Result<Vec<BlockedPackage>, DbError>;

    /// Check if a specific package version is blocked
    ///
    /// Returns the block reason if blocked, None otherwise
    async fn is_blocked(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<BlockReason>, DbError>;

    /// Clear all blocked packages from a specific source
    ///
    /// Returns the number of deleted records
    async fn clear_blocked_by_source(&self, source: &str) -> Result<u64, DbError>;

    // =========================================================================
    // Sync status operations
    // =========================================================================

    /// Update sync status for a security source
    async fn update_sync_status(&self, status: &SyncStatus) -> Result<(), DbError>;

    /// Get sync status for a security source
    async fn get_sync_status(&self, source: &str) -> Result<Option<SyncStatus>, DbError>;

    /// Get all sync statuses
    async fn get_all_sync_statuses(&self) -> Result<Vec<SyncStatus>, DbError>;

    // =========================================================================
    // Token operations
    // =========================================================================

    /// Create a new API token
    async fn create_token(&self, token: &Token) -> Result<(), DbError>;

    /// Get a token by its hash
    async fn get_token_by_hash(&self, hash: &str) -> Result<Option<Token>, DbError>;

    /// Revoke a token by its ID
    async fn revoke_token(&self, id: &str) -> Result<(), DbError>;

    /// List all tokens (excluding revoked)
    async fn list_tokens(&self) -> Result<Vec<Token>, DbError>;

    /// Update token's last used timestamp
    async fn update_token_last_used(&self, id: &str) -> Result<(), DbError>;

    // =========================================================================
    // Block log operations
    // =========================================================================

    /// Insert a block log entry
    async fn insert_block_log(&self, log: &BlockLog) -> Result<(), DbError>;

    /// Get block logs with pagination
    async fn get_block_logs(&self, limit: u32, offset: u32) -> Result<Vec<BlockLog>, DbError>;

    /// Get total count of block logs
    async fn get_block_logs_count(&self) -> Result<u64, DbError>;

    // =========================================================================
    // Custom rules operations
    // =========================================================================

    /// Insert a custom block rule
    ///
    /// Returns the ID of the inserted rule
    async fn insert_rule(&self, rule: &CustomRule) -> Result<i64, DbError>;

    /// Update an existing custom rule
    async fn update_rule(&self, rule: &CustomRule) -> Result<(), DbError>;

    /// Delete a custom rule by ID
    async fn delete_rule(&self, id: i64) -> Result<(), DbError>;

    /// List all custom rules
    async fn list_rules(&self) -> Result<Vec<CustomRule>, DbError>;

    /// Get a custom rule by ID
    async fn get_rule(&self, id: i64) -> Result<Option<CustomRule>, DbError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Severity, SyncStatusValue};

    // Test 1: MockDatabase can be created and used
    #[tokio::test]
    async fn test_mock_database_is_blocked() {
        let mut mock = MockDatabase::new();

        mock.expect_is_blocked()
            .withf(|eco, pkg, ver| eco == "pypi" && pkg == "requests" && ver == "2.31.0")
            .returning(|_, _, _| Ok(Some(BlockReason::new("osv", "Test vulnerability"))));

        let result = mock.is_blocked("pypi", "requests", "2.31.0").await;
        assert!(result.is_ok());
        let reason = result.unwrap();
        assert!(reason.is_some());
        assert_eq!(reason.unwrap().source, "osv");
    }

    // Test 2: MockDatabase returns None for unblocked packages
    #[tokio::test]
    async fn test_mock_database_not_blocked() {
        let mut mock = MockDatabase::new();

        mock.expect_is_blocked().returning(|_, _, _| Ok(None));

        let result = mock.is_blocked("pypi", "safe-package", "1.0.0").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // Test 3: MockDatabase insert_blocked_package
    #[tokio::test]
    async fn test_mock_database_insert_blocked_package() {
        let mut mock = MockDatabase::new();

        mock.expect_insert_blocked_package().returning(|_| Ok(()));

        let pkg = BlockedPackage::new("pypi", "malicious", "1.0.0", "openssf");
        let result = mock.insert_blocked_package(&pkg).await;
        assert!(result.is_ok());
    }

    // Test 4: MockDatabase get_blocked_packages
    #[tokio::test]
    async fn test_mock_database_get_blocked_packages() {
        let mut mock = MockDatabase::new();

        mock.expect_get_blocked_packages()
            .withf(|eco| eco == "pypi")
            .returning(|_| {
                Ok(vec![
                    BlockedPackage::new("pypi", "pkg1", "1.0.0", "osv"),
                    BlockedPackage::new("pypi", "pkg2", "2.0.0", "openssf"),
                ])
            });

        let result = mock.get_blocked_packages("pypi").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    // Test 5: MockDatabase clear_blocked_by_source
    #[tokio::test]
    async fn test_mock_database_clear_blocked_by_source() {
        let mut mock = MockDatabase::new();

        mock.expect_clear_blocked_by_source()
            .withf(|src| src == "osv")
            .returning(|_| Ok(100));

        let result = mock.clear_blocked_by_source("osv").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 100);
    }

    // Test 6: MockDatabase sync status operations
    #[tokio::test]
    async fn test_mock_database_sync_status() {
        let mut mock = MockDatabase::new();

        mock.expect_update_sync_status().returning(|_| Ok(()));

        mock.expect_get_sync_status()
            .withf(|src| src == "osv")
            .returning(|_| {
                Ok(Some(SyncStatus {
                    source: "osv".to_string(),
                    last_sync_at: Some(chrono::Utc::now()),
                    status: SyncStatusValue::Success,
                    error_message: None,
                    records_count: 500,
                }))
            });

        let status = SyncStatus::new("osv").success(500);
        let result = mock.update_sync_status(&status).await;
        assert!(result.is_ok());

        let result = mock.get_sync_status("osv").await;
        assert!(result.is_ok());
        let status = result.unwrap().unwrap();
        assert_eq!(status.source, "osv");
        assert_eq!(status.records_count, 500);
    }

    // Test 7: MockDatabase token operations
    #[tokio::test]
    async fn test_mock_database_token_operations() {
        let mut mock = MockDatabase::new();

        mock.expect_create_token().returning(|_| Ok(()));

        mock.expect_get_token_by_hash()
            .withf(|hash| hash == "test_hash")
            .returning(|_| Ok(Some(Token::new("id1", "test-token", "test_hash"))));

        mock.expect_list_tokens()
            .returning(|| Ok(vec![Token::new("id1", "test-token", "hash1")]));

        mock.expect_revoke_token()
            .withf(|id| id == "id1")
            .returning(|_| Ok(()));

        let token = Token::new("id1", "test-token", "test_hash");
        assert!(mock.create_token(&token).await.is_ok());

        let result = mock.get_token_by_hash("test_hash").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap().name, "test-token");

        let tokens = mock.list_tokens().await.unwrap();
        assert_eq!(tokens.len(), 1);

        assert!(mock.revoke_token("id1").await.is_ok());
    }

    // Test 8: MockDatabase block log operations
    #[tokio::test]
    async fn test_mock_database_block_log_operations() {
        let mut mock = MockDatabase::new();

        mock.expect_insert_block_log().returning(|_| Ok(()));

        mock.expect_get_block_logs()
            .withf(|limit, offset| *limit == 10 && *offset == 0)
            .returning(|_, _| Ok(vec![BlockLog::new("pypi", "malicious", "1.0.0", "osv")]));

        mock.expect_get_block_logs_count().returning(|| Ok(100));

        let log = BlockLog::new("pypi", "malicious", "1.0.0", "osv");
        assert!(mock.insert_block_log(&log).await.is_ok());

        let logs = mock.get_block_logs(10, 0).await.unwrap();
        assert_eq!(logs.len(), 1);

        let count = mock.get_block_logs_count().await.unwrap();
        assert_eq!(count, 100);
    }

    // Test 9: MockDatabase custom rule operations
    #[tokio::test]
    async fn test_mock_database_custom_rule_operations() {
        let mut mock = MockDatabase::new();

        mock.expect_insert_rule().returning(|_| Ok(1));

        mock.expect_get_rule()
            .withf(|id| *id == 1)
            .returning(|_| Ok(Some(CustomRule::new("pypi", "malicious-*", "*"))));

        mock.expect_list_rules()
            .returning(|| Ok(vec![CustomRule::new("pypi", "malicious-*", "*")]));

        mock.expect_update_rule().returning(|_| Ok(()));

        mock.expect_delete_rule()
            .withf(|id| *id == 1)
            .returning(|_| Ok(()));

        let rule = CustomRule::new("pypi", "malicious-*", "*");
        let id = mock.insert_rule(&rule).await.unwrap();
        assert_eq!(id, 1);

        let fetched = mock.get_rule(1).await.unwrap().unwrap();
        assert_eq!(fetched.package_pattern, "malicious-*");

        let rules = mock.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);

        assert!(mock.update_rule(&rule).await.is_ok());
        assert!(mock.delete_rule(1).await.is_ok());
    }

    // Test 10: MockDatabase error handling
    #[tokio::test]
    async fn test_mock_database_error_handling() {
        let mut mock = MockDatabase::new();

        mock.expect_is_blocked()
            .returning(|_, _, _| Err(DbError::NotFound));

        let result = mock.is_blocked("pypi", "pkg", "1.0.0").await;
        assert!(result.is_err());
        match result {
            Err(DbError::NotFound) => (),
            _ => panic!("Expected DbError::NotFound"),
        }
    }

    // Test 11: BlockedPackage with severity
    #[tokio::test]
    async fn test_mock_database_blocked_package_with_severity() {
        let mut mock = MockDatabase::new();

        mock.expect_is_blocked().returning(|_, _, _| {
            Ok(Some(
                BlockReason::new("osv", "Critical vulnerability")
                    .with_severity(Severity::Critical)
                    .with_advisory_id("CVE-2024-1234"),
            ))
        });

        let result = mock.is_blocked("pypi", "vulnerable", "1.0.0").await;
        let reason = result.unwrap().unwrap();
        assert_eq!(reason.severity, Severity::Critical);
        assert_eq!(reason.advisory_id, Some("CVE-2024-1234".to_string()));
    }
}
