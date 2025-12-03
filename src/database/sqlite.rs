//! SQLite implementation of the Database trait
//!
//! This module provides a SQLite-based implementation of the Database trait
//! using rusqlite and tokio-rusqlite for async operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

use super::migrations::CREATE_SCHEMA;
use super::Database;
use crate::error::DbError;
use crate::models::{
    BlockLog, BlockReason, BlockedPackage, CustomRule, Severity, SyncStatus, SyncStatusValue, Token,
};

/// SQLite database implementation
pub struct SqliteDatabase {
    conn: Connection,
}

impl SqliteDatabase {
    /// Create a new SQLite database connection
    ///
    /// Use `:memory:` for in-memory database or a file path for persistent storage.
    pub async fn new(path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(path).await?;

        // Run migrations
        conn.call(|conn| {
            conn.execute_batch(CREATE_SCHEMA)?;
            Ok(())
        })
        .await?;

        Ok(Self { conn })
    }

    /// Create a new in-memory database (useful for testing)
    pub async fn in_memory() -> Result<Self, DbError> {
        Self::new(":memory:").await
    }
}

#[async_trait]
impl Database for SqliteDatabase {
    // =========================================================================
    // Blocked packages operations
    // =========================================================================

    async fn insert_blocked_package(&self, pkg: &BlockedPackage) -> Result<(), DbError> {
        let ecosystem = pkg.ecosystem.clone();
        let package = pkg.package.clone();
        let version = pkg.version.clone();
        let source = pkg.source.clone();
        let reason = pkg.reason.clone();
        let severity = pkg.severity.map(|s| s.to_string());
        let advisory_id = pkg.advisory_id.clone();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT OR REPLACE INTO blocked_packages
                    (ecosystem, package, version, source, reason, severity, advisory_id)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    "#,
                    rusqlite::params![
                        ecosystem,
                        package,
                        version,
                        source,
                        reason,
                        severity,
                        advisory_id
                    ],
                )?;
                Ok(())
            })
            .await?;

        Ok(())
    }

    async fn get_blocked_packages(&self, ecosystem: &str) -> Result<Vec<BlockedPackage>, DbError> {
        let ecosystem = ecosystem.to_string();

        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT id, ecosystem, package, version, source, reason, severity, advisory_id, created_at
                    FROM blocked_packages
                    WHERE ecosystem = ?1
                    ORDER BY package, version
                    "#,
                )?;

                let packages = stmt
                    .query_map([&ecosystem], |row| {
                        Ok(BlockedPackage {
                            id: Some(row.get(0)?),
                            ecosystem: row.get(1)?,
                            package: row.get(2)?,
                            version: row.get(3)?,
                            source: row.get(4)?,
                            reason: row.get(5)?,
                            severity: row
                                .get::<_, Option<String>>(6)?
                                .and_then(|s| s.parse().ok()),
                            advisory_id: row.get(7)?,
                            created_at: parse_datetime(row.get::<_, Option<String>>(8)?),
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(packages)
            })
            .await
            .map_err(Into::into)
    }

    async fn is_blocked(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Option<BlockReason>, DbError> {
        let ecosystem = ecosystem.to_string();
        let package = package.to_string();
        let version = version.to_string();

        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT source, reason, severity, advisory_id
                    FROM blocked_packages
                    WHERE ecosystem = ?1 AND package = ?2 AND version = ?3
                    LIMIT 1
                    "#,
                )?;

                let result = stmt
                    .query_row(rusqlite::params![ecosystem, package, version], |row| {
                        let source: String = row.get(0)?;
                        let reason: Option<String> = row.get(1)?;
                        let severity: Option<String> = row.get(2)?;
                        let advisory_id: Option<String> = row.get(3)?;

                        Ok(BlockReason {
                            source,
                            reason: reason.unwrap_or_else(|| "Blocked".to_string()),
                            severity: severity
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(Severity::Unknown),
                            advisory_id,
                            advisory_url: None,
                        })
                    })
                    .optional()?;

                Ok(result)
            })
            .await
            .map_err(Into::into)
    }

    async fn clear_blocked_by_source(&self, source: &str) -> Result<u64, DbError> {
        let source = source.to_string();

        self.conn
            .call(move |conn| {
                let count =
                    conn.execute("DELETE FROM blocked_packages WHERE source = ?1", [&source])?;
                Ok(count as u64)
            })
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Sync status operations
    // =========================================================================

    async fn update_sync_status(&self, status: &SyncStatus) -> Result<(), DbError> {
        let source = status.source.clone();
        let last_sync_at = status.last_sync_at.map(|dt| dt.to_rfc3339());
        let status_str = status.status.to_string();
        let error_message = status.error_message.clone();
        let records_count = status.records_count as i64;

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT OR REPLACE INTO sync_status
                    (source, last_sync_at, status, error_message, records_count)
                    VALUES (?1, ?2, ?3, ?4, ?5)
                    "#,
                    rusqlite::params![
                        source,
                        last_sync_at,
                        status_str,
                        error_message,
                        records_count
                    ],
                )?;
                Ok(())
            })
            .await?;

        Ok(())
    }

    async fn get_sync_status(&self, source: &str) -> Result<Option<SyncStatus>, DbError> {
        let source = source.to_string();

        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT source, last_sync_at, status, error_message, records_count
                    FROM sync_status
                    WHERE source = ?1
                    "#,
                )?;

                let result = stmt
                    .query_row([&source], |row| {
                        Ok(SyncStatus {
                            source: row.get(0)?,
                            last_sync_at: parse_datetime(row.get::<_, Option<String>>(1)?),
                            status: parse_sync_status(row.get::<_, String>(2)?),
                            error_message: row.get(3)?,
                            records_count: row.get::<_, i64>(4)? as u64,
                        })
                    })
                    .optional()?;

                Ok(result)
            })
            .await
            .map_err(Into::into)
    }

    async fn get_all_sync_statuses(&self) -> Result<Vec<SyncStatus>, DbError> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT source, last_sync_at, status, error_message, records_count
                    FROM sync_status
                    ORDER BY source
                    "#,
                )?;

                let statuses = stmt
                    .query_map([], |row| {
                        Ok(SyncStatus {
                            source: row.get(0)?,
                            last_sync_at: parse_datetime(row.get::<_, Option<String>>(1)?),
                            status: parse_sync_status(row.get::<_, String>(2)?),
                            error_message: row.get(3)?,
                            records_count: row.get::<_, i64>(4)? as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(statuses)
            })
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Token operations
    // =========================================================================

    async fn create_token(&self, token: &Token) -> Result<(), DbError> {
        let id = token.id.clone();
        let name = token.name.clone();
        let token_hash = token.token_hash.clone();
        let allowed_ecosystems =
            serde_json::to_string(&token.allowed_ecosystems).unwrap_or_else(|_| "[]".to_string());
        let expires_at = token.expires_at.map(|dt| dt.to_rfc3339());
        let created_at = token.created_at.to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO api_tokens
                    (id, name, token_hash, allowed_ecosystems, expires_at, created_at, is_revoked)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
                    "#,
                    rusqlite::params![
                        id,
                        name,
                        token_hash,
                        allowed_ecosystems,
                        expires_at,
                        created_at
                    ],
                )?;
                Ok(())
            })
            .await?;

        Ok(())
    }

    async fn get_token_by_hash(&self, hash: &str) -> Result<Option<Token>, DbError> {
        let hash = hash.to_string();

        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT id, name, token_hash, allowed_ecosystems, expires_at,
                           created_at, last_used_at, is_revoked
                    FROM api_tokens
                    WHERE token_hash = ?1
                    "#,
                )?;

                let result = stmt
                    .query_row([&hash], |row| {
                        let allowed_ecosystems: String = row.get(3)?;
                        let ecosystems: Vec<String> =
                            serde_json::from_str(&allowed_ecosystems).unwrap_or_default();

                        Ok(Token {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            token_hash: row.get(2)?,
                            allowed_ecosystems: ecosystems,
                            expires_at: parse_datetime(row.get::<_, Option<String>>(4)?),
                            created_at: parse_datetime(row.get::<_, Option<String>>(5)?)
                                .unwrap_or_else(Utc::now),
                            last_used_at: parse_datetime(row.get::<_, Option<String>>(6)?),
                            is_revoked: row.get::<_, i64>(7)? != 0,
                        })
                    })
                    .optional()?;

                Ok(result)
            })
            .await
            .map_err(Into::into)
    }

    async fn revoke_token(&self, id: &str) -> Result<(), DbError> {
        let id = id.to_string();

        let rows_affected = self
            .conn
            .call(move |conn| {
                let count =
                    conn.execute("UPDATE api_tokens SET is_revoked = 1 WHERE id = ?1", [&id])?;
                Ok(count)
            })
            .await?;

        if rows_affected == 0 {
            return Err(DbError::NotFound);
        }

        Ok(())
    }

    async fn list_tokens(&self) -> Result<Vec<Token>, DbError> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT id, name, token_hash, allowed_ecosystems, expires_at,
                           created_at, last_used_at, is_revoked
                    FROM api_tokens
                    WHERE is_revoked = 0
                    ORDER BY created_at DESC
                    "#,
                )?;

                let tokens = stmt
                    .query_map([], |row| {
                        let allowed_ecosystems: String = row.get(3)?;
                        let ecosystems: Vec<String> =
                            serde_json::from_str(&allowed_ecosystems).unwrap_or_default();

                        Ok(Token {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            token_hash: row.get(2)?,
                            allowed_ecosystems: ecosystems,
                            expires_at: parse_datetime(row.get::<_, Option<String>>(4)?),
                            created_at: parse_datetime(row.get::<_, Option<String>>(5)?)
                                .unwrap_or_else(Utc::now),
                            last_used_at: parse_datetime(row.get::<_, Option<String>>(6)?),
                            is_revoked: row.get::<_, i64>(7)? != 0,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(tokens)
            })
            .await
            .map_err(Into::into)
    }

    async fn update_token_last_used(&self, id: &str) -> Result<(), DbError> {
        let id = id.to_string();
        let now = Utc::now().to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
                    rusqlite::params![now, id],
                )?;
                Ok(())
            })
            .await?;

        Ok(())
    }

    // =========================================================================
    // Block log operations
    // =========================================================================

    async fn insert_block_log(&self, log: &BlockLog) -> Result<(), DbError> {
        let timestamp = log.timestamp.to_rfc3339();
        let client_id = log.client_id.clone();
        let client_ip = log.client_ip.clone();
        let ecosystem = log.ecosystem.clone();
        let package = log.package.clone();
        let version = log.version.clone();
        let source = log.source.clone();
        let reason = log.reason.clone();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO block_logs
                    (timestamp, client_id, client_ip, ecosystem, package, version, source, reason)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                    rusqlite::params![
                        timestamp, client_id, client_ip, ecosystem, package, version, source,
                        reason
                    ],
                )?;
                Ok(())
            })
            .await?;

        Ok(())
    }

    async fn get_block_logs(&self, limit: u32, offset: u32) -> Result<Vec<BlockLog>, DbError> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT id, timestamp, client_id, client_ip, ecosystem, package, version, source, reason
                    FROM block_logs
                    ORDER BY timestamp DESC
                    LIMIT ?1 OFFSET ?2
                    "#,
                )?;

                let logs = stmt
                    .query_map(rusqlite::params![limit, offset], |row| {
                        Ok(BlockLog {
                            id: Some(row.get(0)?),
                            timestamp: parse_datetime(row.get::<_, Option<String>>(1)?)
                                .unwrap_or_else(Utc::now),
                            client_id: row.get(2)?,
                            client_ip: row.get(3)?,
                            ecosystem: row.get(4)?,
                            package: row.get(5)?,
                            version: row.get(6)?,
                            source: row.get(7)?,
                            reason: row.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(logs)
            })
            .await
            .map_err(Into::into)
    }

    async fn get_block_logs_count(&self) -> Result<u64, DbError> {
        self.conn
            .call(|conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM block_logs", [], |row| row.get(0))?;
                Ok(count as u64)
            })
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Custom rules operations
    // =========================================================================

    async fn insert_rule(&self, rule: &CustomRule) -> Result<i64, DbError> {
        let ecosystem = rule.ecosystem.clone();
        let package_pattern = rule.package_pattern.clone();
        let version_constraint = rule.version_constraint.clone();
        let reason = rule.reason.clone();
        let created_by = rule.created_by.clone();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO custom_rules
                    (ecosystem, package_pattern, version_constraint, reason, created_by)
                    VALUES (?1, ?2, ?3, ?4, ?5)
                    "#,
                    rusqlite::params![
                        ecosystem,
                        package_pattern,
                        version_constraint,
                        reason,
                        created_by
                    ],
                )?;
                let id = conn.last_insert_rowid();
                Ok(id)
            })
            .await
            .map_err(Into::into)
    }

    async fn update_rule(&self, rule: &CustomRule) -> Result<(), DbError> {
        let id = rule.id.ok_or(DbError::NotFound)?;
        let ecosystem = rule.ecosystem.clone();
        let package_pattern = rule.package_pattern.clone();
        let version_constraint = rule.version_constraint.clone();
        let reason = rule.reason.clone();

        let rows_affected = self
            .conn
            .call(move |conn| {
                let count = conn.execute(
                    r#"
                    UPDATE custom_rules
                    SET ecosystem = ?1, package_pattern = ?2, version_constraint = ?3, reason = ?4
                    WHERE id = ?5
                    "#,
                    rusqlite::params![ecosystem, package_pattern, version_constraint, reason, id],
                )?;
                Ok(count)
            })
            .await?;

        if rows_affected == 0 {
            return Err(DbError::NotFound);
        }

        Ok(())
    }

    async fn delete_rule(&self, id: i64) -> Result<(), DbError> {
        let rows_affected = self
            .conn
            .call(move |conn| {
                let count = conn.execute("DELETE FROM custom_rules WHERE id = ?1", [id])?;
                Ok(count)
            })
            .await?;

        if rows_affected == 0 {
            return Err(DbError::NotFound);
        }

        Ok(())
    }

    async fn list_rules(&self) -> Result<Vec<CustomRule>, DbError> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT id, ecosystem, package_pattern, version_constraint, reason, created_at, created_by
                    FROM custom_rules
                    ORDER BY ecosystem, package_pattern
                    "#,
                )?;

                let rules = stmt
                    .query_map([], |row| {
                        Ok(CustomRule {
                            id: Some(row.get(0)?),
                            ecosystem: row.get(1)?,
                            package_pattern: row.get(2)?,
                            version_constraint: row.get(3)?,
                            reason: row.get(4)?,
                            created_at: parse_datetime(row.get::<_, Option<String>>(5)?),
                            created_by: row.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(rules)
            })
            .await
            .map_err(Into::into)
    }

    async fn get_rule(&self, id: i64) -> Result<Option<CustomRule>, DbError> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    r#"
                    SELECT id, ecosystem, package_pattern, version_constraint, reason, created_at, created_by
                    FROM custom_rules
                    WHERE id = ?1
                    "#,
                )?;

                let result = stmt
                    .query_row([id], |row| {
                        Ok(CustomRule {
                            id: Some(row.get(0)?),
                            ecosystem: row.get(1)?,
                            package_pattern: row.get(2)?,
                            version_constraint: row.get(3)?,
                            reason: row.get(4)?,
                            created_at: parse_datetime(row.get::<_, Option<String>>(5)?),
                            created_by: row.get(6)?,
                        })
                    })
                    .optional()?;

                Ok(result)
            })
            .await
            .map_err(Into::into)
    }
}

/// Parse a datetime string to DateTime<Utc>
fn parse_datetime(s: Option<String>) -> Option<DateTime<Utc>> {
    s.and_then(|s| {
        DateTime::parse_from_rfc3339(&s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
            .or_else(|| {
                // Try parsing SQLite's datetime format
                chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc())
            })
    })
}

/// Parse sync status string to SyncStatusValue
fn parse_sync_status(s: String) -> SyncStatusValue {
    match s.as_str() {
        "pending" => SyncStatusValue::Pending,
        "in_progress" => SyncStatusValue::InProgress,
        "success" => SyncStatusValue::Success,
        "failed" => SyncStatusValue::Failed,
        _ => SyncStatusValue::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Create in-memory database
    #[tokio::test]
    async fn test_create_in_memory_database() {
        let db = SqliteDatabase::in_memory().await;
        assert!(db.is_ok());
    }

    // Test 2: Insert and retrieve blocked package
    #[tokio::test]
    async fn test_insert_and_get_blocked_package() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let pkg = BlockedPackage::new("pypi", "requests", "2.31.0", "osv")
            .with_reason("Test vulnerability")
            .with_severity(Severity::High)
            .with_advisory_id("CVE-2024-1234");

        db.insert_blocked_package(&pkg).await.unwrap();

        let packages = db.get_blocked_packages("pypi").await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package, "requests");
        assert_eq!(packages[0].version, "2.31.0");
        assert_eq!(packages[0].severity, Some(Severity::High));
    }

    // Test 3: Check is_blocked returns BlockReason
    #[tokio::test]
    async fn test_is_blocked_returns_reason() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let pkg = BlockedPackage::new("pypi", "malicious", "1.0.0", "openssf")
            .with_reason("Known malware")
            .with_severity(Severity::Critical)
            .with_advisory_id("MAL-001");

        db.insert_blocked_package(&pkg).await.unwrap();

        let result = db.is_blocked("pypi", "malicious", "1.0.0").await.unwrap();
        assert!(result.is_some());

        let reason = result.unwrap();
        assert_eq!(reason.source, "openssf");
        assert_eq!(reason.reason, "Known malware");
        assert_eq!(reason.severity, Severity::Critical);
        assert_eq!(reason.advisory_id, Some("MAL-001".to_string()));
    }

    // Test 4: Check is_blocked returns None for safe packages
    #[tokio::test]
    async fn test_is_blocked_returns_none_for_safe() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let result = db
            .is_blocked("pypi", "safe-package", "1.0.0")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    // Test 5: Clear blocked by source
    #[tokio::test]
    async fn test_clear_blocked_by_source() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        // Insert packages from different sources
        db.insert_blocked_package(&BlockedPackage::new("pypi", "pkg1", "1.0.0", "osv"))
            .await
            .unwrap();
        db.insert_blocked_package(&BlockedPackage::new("pypi", "pkg2", "1.0.0", "osv"))
            .await
            .unwrap();
        db.insert_blocked_package(&BlockedPackage::new("pypi", "pkg3", "1.0.0", "openssf"))
            .await
            .unwrap();

        let deleted = db.clear_blocked_by_source("osv").await.unwrap();
        assert_eq!(deleted, 2);

        let remaining = db.get_blocked_packages("pypi").await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].source, "openssf");
    }

    // Test 6: Sync status operations
    #[tokio::test]
    async fn test_sync_status_operations() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let status = SyncStatus::new("osv").success(500);
        db.update_sync_status(&status).await.unwrap();

        let retrieved = db.get_sync_status("osv").await.unwrap().unwrap();
        assert_eq!(retrieved.source, "osv");
        assert_eq!(retrieved.status, SyncStatusValue::Success);
        assert_eq!(retrieved.records_count, 500);
    }

    // Test 7: Token operations
    #[tokio::test]
    async fn test_token_operations() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let token = Token::new("id1", "test-token", "hash123")
            .with_ecosystems(vec!["pypi".to_string(), "cargo".to_string()]);

        db.create_token(&token).await.unwrap();

        let retrieved = db.get_token_by_hash("hash123").await.unwrap().unwrap();
        assert_eq!(retrieved.id, "id1");
        assert_eq!(retrieved.name, "test-token");
        assert_eq!(retrieved.allowed_ecosystems, vec!["pypi", "cargo"]);
        assert!(!retrieved.is_revoked);

        // List tokens
        let tokens = db.list_tokens().await.unwrap();
        assert_eq!(tokens.len(), 1);

        // Revoke token
        db.revoke_token("id1").await.unwrap();

        // Should no longer appear in list
        let tokens = db.list_tokens().await.unwrap();
        assert_eq!(tokens.len(), 0);
    }

    // Test 8: Block log operations
    #[tokio::test]
    async fn test_block_log_operations() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let log = BlockLog::new("pypi", "malicious", "1.0.0", "osv")
            .with_client_id("client-123")
            .with_client_ip("192.168.1.1")
            .with_reason("Known vulnerability");

        db.insert_block_log(&log).await.unwrap();

        let logs = db.get_block_logs(10, 0).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].package, "malicious");
        assert_eq!(logs[0].client_id, Some("client-123".to_string()));

        let count = db.get_block_logs_count().await.unwrap();
        assert_eq!(count, 1);
    }

    // Test 9: Custom rule operations
    #[tokio::test]
    async fn test_custom_rule_operations() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let rule = CustomRule::new("pypi", "malicious-*", "*")
            .with_reason("Malware pattern")
            .with_created_by("admin");

        let id = db.insert_rule(&rule).await.unwrap();
        assert!(id > 0);

        let retrieved = db.get_rule(id).await.unwrap().unwrap();
        assert_eq!(retrieved.package_pattern, "malicious-*");
        assert_eq!(retrieved.reason, Some("Malware pattern".to_string()));

        let rules = db.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);

        // Update rule
        let mut updated_rule = retrieved;
        updated_rule.reason = Some("Updated reason".to_string());
        db.update_rule(&updated_rule).await.unwrap();

        let retrieved = db.get_rule(id).await.unwrap().unwrap();
        assert_eq!(retrieved.reason, Some("Updated reason".to_string()));

        // Delete rule
        db.delete_rule(id).await.unwrap();

        let result = db.get_rule(id).await.unwrap();
        assert!(result.is_none());
    }

    // Test 10: Revoke non-existent token returns error
    #[tokio::test]
    async fn test_revoke_nonexistent_token() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let result = db.revoke_token("nonexistent").await;
        assert!(matches!(result, Err(DbError::NotFound)));
    }

    // Test 11: Update non-existent rule returns error
    #[tokio::test]
    async fn test_update_nonexistent_rule() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let rule = CustomRule {
            id: Some(999),
            ecosystem: "pypi".to_string(),
            package_pattern: "test".to_string(),
            version_constraint: "*".to_string(),
            reason: None,
            created_at: None,
            created_by: None,
        };

        let result = db.update_rule(&rule).await;
        assert!(matches!(result, Err(DbError::NotFound)));
    }

    // Test 12: Delete non-existent rule returns error
    #[tokio::test]
    async fn test_delete_nonexistent_rule() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let result = db.delete_rule(999).await;
        assert!(matches!(result, Err(DbError::NotFound)));
    }

    // Test 13: Update token last used
    #[tokio::test]
    async fn test_update_token_last_used() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let token = Token::new("id1", "test-token", "hash123");
        db.create_token(&token).await.unwrap();

        // Initially last_used_at should be None
        let retrieved = db.get_token_by_hash("hash123").await.unwrap().unwrap();
        assert!(retrieved.last_used_at.is_none());

        // Update last used
        db.update_token_last_used("id1").await.unwrap();

        // Now last_used_at should be set
        let retrieved = db.get_token_by_hash("hash123").await.unwrap().unwrap();
        assert!(retrieved.last_used_at.is_some());
    }

    // Test 14: Get all sync statuses
    #[tokio::test]
    async fn test_get_all_sync_statuses() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        db.update_sync_status(&SyncStatus::new("osv").success(100))
            .await
            .unwrap();
        db.update_sync_status(&SyncStatus::new("openssf").success(50))
            .await
            .unwrap();

        let statuses = db.get_all_sync_statuses().await.unwrap();
        assert_eq!(statuses.len(), 2);
    }

    // Test 15: Insert duplicate blocked package replaces
    #[tokio::test]
    async fn test_insert_duplicate_blocked_package_replaces() {
        let db = SqliteDatabase::in_memory().await.unwrap();

        let pkg1 =
            BlockedPackage::new("pypi", "pkg", "1.0.0", "osv").with_reason("Original reason");
        db.insert_blocked_package(&pkg1).await.unwrap();

        let pkg2 = BlockedPackage::new("pypi", "pkg", "1.0.0", "osv").with_reason("Updated reason");
        db.insert_blocked_package(&pkg2).await.unwrap();

        let packages = db.get_blocked_packages("pypi").await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].reason, Some("Updated reason".to_string()));
    }
}
