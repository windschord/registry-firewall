//! Token-related domain models
//!
//! This module defines models for API tokens, clients, and sync status.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// API token stored in database
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    /// Unique token ID
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Hashed token value (argon2id)
    pub token_hash: String,

    /// Allowed ecosystems (empty means all)
    pub allowed_ecosystems: Vec<String>,

    /// When the token expires (None = never)
    pub expires_at: Option<DateTime<Utc>>,

    /// When the token was created
    pub created_at: DateTime<Utc>,

    /// When the token was last used
    pub last_used_at: Option<DateTime<Utc>>,

    /// Whether the token has been revoked
    pub is_revoked: bool,
}

impl Token {
    /// Create a new token
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        token_hash: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            token_hash: token_hash.into(),
            allowed_ecosystems: Vec::new(),
            expires_at: None,
            created_at: Utc::now(),
            last_used_at: None,
            is_revoked: false,
        }
    }

    /// Set allowed ecosystems
    pub fn with_ecosystems(mut self, ecosystems: Vec<String>) -> Self {
        self.allowed_ecosystems = ecosystems;
        self
    }

    /// Set expiration time
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Check if the token is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        if self.is_revoked {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            if expires_at < Utc::now() {
                return false;
            }
        }

        true
    }

    /// Check if the token allows access to a specific ecosystem
    pub fn allows_ecosystem(&self, ecosystem: &str) -> bool {
        if self.allowed_ecosystems.is_empty() {
            // Empty means all ecosystems are allowed
            return true;
        }

        self.allowed_ecosystems
            .iter()
            .any(|e| e == "*" || e.eq_ignore_ascii_case(ecosystem))
    }
}

/// Client information extracted from a valid token
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// Token ID
    pub id: String,

    /// Client name
    pub name: String,

    /// Allowed ecosystems
    pub allowed_ecosystems: Vec<String>,
}

impl From<&Token> for Client {
    fn from(token: &Token) -> Self {
        Self {
            id: token.id.clone(),
            name: token.name.clone(),
            allowed_ecosystems: token.allowed_ecosystems.clone(),
        }
    }
}

/// Request to create a new API token
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    /// Human-readable name for the token
    pub name: String,

    /// When the token should expire (None = never)
    pub expires_at: Option<DateTime<Utc>>,

    /// Allowed ecosystems (empty = all)
    pub allowed_ecosystems: Vec<String>,
}

impl CreateTokenRequest {
    /// Create a new token creation request
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expires_at: None,
            allowed_ecosystems: Vec::new(),
        }
    }

    /// Set expiration time
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set allowed ecosystems
    pub fn with_ecosystems(mut self, ecosystems: Vec<String>) -> Self {
        self.allowed_ecosystems = ecosystems;
        self
    }
}

/// Response when a token is created (includes the raw token value)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTokenResponse {
    /// Token ID
    pub id: String,

    /// Token name
    pub name: String,

    /// Raw token value (only shown once at creation)
    pub token: String,

    /// When the token expires
    pub expires_at: Option<DateTime<Utc>>,

    /// When the token was created
    pub created_at: DateTime<Utc>,
}

/// Sync result from a security source
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncResult {
    /// Number of records updated
    pub records_updated: u64,

    /// Whether the sync was skipped (e.g., 304 Not Modified)
    pub skipped: bool,

    /// Optional message
    pub message: Option<String>,
}

impl SyncResult {
    /// Create a skipped sync result
    pub fn skipped() -> Self {
        Self {
            records_updated: 0,
            skipped: true,
            message: None,
        }
    }

    /// Create a successful sync result
    pub fn success(records_updated: u64) -> Self {
        Self {
            records_updated,
            skipped: false,
            message: None,
        }
    }

    /// Add a message
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

/// Sync status for a security source
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Source name
    pub source: String,

    /// When the last sync occurred
    pub last_sync_at: Option<DateTime<Utc>>,

    /// Status of the last sync
    pub status: SyncStatusValue,

    /// Error message if last sync failed
    pub error_message: Option<String>,

    /// Number of records from this source
    pub records_count: u64,
}

impl SyncStatus {
    /// Create a new sync status
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            last_sync_at: None,
            status: SyncStatusValue::Pending,
            error_message: None,
            records_count: 0,
        }
    }

    /// Mark as successful
    pub fn success(mut self, records_count: u64) -> Self {
        self.last_sync_at = Some(Utc::now());
        self.status = SyncStatusValue::Success;
        self.error_message = None;
        self.records_count = records_count;
        self
    }

    /// Mark as failed
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.last_sync_at = Some(Utc::now());
        self.status = SyncStatusValue::Failed;
        self.error_message = Some(error.into());
        self
    }

    /// Mark as in progress
    pub fn in_progress(mut self) -> Self {
        self.status = SyncStatusValue::InProgress;
        self
    }
}

/// Status value for sync operations
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatusValue {
    /// Sync has never been run
    #[default]
    Pending,
    /// Sync is currently running
    InProgress,
    /// Last sync was successful
    Success,
    /// Last sync failed
    Failed,
}

impl std::fmt::Display for SyncStatusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncStatusValue::Pending => write!(f, "pending"),
            SyncStatusValue::InProgress => write!(f, "in_progress"),
            SyncStatusValue::Success => write!(f, "success"),
            SyncStatusValue::Failed => write!(f, "failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_token_is_valid_not_revoked() {
        let token = Token::new("id1", "test-token", "hash123");
        assert!(token.is_valid());
    }

    #[test]
    fn test_token_is_valid_revoked() {
        let mut token = Token::new("id1", "test-token", "hash123");
        token.is_revoked = true;
        assert!(!token.is_valid());
    }

    #[test]
    fn test_token_is_valid_expired() {
        let token = Token::new("id1", "test-token", "hash123")
            .with_expires_at(Utc::now() - Duration::hours(1));
        assert!(!token.is_valid());
    }

    #[test]
    fn test_token_is_valid_not_expired() {
        let token = Token::new("id1", "test-token", "hash123")
            .with_expires_at(Utc::now() + Duration::hours(1));
        assert!(token.is_valid());
    }

    #[test]
    fn test_token_allows_ecosystem_all() {
        let token = Token::new("id1", "test-token", "hash123");
        // Empty ecosystems means all are allowed
        assert!(token.allows_ecosystem("pypi"));
        assert!(token.allows_ecosystem("cargo"));
        assert!(token.allows_ecosystem("docker"));
    }

    #[test]
    fn test_token_allows_ecosystem_specific() {
        let token = Token::new("id1", "test-token", "hash123")
            .with_ecosystems(vec!["pypi".to_string(), "cargo".to_string()]);

        assert!(token.allows_ecosystem("pypi"));
        assert!(token.allows_ecosystem("cargo"));
        assert!(!token.allows_ecosystem("docker"));
    }

    #[test]
    fn test_token_allows_ecosystem_wildcard() {
        let token =
            Token::new("id1", "test-token", "hash123").with_ecosystems(vec!["*".to_string()]);

        assert!(token.allows_ecosystem("pypi"));
        assert!(token.allows_ecosystem("cargo"));
        assert!(token.allows_ecosystem("docker"));
    }

    #[test]
    fn test_token_allows_ecosystem_case_insensitive() {
        let token =
            Token::new("id1", "test-token", "hash123").with_ecosystems(vec!["PyPI".to_string()]);

        assert!(token.allows_ecosystem("pypi"));
        assert!(token.allows_ecosystem("PYPI"));
        assert!(token.allows_ecosystem("PyPI"));
    }

    #[test]
    fn test_client_from_token() {
        let token =
            Token::new("id1", "test-token", "hash123").with_ecosystems(vec!["pypi".to_string()]);

        let client = Client::from(&token);

        assert_eq!(client.id, "id1");
        assert_eq!(client.name, "test-token");
        assert_eq!(client.allowed_ecosystems, vec!["pypi"]);
    }

    #[test]
    fn test_create_token_request() {
        let req = CreateTokenRequest::new("my-ci-token")
            .with_expires_at(Utc::now() + Duration::days(30))
            .with_ecosystems(vec!["pypi".to_string(), "cargo".to_string()]);

        assert_eq!(req.name, "my-ci-token");
        assert!(req.expires_at.is_some());
        assert_eq!(
            req.allowed_ecosystems,
            vec!["pypi".to_string(), "cargo".to_string()]
        );
    }

    #[test]
    fn test_sync_result() {
        let skipped = SyncResult::skipped();
        assert!(skipped.skipped);
        assert_eq!(skipped.records_updated, 0);

        let success = SyncResult::success(100);
        assert!(!success.skipped);
        assert_eq!(success.records_updated, 100);

        let with_msg = SyncResult::success(50).with_message("Updated from cache");
        assert_eq!(with_msg.message, Some("Updated from cache".to_string()));
    }

    #[test]
    fn test_sync_status() {
        let mut status = SyncStatus::new("osv");
        assert_eq!(status.status, SyncStatusValue::Pending);

        status = status.in_progress();
        assert_eq!(status.status, SyncStatusValue::InProgress);

        status = status.success(500);
        assert_eq!(status.status, SyncStatusValue::Success);
        assert_eq!(status.records_count, 500);
        assert!(status.last_sync_at.is_some());

        status = status.failed("Connection timeout");
        assert_eq!(status.status, SyncStatusValue::Failed);
        assert_eq!(status.error_message, Some("Connection timeout".to_string()));
    }

    #[test]
    fn test_sync_status_value_serialization() {
        let values = vec![
            (SyncStatusValue::Pending, r#""pending""#),
            (SyncStatusValue::InProgress, r#""in_progress""#),
            (SyncStatusValue::Success, r#""success""#),
            (SyncStatusValue::Failed, r#""failed""#),
        ];

        for (value, expected_json) in values {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(json, expected_json);

            let parsed: SyncStatusValue = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, value);
        }
    }

    #[test]
    fn test_token_serialization() {
        let token =
            Token::new("id-123", "my-token", "hash-abc").with_ecosystems(vec!["pypi".to_string()]);

        let json = serde_json::to_string(&token).unwrap();
        let parsed: Token = serde_json::from_str(&json).unwrap();

        assert_eq!(token.id, parsed.id);
        assert_eq!(token.name, parsed.name);
        assert_eq!(token.token_hash, parsed.token_hash);
        assert_eq!(token.allowed_ecosystems, parsed.allowed_ecosystems);
    }

    #[test]
    fn test_create_token_response_serialization() {
        let response = CreateTokenResponse {
            id: "id-123".to_string(),
            name: "my-token".to_string(),
            token: "rf_abcdef123456".to_string(),
            expires_at: None,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: CreateTokenResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(response.id, parsed.id);
        assert_eq!(response.name, parsed.name);
        assert_eq!(response.token, parsed.token);
    }
}
