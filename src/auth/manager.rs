//! Authentication manager
//!
//! This module provides the main authentication interface for the application.
//! It handles token validation, basic auth, and token CRUD operations.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::Utc;

use crate::database::Database;
use crate::error::AuthError;
use crate::models::{Client, CreateTokenRequest, CreateTokenResponse, Token};

use super::ratelimit::{RateLimitConfig, RateLimiter};
use super::token::{generate_token, hash_token, is_valid_token_format, verify_token};

/// Configuration for the authentication manager
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Whether authentication is enabled
    pub enabled: bool,

    /// Admin password for basic auth (hashed)
    pub admin_password_hash: Option<String>,

    /// Rate limit configuration
    pub rate_limit: RateLimitConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            admin_password_hash: None,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Authentication manager
///
/// Provides methods for authenticating requests and managing tokens.
pub struct AuthManager<D: Database> {
    db: Arc<D>,
    config: AuthConfig,
    rate_limiter: RateLimiter,
}

impl<D: Database> AuthManager<D> {
    /// Create a new authentication manager
    pub fn new(db: Arc<D>, config: AuthConfig) -> Self {
        let rate_limiter = RateLimiter::new(config.rate_limit.clone());
        Self {
            db,
            config,
            rate_limiter,
        }
    }

    /// Check if authentication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Validate a bearer token
    ///
    /// Returns the client information if the token is valid.
    pub async fn validate_token(
        &self,
        token: &str,
        ip: Option<IpAddr>,
    ) -> Result<Client, AuthError> {
        // Check rate limiting
        if let Some(ip) = ip {
            if self.rate_limiter.is_blocked(ip) {
                return Err(AuthError::RateLimited);
            }
        }

        // Check token format
        if !is_valid_token_format(token) {
            if let Some(ip) = ip {
                self.rate_limiter.record_failure(ip);
            }
            return Err(AuthError::InvalidToken);
        }

        // Hash the token to look it up
        // Since we use salted hashes, we need to iterate through all tokens
        // This is acceptable because the number of tokens is typically small
        let tokens = self
            .db
            .list_tokens()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        for db_token in tokens {
            if verify_token(token, &db_token.token_hash) {
                // Token found, check if valid
                if !db_token.is_valid() {
                    if let Some(ip) = ip {
                        self.rate_limiter.record_failure(ip);
                    }
                    return Err(AuthError::InvalidToken);
                }

                // Update last used timestamp
                let _ = self.db.update_token_last_used(&db_token.id).await;

                // Reset rate limiter on success
                if let Some(ip) = ip {
                    self.rate_limiter.reset(ip);
                }

                return Ok(Client::from(&db_token));
            }
        }

        // Token not found
        if let Some(ip) = ip {
            self.rate_limiter.record_failure(ip);
        }
        Err(AuthError::TokenNotFound)
    }

    /// Validate basic authentication
    ///
    /// Only supports the "admin" user with the configured password.
    pub async fn validate_basic_auth(
        &self,
        username: &str,
        password: &str,
        ip: Option<IpAddr>,
    ) -> Result<Client, AuthError> {
        // Check rate limiting
        if let Some(ip) = ip {
            if self.rate_limiter.is_blocked(ip) {
                return Err(AuthError::RateLimited);
            }
        }

        // Only admin user is supported
        if username != "admin" {
            if let Some(ip) = ip {
                self.rate_limiter.record_failure(ip);
            }
            return Err(AuthError::InvalidCredentials);
        }

        // Check password
        let password_hash = self
            .config
            .admin_password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;

        if !verify_token(password, password_hash) {
            if let Some(ip) = ip {
                self.rate_limiter.record_failure(ip);
            }
            return Err(AuthError::InvalidCredentials);
        }

        // Reset rate limiter on success
        if let Some(ip) = ip {
            self.rate_limiter.reset(ip);
        }

        // Return admin client
        Ok(Client {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            allowed_ecosystems: vec!["*".to_string()],
        })
    }

    /// Create a new API token
    ///
    /// Returns the token response containing the raw token value.
    /// The raw token is only returned once and cannot be retrieved later.
    pub async fn create_token(
        &self,
        request: CreateTokenRequest,
    ) -> Result<CreateTokenResponse, AuthError> {
        let (raw_token, token_id) = generate_token();
        let token_hash = hash_token(&raw_token).map_err(|_| AuthError::InvalidToken)?;

        let token = Token::new(&token_id, &request.name, &token_hash)
            .with_ecosystems(request.allowed_ecosystems.clone());

        let token = if let Some(expires_at) = request.expires_at {
            token.with_expires_at(expires_at)
        } else {
            token
        };

        self.db
            .create_token(&token)
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(CreateTokenResponse {
            id: token_id,
            name: request.name,
            token: raw_token,
            expires_at: request.expires_at,
            created_at: Utc::now(),
        })
    }

    /// Revoke a token by ID
    pub async fn revoke_token(&self, id: &str) -> Result<(), AuthError> {
        self.db
            .revoke_token(id)
            .await
            .map_err(|_| AuthError::TokenNotFound)
    }

    /// List all tokens (excluding revoked)
    ///
    /// Note: Token hashes are included but raw tokens cannot be recovered.
    pub async fn list_tokens(&self) -> Result<Vec<Token>, AuthError> {
        self.db
            .list_tokens()
            .await
            .map_err(|_| AuthError::TokenNotFound)
    }

    /// Check if a client has access to a specific ecosystem
    pub fn check_ecosystem_access(&self, client: &Client, ecosystem: &str) -> bool {
        if client.allowed_ecosystems.is_empty() {
            // Empty means all ecosystems allowed
            return true;
        }

        client
            .allowed_ecosystems
            .iter()
            .any(|e| e == "*" || e.eq_ignore_ascii_case(ecosystem))
    }

    /// Check if an IP is rate limited
    pub fn is_rate_limited(&self, ip: IpAddr) -> bool {
        self.rate_limiter.is_blocked(ip)
    }

    /// Reset rate limit for an IP (for testing)
    #[cfg(test)]
    pub fn reset_rate_limit(&self, ip: IpAddr) {
        self.rate_limiter.reset(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::MockDatabase;
    use crate::error::DbError;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    fn create_test_manager(db: MockDatabase) -> AuthManager<MockDatabase> {
        let password_hash = hash_token("admin_password").unwrap();
        let config = AuthConfig {
            enabled: true,
            admin_password_hash: Some(password_hash),
            rate_limit: RateLimitConfig {
                max_failures: 5,
                block_duration: Duration::from_secs(60),
                window_duration: Duration::from_secs(120),
            },
        };
        AuthManager::new(Arc::new(db), config)
    }

    // Test 1: validate_token succeeds with valid token
    #[tokio::test]
    async fn test_validate_token_success() {
        let (raw_token, _) = generate_token();
        let token_hash = hash_token(&raw_token).unwrap();
        let stored_token = Token::new("id1", "test-token", &token_hash);

        let mut mock_db = MockDatabase::new();
        mock_db
            .expect_list_tokens()
            .returning(move || Ok(vec![stored_token.clone()]));
        mock_db
            .expect_update_token_last_used()
            .returning(|_| Ok(()));

        let manager = create_test_manager(mock_db);
        let result = manager.validate_token(&raw_token, None).await;

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.id, "id1");
        assert_eq!(client.name, "test-token");
    }

    // Test 2: validate_token fails with invalid token (not found in database)
    #[tokio::test]
    async fn test_validate_token_not_found() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_list_tokens().returning(|| Ok(vec![]));

        let manager = create_test_manager(mock_db);
        // Use a properly formatted token that just doesn't exist in the database
        // 43 base64 chars = 32 bytes
        let nonexistent_token = "rf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result = manager.validate_token(nonexistent_token, None).await;

        assert!(matches!(result, Err(AuthError::TokenNotFound)));
    }

    // Test 3: validate_token fails with bad format
    #[tokio::test]
    async fn test_validate_token_bad_format() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let result = manager.validate_token("not_a_valid_token", None).await;

        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    // Test 4: validate_basic_auth succeeds with correct credentials
    #[tokio::test]
    async fn test_validate_basic_auth_success() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let result = manager
            .validate_basic_auth("admin", "admin_password", None)
            .await;

        assert!(result.is_ok());
        let client = result.unwrap();
        assert_eq!(client.id, "admin");
        assert_eq!(client.allowed_ecosystems, vec!["*"]);
    }

    // Test 5: validate_basic_auth fails with wrong password
    #[tokio::test]
    async fn test_validate_basic_auth_wrong_password() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let result = manager
            .validate_basic_auth("admin", "wrong_password", None)
            .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    // Test 6: validate_basic_auth fails with wrong username
    #[tokio::test]
    async fn test_validate_basic_auth_wrong_username() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let result = manager
            .validate_basic_auth("notadmin", "admin_password", None)
            .await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    // Test 7: create_token succeeds
    #[tokio::test]
    async fn test_create_token_success() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_create_token().returning(|_| Ok(()));

        let manager = create_test_manager(mock_db);
        let request = CreateTokenRequest::new("my-token");

        let result = manager.create_token(request).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.token.starts_with("rf_"));
        assert_eq!(response.name, "my-token");
    }

    // Test 8: revoke_token succeeds
    #[tokio::test]
    async fn test_revoke_token_success() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_revoke_token().returning(|_| Ok(()));

        let manager = create_test_manager(mock_db);
        let result = manager.revoke_token("token-id").await;

        assert!(result.is_ok());
    }

    // Test 9: revoke_token fails for non-existent token
    #[tokio::test]
    async fn test_revoke_token_not_found() {
        let mut mock_db = MockDatabase::new();
        mock_db
            .expect_revoke_token()
            .returning(|_| Err(DbError::NotFound));

        let manager = create_test_manager(mock_db);
        let result = manager.revoke_token("nonexistent").await;

        assert!(matches!(result, Err(AuthError::TokenNotFound)));
    }

    // Test 10: list_tokens returns tokens
    #[tokio::test]
    async fn test_list_tokens() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_list_tokens().returning(|| {
            Ok(vec![
                Token::new("id1", "token1", "hash1"),
                Token::new("id2", "token2", "hash2"),
            ])
        });

        let manager = create_test_manager(mock_db);
        let result = manager.list_tokens().await;

        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert_eq!(tokens.len(), 2);
    }

    // Test 11: check_ecosystem_access with all allowed
    #[test]
    fn test_check_ecosystem_access_all_allowed() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let client = Client {
            id: "id1".to_string(),
            name: "test".to_string(),
            allowed_ecosystems: vec![],
        };

        assert!(manager.check_ecosystem_access(&client, "pypi"));
        assert!(manager.check_ecosystem_access(&client, "cargo"));
        assert!(manager.check_ecosystem_access(&client, "docker"));
    }

    // Test 12: check_ecosystem_access with wildcard
    #[test]
    fn test_check_ecosystem_access_wildcard() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let client = Client {
            id: "id1".to_string(),
            name: "test".to_string(),
            allowed_ecosystems: vec!["*".to_string()],
        };

        assert!(manager.check_ecosystem_access(&client, "pypi"));
        assert!(manager.check_ecosystem_access(&client, "anything"));
    }

    // Test 13: check_ecosystem_access with specific ecosystems
    #[test]
    fn test_check_ecosystem_access_specific() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let client = Client {
            id: "id1".to_string(),
            name: "test".to_string(),
            allowed_ecosystems: vec!["pypi".to_string(), "cargo".to_string()],
        };

        assert!(manager.check_ecosystem_access(&client, "pypi"));
        assert!(manager.check_ecosystem_access(&client, "cargo"));
        assert!(!manager.check_ecosystem_access(&client, "docker"));
    }

    // Test 14: check_ecosystem_access is case insensitive
    #[test]
    fn test_check_ecosystem_access_case_insensitive() {
        let mock_db = MockDatabase::new();
        let manager = create_test_manager(mock_db);

        let client = Client {
            id: "id1".to_string(),
            name: "test".to_string(),
            allowed_ecosystems: vec!["PyPI".to_string()],
        };

        assert!(manager.check_ecosystem_access(&client, "pypi"));
        assert!(manager.check_ecosystem_access(&client, "PYPI"));
        assert!(manager.check_ecosystem_access(&client, "PyPI"));
    }

    // Test 15: rate limiting blocks after max failures
    #[tokio::test]
    async fn test_rate_limiting() {
        let mut mock_db = MockDatabase::new();
        mock_db.expect_list_tokens().returning(|| Ok(vec![]));

        let manager = create_test_manager(mock_db);
        let ip = test_ip();

        // Fail multiple times
        for _ in 0..5 {
            let _ = manager.validate_token("rf_invalid", Some(ip)).await;
        }

        // Should be blocked now
        assert!(manager.is_rate_limited(ip));

        // Further requests should fail with rate limited error
        let result = manager.validate_token("rf_another", Some(ip)).await;
        assert!(matches!(result, Err(AuthError::RateLimited)));
    }

    // Test 16: successful auth resets rate limit
    #[tokio::test]
    async fn test_successful_auth_resets_rate_limit() {
        let (raw_token, _) = generate_token();
        let token_hash = hash_token(&raw_token).unwrap();
        let stored_token = Token::new("id1", "test-token", &token_hash);

        let mut mock_db = MockDatabase::new();
        mock_db
            .expect_list_tokens()
            .returning(move || Ok(vec![stored_token.clone()]));
        mock_db
            .expect_update_token_last_used()
            .returning(|_| Ok(()));

        let manager = create_test_manager(mock_db);
        let ip = test_ip();

        // Record some failures (but not enough to block)
        for _ in 0..3 {
            manager.rate_limiter.record_failure(ip);
        }

        // Successful auth
        let result = manager.validate_token(&raw_token, Some(ip)).await;
        assert!(result.is_ok());

        // Rate limit should be reset
        assert!(!manager.is_rate_limited(ip));
    }

    // Test 17: validate expired token fails
    #[tokio::test]
    async fn test_validate_expired_token() {
        let (raw_token, _) = generate_token();
        let token_hash = hash_token(&raw_token).unwrap();
        let mut stored_token = Token::new("id1", "test-token", &token_hash);
        // Set expiration in the past
        stored_token.expires_at = Some(Utc::now() - chrono::Duration::hours(1));

        let mut mock_db = MockDatabase::new();
        mock_db
            .expect_list_tokens()
            .returning(move || Ok(vec![stored_token.clone()]));

        let manager = create_test_manager(mock_db);
        let result = manager.validate_token(&raw_token, None).await;

        assert!(matches!(result, Err(AuthError::InvalidToken)));
    }

    // Test 18: create token with ecosystems
    #[tokio::test]
    async fn test_create_token_with_ecosystems() {
        let mut mock_db = MockDatabase::new();
        mock_db
            .expect_create_token()
            .withf(|token| {
                token.allowed_ecosystems == vec!["pypi".to_string(), "cargo".to_string()]
            })
            .returning(|_| Ok(()));

        let manager = create_test_manager(mock_db);
        let request = CreateTokenRequest::new("my-token")
            .with_ecosystems(vec!["pypi".to_string(), "cargo".to_string()]);

        let result = manager.create_token(request).await;
        assert!(result.is_ok());
    }
}
