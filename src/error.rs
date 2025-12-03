//! Application error types for registry-firewall
//!
//! This module defines common error types used throughout the application.
//! All error types use `thiserror` for ergonomic error handling.

use thiserror::Error;

/// Authentication-related errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum AuthError {
    /// Invalid or expired token
    #[error("Invalid token")]
    InvalidToken,

    /// Token not found in database
    #[error("Token not found")]
    TokenNotFound,

    /// Invalid credentials for basic auth
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Rate limited due to too many failed attempts
    #[error("Rate limited: too many failed attempts")]
    RateLimited,

    /// Missing authorization header
    #[error("Missing authorization header")]
    MissingAuth,
}

/// Plugin-related errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum PluginError {
    /// Plugin not found
    #[error("Plugin not found: {0}")]
    NotFound(String),

    /// Plugin initialization failed
    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),

    /// Plugin configuration invalid
    #[error("Invalid plugin configuration: {0}")]
    InvalidConfig(String),
}

/// Cache-related errors
#[derive(Debug, Error)]
pub enum CacheError {
    /// IO error during cache operation
    #[error("Cache IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Cache serialization error: {0}")]
    Serialization(String),

    /// Cache entry not found
    #[error("Cache entry not found")]
    NotFound,

    /// Cache entry expired
    #[error("Cache entry expired")]
    Expired,
}

/// Database-related errors
#[derive(Debug, Error)]
pub enum DbError {
    /// SQLite error
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Record not found
    #[error("Record not found")]
    NotFound,

    /// Constraint violation
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Migration error
    #[error("Migration error: {0}")]
    Migration(String),
}

/// Synchronization-related errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SyncError {
    /// Network timeout
    #[error("Network timeout")]
    NetworkTimeout,

    /// Connection refused
    #[error("Connection refused")]
    ConnectionRefused,

    /// Rate limited by upstream
    #[error("Rate limited, retry after {0} seconds")]
    RateLimited(u64),

    /// Server error
    #[error("Server error: HTTP {0}")]
    ServerError(u16),

    /// Invalid data received
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Resource not found
    #[error("Resource not found")]
    NotFound,

    /// Unauthorized
    #[error("Unauthorized")]
    Unauthorized,

    /// Generic network error
    #[error("Network error: {0}")]
    Network(String),
}

/// Request parsing errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ParseError {
    /// Invalid path format
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Missing required parameter
    #[error("Missing parameter: {0}")]
    MissingParameter(String),

    /// Invalid package name
    #[error("Invalid package name: {0}")]
    InvalidPackageName(String),

    /// Invalid version
    #[error("Invalid version: {0}")]
    InvalidVersion(String),
}

/// Proxy-related errors
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Upstream request failed
    #[error("Upstream error: {0}")]
    Upstream(#[from] reqwest::Error),

    /// Package blocked
    #[error("Package blocked: {0}")]
    Blocked(String),

    /// Parse error
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    /// Cache error
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),
}

/// Metadata filtering errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum FilterError {
    /// Invalid metadata format
    #[error("Invalid metadata format: {0}")]
    InvalidFormat(String),

    /// Parse error
    #[error("Parse error: {0}")]
    Parse(String),
}

/// OpenTelemetry-related errors
#[derive(Debug, Error, Clone, PartialEq)]
pub enum OtelError {
    /// Failed to initialize tracer
    #[error("Failed to initialize tracer: {0}")]
    TracerInit(String),

    /// Failed to initialize meter
    #[error("Failed to initialize meter: {0}")]
    MeterInit(String),

    /// Export error
    #[error("Export error: {0}")]
    Export(String),
}

/// Application-level error type
///
/// This is the main error type used throughout the application.
/// It aggregates all domain-specific error types.
#[derive(Debug, Error)]
pub enum AppError {
    /// Authentication error
    #[error("Authentication failed: {0}")]
    Auth(#[from] AuthError),

    /// Plugin error
    #[error("Plugin error: {0}")]
    Plugin(#[from] PluginError),

    /// Cache error
    #[error("Cache error: {0}")]
    Cache(#[from] CacheError),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] DbError),

    /// Sync error
    #[error("Sync error: {0}")]
    Sync(#[from] SyncError),

    /// Proxy error
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Trait for determining if an error is retryable
pub trait RetryableError {
    /// Returns true if the error is retryable
    fn is_retryable(&self) -> bool;
}

impl RetryableError for SyncError {
    fn is_retryable(&self) -> bool {
        match self {
            // Retryable errors
            SyncError::NetworkTimeout => true,
            SyncError::ConnectionRefused => true,
            SyncError::RateLimited(_) => true,
            SyncError::ServerError(code) if *code >= 500 => true,
            SyncError::Network(_) => true,

            // Non-retryable errors
            SyncError::InvalidData(_) => false,
            SyncError::NotFound => false,
            SyncError::Unauthorized => false,
            SyncError::ServerError(_) => false, // 4xx errors
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Error message formatting
    #[test]
    fn test_auth_error_messages() {
        assert_eq!(AuthError::InvalidToken.to_string(), "Invalid token");
        assert_eq!(AuthError::TokenNotFound.to_string(), "Token not found");
        assert_eq!(
            AuthError::InvalidCredentials.to_string(),
            "Invalid credentials"
        );
        assert_eq!(
            AuthError::RateLimited.to_string(),
            "Rate limited: too many failed attempts"
        );
        assert_eq!(
            AuthError::MissingAuth.to_string(),
            "Missing authorization header"
        );
    }

    // Test 2: SyncError messages with parameters
    #[test]
    fn test_sync_error_messages() {
        assert_eq!(SyncError::NetworkTimeout.to_string(), "Network timeout");
        assert_eq!(
            SyncError::RateLimited(60).to_string(),
            "Rate limited, retry after 60 seconds"
        );
        assert_eq!(
            SyncError::ServerError(503).to_string(),
            "Server error: HTTP 503"
        );
        assert_eq!(
            SyncError::InvalidData("bad json".to_string()).to_string(),
            "Invalid data: bad json"
        );
    }

    // Test 3: From trait conversions for AppError
    #[test]
    fn test_app_error_from_auth_error() {
        let auth_err = AuthError::InvalidToken;
        let app_err: AppError = auth_err.into();

        match app_err {
            AppError::Auth(AuthError::InvalidToken) => (),
            _ => panic!("Expected AppError::Auth(AuthError::InvalidToken)"),
        }
    }

    // Test 4: From trait conversion for PluginError
    #[test]
    fn test_app_error_from_plugin_error() {
        let plugin_err = PluginError::NotFound("pypi".to_string());
        let app_err: AppError = plugin_err.into();

        match app_err {
            AppError::Plugin(PluginError::NotFound(name)) => {
                assert_eq!(name, "pypi");
            }
            _ => panic!("Expected AppError::Plugin(PluginError::NotFound)"),
        }
    }

    // Test 5: From trait conversion for SyncError
    #[test]
    fn test_app_error_from_sync_error() {
        let sync_err = SyncError::NetworkTimeout;
        let app_err: AppError = sync_err.into();

        match app_err {
            AppError::Sync(SyncError::NetworkTimeout) => (),
            _ => panic!("Expected AppError::Sync(SyncError::NetworkTimeout)"),
        }
    }

    // Test 6: RetryableError trait for SyncError
    #[test]
    fn test_sync_error_retryable() {
        // Retryable errors
        assert!(SyncError::NetworkTimeout.is_retryable());
        assert!(SyncError::ConnectionRefused.is_retryable());
        assert!(SyncError::RateLimited(30).is_retryable());
        assert!(SyncError::ServerError(500).is_retryable());
        assert!(SyncError::ServerError(503).is_retryable());
        assert!(SyncError::Network("connection reset".to_string()).is_retryable());

        // Non-retryable errors
        assert!(!SyncError::InvalidData("bad format".to_string()).is_retryable());
        assert!(!SyncError::NotFound.is_retryable());
        assert!(!SyncError::Unauthorized.is_retryable());
        assert!(!SyncError::ServerError(404).is_retryable()); // 4xx
    }

    // Test 7: CacheError from IO error
    #[test]
    fn test_cache_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let cache_err: CacheError = io_err.into();

        match cache_err {
            CacheError::Io(_) => (),
            _ => panic!("Expected CacheError::Io"),
        }
    }

    // Test 8: ProxyError from ParseError
    #[test]
    fn test_proxy_error_from_parse_error() {
        let parse_err = ParseError::InvalidPath("/invalid".to_string());
        let proxy_err: ProxyError = parse_err.into();

        match proxy_err {
            ProxyError::Parse(ParseError::InvalidPath(path)) => {
                assert_eq!(path, "/invalid");
            }
            _ => panic!("Expected ProxyError::Parse"),
        }
    }

    // Test 9: AppError display includes source error
    #[test]
    fn test_app_error_display() {
        let app_err = AppError::Auth(AuthError::InvalidToken);
        assert_eq!(app_err.to_string(), "Authentication failed: Invalid token");

        let app_err = AppError::Sync(SyncError::RateLimited(120));
        assert_eq!(
            app_err.to_string(),
            "Sync error: Rate limited, retry after 120 seconds"
        );
    }

    // Test 10: PluginError messages
    #[test]
    fn test_plugin_error_messages() {
        assert_eq!(
            PluginError::NotFound("cargo".to_string()).to_string(),
            "Plugin not found: cargo"
        );
        assert_eq!(
            PluginError::InitializationFailed("connection failed".to_string()).to_string(),
            "Plugin initialization failed: connection failed"
        );
        assert_eq!(
            PluginError::InvalidConfig("missing url".to_string()).to_string(),
            "Invalid plugin configuration: missing url"
        );
    }

    // Test 11: DbError messages
    #[test]
    fn test_db_error_messages() {
        assert_eq!(DbError::NotFound.to_string(), "Record not found");
        assert_eq!(
            DbError::ConstraintViolation("unique".to_string()).to_string(),
            "Constraint violation: unique"
        );
        assert_eq!(
            DbError::Migration("v2 failed".to_string()).to_string(),
            "Migration error: v2 failed"
        );
    }

    // Test 12: ParseError all variants
    #[test]
    fn test_parse_error_messages() {
        assert_eq!(
            ParseError::InvalidPath("/bad/path".to_string()).to_string(),
            "Invalid path: /bad/path"
        );
        assert_eq!(
            ParseError::MissingParameter("version".to_string()).to_string(),
            "Missing parameter: version"
        );
        assert_eq!(
            ParseError::InvalidPackageName("bad@name".to_string()).to_string(),
            "Invalid package name: bad@name"
        );
        assert_eq!(
            ParseError::InvalidVersion("not.a.version".to_string()).to_string(),
            "Invalid version: not.a.version"
        );
    }

    // Test 13: OtelError all variants
    #[test]
    fn test_otel_error_messages() {
        assert_eq!(
            OtelError::TracerInit("connection failed".to_string()).to_string(),
            "Failed to initialize tracer: connection failed"
        );
        assert_eq!(
            OtelError::MeterInit("invalid config".to_string()).to_string(),
            "Failed to initialize meter: invalid config"
        );
        assert_eq!(
            OtelError::Export("timeout".to_string()).to_string(),
            "Export error: timeout"
        );
    }

    // Test 14: FilterError all variants
    #[test]
    fn test_filter_error_messages() {
        assert_eq!(
            FilterError::InvalidFormat("not json".to_string()).to_string(),
            "Invalid metadata format: not json"
        );
        assert_eq!(
            FilterError::Parse("unexpected token".to_string()).to_string(),
            "Parse error: unexpected token"
        );
    }

    // Test 15: CacheError Serialization and Expired variants
    #[test]
    fn test_cache_error_all_variants() {
        assert_eq!(
            CacheError::Serialization("failed to encode".to_string()).to_string(),
            "Cache serialization error: failed to encode"
        );
        assert_eq!(CacheError::Expired.to_string(), "Cache entry expired");
        assert_eq!(CacheError::NotFound.to_string(), "Cache entry not found");
    }

    // Test 16: AppError Config and Internal variants
    #[test]
    fn test_app_error_config_and_internal() {
        let config_err = AppError::Config("missing field".to_string());
        assert_eq!(config_err.to_string(), "Configuration error: missing field");

        let internal_err = AppError::Internal("unexpected state".to_string());
        assert_eq!(internal_err.to_string(), "Internal error: unexpected state");
    }

    // Test 17: DbError from rusqlite::Error
    #[test]
    fn test_db_error_from_sqlite() {
        // Create a rusqlite error by attempting an invalid operation
        let sqlite_err = rusqlite::Error::InvalidParameterName("test".to_string());
        let db_err: DbError = sqlite_err.into();

        match db_err {
            DbError::Sqlite(_) => (),
            _ => panic!("Expected DbError::Sqlite"),
        }
    }

    // Test 18: PluginError Clone and PartialEq
    #[test]
    fn test_plugin_error_clone_and_eq() {
        let err1 = PluginError::NotFound("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = PluginError::NotFound("other".to_string());
        assert_ne!(err1, err3);
    }
}
