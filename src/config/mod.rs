//! Configuration management for registry-firewall
//!
//! This module handles loading, parsing, and validating application configuration
//! from YAML files and environment variables.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Main application configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// HTTP server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// Registry plugin configurations
    #[serde(default)]
    pub registry_plugins: HashMap<String, RegistryPluginConfig>,

    /// Security plugin configurations
    #[serde(default)]
    pub security_plugins: HashMap<String, SecurityPluginConfig>,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,

    /// Database configuration
    #[serde(default)]
    pub database: DatabaseConfig,

    /// OpenTelemetry configuration
    #[serde(default)]
    pub otel: OtelConfig,

    /// Web UI configuration
    #[serde(default)]
    pub webui: WebUiConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    /// Load configuration from a YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::FileRead(format!("Failed to read config file: {}", e)))?;
        Self::from_yaml(&content)
    }

    /// Parse configuration from a YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        // First, expand environment variables in the YAML string
        let expanded = expand_env_vars(yaml);
        serde_yaml::from_str(&expanded)
            .map_err(|e| ConfigError::Parse(format!("Failed to parse YAML: {}", e)))
    }

    /// Load configuration from environment variables with prefix REGISTRY_FIREWALL_
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Config::default();

        // Server config from env
        if let Ok(host) = std::env::var("REGISTRY_FIREWALL_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("REGISTRY_FIREWALL_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|_| ConfigError::Parse("Invalid port number".to_string()))?;
        }

        // Database config from env
        if let Ok(path) = std::env::var("REGISTRY_FIREWALL_DATABASE_PATH") {
            config.database.path = path;
        }

        // Auth config from env
        if let Ok(enabled) = std::env::var("REGISTRY_FIREWALL_AUTH_ENABLED") {
            config.auth.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(password) = std::env::var("REGISTRY_FIREWALL_AUTH_ADMIN_PASSWORD") {
            config.auth.admin_password = Some(password);
        }

        // OTEL config from env
        if let Ok(enabled) = std::env::var("REGISTRY_FIREWALL_OTEL_ENABLED") {
            config.otel.enabled = enabled.parse().unwrap_or(false);
        }
        if let Ok(endpoint) = std::env::var("REGISTRY_FIREWALL_OTEL_ENDPOINT") {
            config.otel.endpoint = Some(endpoint);
        }

        Ok(config)
    }
}

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// Host address to bind to
    #[serde(default = "default_host")]
    pub host: String,

    /// Port to listen on
    #[serde(default = "default_port")]
    pub port: u16,

    /// Read timeout in seconds
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,

    /// Write timeout in seconds
    #[serde(default = "default_write_timeout")]
    pub write_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            read_timeout_secs: default_read_timeout(),
            write_timeout_secs: default_write_timeout(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_read_timeout() -> u64 {
    30
}

fn default_write_timeout() -> u64 {
    60
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthConfig {
    /// Whether authentication is enabled
    #[serde(default = "default_auth_enabled")]
    pub enabled: bool,

    /// Admin password for Web UI
    pub admin_password: Option<String>,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: AuthRateLimitConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_auth_enabled(),
            admin_password: None,
            rate_limit: AuthRateLimitConfig::default(),
        }
    }
}

fn default_auth_enabled() -> bool {
    true
}

/// Rate limiting configuration for authentication failures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthRateLimitConfig {
    /// Maximum number of failed attempts before blocking
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,

    /// Duration to block after max failures (in seconds)
    #[serde(default = "default_block_duration")]
    pub block_duration_secs: u64,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: default_max_failures(),
            block_duration_secs: default_block_duration(),
        }
    }
}

fn default_max_failures() -> u32 {
    10
}

fn default_block_duration() -> u64 {
    300
}

/// Registry plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryPluginConfig {
    /// Whether this plugin is enabled
    #[serde(default = "default_plugin_enabled")]
    pub enabled: bool,

    /// URL path prefix for this registry
    pub path_prefix: String,

    /// Upstream registry URL
    pub upstream: String,

    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,

    /// Plugin-specific options
    #[serde(default)]
    pub options: HashMap<String, String>,
}

fn default_plugin_enabled() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    86400 // 24 hours
}

/// Security plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityPluginConfig {
    /// Whether this plugin is enabled
    #[serde(default = "default_plugin_enabled")]
    pub enabled: bool,

    /// Sync interval in seconds
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,

    /// Target ecosystems
    #[serde(default)]
    pub ecosystems: Vec<String>,

    /// Plugin-specific options
    #[serde(default)]
    pub options: HashMap<String, String>,

    /// Retry configuration
    #[serde(default)]
    pub retry: RetryConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

fn default_sync_interval() -> u64 {
    3600 // 1 hour
}

/// Retry configuration for external API calls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial backoff duration in seconds
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_secs: u64,

    /// Maximum backoff duration in seconds
    #[serde(default = "default_max_backoff")]
    pub max_backoff_secs: u64,

    /// Backoff multiplier
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,

    /// Whether to add jitter to backoff
    #[serde(default = "default_jitter")]
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_secs: default_initial_backoff(),
            max_backoff_secs: default_max_backoff(),
            backoff_multiplier: default_backoff_multiplier(),
            jitter: default_jitter(),
        }
    }
}

fn default_max_retries() -> u32 {
    3
}

fn default_initial_backoff() -> u64 {
    5
}

fn default_max_backoff() -> u64 {
    300
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

fn default_jitter() -> bool {
    true
}

/// Rate limiting configuration for HTTP clients
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    /// Minimum interval between requests in milliseconds
    #[serde(default = "default_min_interval")]
    pub min_interval_ms: u64,

    /// Maximum number of concurrent requests
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,

    /// Wait time when rate limited (in seconds)
    #[serde(default = "default_rate_limit_wait")]
    pub rate_limit_wait_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            min_interval_ms: default_min_interval(),
            max_concurrent: default_max_concurrent(),
            rate_limit_wait_secs: default_rate_limit_wait(),
        }
    }
}

fn default_min_interval() -> u64 {
    1000
}

fn default_max_concurrent() -> usize {
    2
}

fn default_rate_limit_wait() -> u64 {
    60
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheConfig {
    /// Cache plugin to use
    #[serde(default = "default_cache_plugin")]
    pub plugin: String,

    /// Filesystem cache configuration
    #[serde(default)]
    pub filesystem: FilesystemCacheConfig,

    /// Redis cache configuration (optional)
    #[serde(default)]
    pub redis: Option<RedisCacheConfig>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            plugin: default_cache_plugin(),
            filesystem: FilesystemCacheConfig::default(),
            redis: None,
        }
    }
}

fn default_cache_plugin() -> String {
    "filesystem".to_string()
}

/// Filesystem cache configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilesystemCacheConfig {
    /// Base path for cache storage
    #[serde(default = "default_cache_base_path")]
    pub base_path: String,

    /// Maximum cache size in GB
    #[serde(default = "default_max_size_gb")]
    pub max_size_gb: u64,
}

impl Default for FilesystemCacheConfig {
    fn default() -> Self {
        Self {
            base_path: default_cache_base_path(),
            max_size_gb: default_max_size_gb(),
        }
    }
}

fn default_cache_base_path() -> String {
    "/data/cache".to_string()
}

fn default_max_size_gb() -> u64 {
    50
}

/// Redis cache configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedisCacheConfig {
    /// Redis connection URL
    pub url: String,

    /// Key prefix
    #[serde(default = "default_redis_prefix")]
    pub prefix: String,
}

fn default_redis_prefix() -> String {
    "rf:".to_string()
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DatabaseConfig {
    /// Path to SQLite database file
    #[serde(default = "default_database_path")]
    pub path: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_database_path(),
        }
    }
}

fn default_database_path() -> String {
    "/data/db/registry-firewall.db".to_string()
}

/// OpenTelemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OtelConfig {
    /// Whether OpenTelemetry is enabled
    #[serde(default)]
    pub enabled: bool,

    /// OTLP endpoint URL
    pub endpoint: Option<String>,

    /// Whether to use insecure connection
    #[serde(default)]
    pub insecure: bool,

    /// Service name for tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            insecure: false,
            service_name: default_service_name(),
        }
    }
}

fn default_service_name() -> String {
    "registry-firewall".to_string()
}

/// Web UI configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebUiConfig {
    /// Whether Web UI is enabled
    #[serde(default = "default_webui_enabled")]
    pub enabled: bool,

    /// URL path prefix for Web UI
    #[serde(default = "default_webui_path")]
    pub path_prefix: String,
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self {
            enabled: default_webui_enabled(),
            path_prefix: default_webui_path(),
        }
    }
}

fn default_webui_enabled() -> bool {
    true
}

fn default_webui_path() -> String {
    "/ui".to_string()
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

/// Configuration error types
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum ConfigError {
    /// Error reading configuration file
    #[error("Failed to read configuration file: {0}")]
    FileRead(String),

    /// Error parsing configuration
    #[error("Failed to parse configuration: {0}")]
    Parse(String),

    /// Invalid configuration value
    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),

    /// Missing required configuration
    #[error("Missing required configuration: {0}")]
    MissingRequired(String),
}

/// Expand environment variables in a string
///
/// Supports `${VAR_NAME}` syntax
fn expand_env_vars(input: &str) -> String {
    let re = regex_lite::Regex::new(r"\$\{([^}]+)\}")
        .expect("Invalid regex pattern for environment variable expansion");

    re.replace_all(input, |caps: &regex_lite::Captures| {
        let var_name = &caps[1];
        std::env::var(var_name).unwrap_or_else(|_| caps[0].to_string())
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Parse complete configuration from YAML
    #[test]
    fn test_parse_complete_yaml_config() {
        let yaml = r#"
server:
  host: "127.0.0.1"
  port: 9090
  read_timeout_secs: 45
  write_timeout_secs: 90

auth:
  enabled: true
  admin_password: "secret123"
  rate_limit:
    max_failures: 5
    block_duration_secs: 600

registry_plugins:
  pypi:
    enabled: true
    path_prefix: "/pypi"
    upstream: "https://pypi.org"
    cache_ttl_secs: 3600

security_plugins:
  osv:
    enabled: true
    sync_interval_secs: 7200
    ecosystems: ["pypi", "go"]
    retry:
      max_retries: 5
      initial_backoff_secs: 10
    rate_limit:
      min_interval_ms: 2000
      max_concurrent: 4

cache:
  plugin: "filesystem"
  filesystem:
    base_path: "/tmp/cache"
    max_size_gb: 100

database:
  path: "/tmp/test.db"

otel:
  enabled: true
  endpoint: "http://localhost:4317"
  service_name: "test-service"

webui:
  enabled: true
  path_prefix: "/admin"

logging:
  level: "debug"
  format: "pretty"
"#;

        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
        assert_eq!(config.server.read_timeout_secs, 45);
        assert_eq!(config.server.write_timeout_secs, 90);

        assert!(config.auth.enabled);
        assert_eq!(config.auth.admin_password, Some("secret123".to_string()));
        assert_eq!(config.auth.rate_limit.max_failures, 5);
        assert_eq!(config.auth.rate_limit.block_duration_secs, 600);

        let pypi = config.registry_plugins.get("pypi").unwrap();
        assert!(pypi.enabled);
        assert_eq!(pypi.path_prefix, "/pypi");
        assert_eq!(pypi.upstream, "https://pypi.org");
        assert_eq!(pypi.cache_ttl_secs, 3600);

        let osv = config.security_plugins.get("osv").unwrap();
        assert!(osv.enabled);
        assert_eq!(osv.sync_interval_secs, 7200);
        assert_eq!(osv.ecosystems, vec!["pypi", "go"]);
        assert_eq!(osv.retry.max_retries, 5);
        assert_eq!(osv.rate_limit.min_interval_ms, 2000);

        assert_eq!(config.cache.plugin, "filesystem");
        assert_eq!(config.cache.filesystem.base_path, "/tmp/cache");
        assert_eq!(config.cache.filesystem.max_size_gb, 100);

        assert_eq!(config.database.path, "/tmp/test.db");

        assert!(config.otel.enabled);
        assert_eq!(
            config.otel.endpoint,
            Some("http://localhost:4317".to_string())
        );

        assert!(config.webui.enabled);
        assert_eq!(config.webui.path_prefix, "/admin");

        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "pretty");
    }

    // Test 2: Default values are applied for missing fields
    #[test]
    fn test_default_values_applied() {
        let yaml = r#"
server:
  port: 3000
"#;

        let config = Config::from_yaml(yaml).unwrap();

        // Server defaults
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000); // specified value
        assert_eq!(config.server.read_timeout_secs, 30);
        assert_eq!(config.server.write_timeout_secs, 60);

        // Auth defaults
        assert!(config.auth.enabled);
        assert_eq!(config.auth.admin_password, None);
        assert_eq!(config.auth.rate_limit.max_failures, 10);
        assert_eq!(config.auth.rate_limit.block_duration_secs, 300);

        // Cache defaults
        assert_eq!(config.cache.plugin, "filesystem");
        assert_eq!(config.cache.filesystem.base_path, "/data/cache");
        assert_eq!(config.cache.filesystem.max_size_gb, 50);

        // Database defaults
        assert_eq!(config.database.path, "/data/db/registry-firewall.db");

        // OTEL defaults
        assert!(!config.otel.enabled);
        assert_eq!(config.otel.endpoint, None);
        assert_eq!(config.otel.service_name, "registry-firewall");

        // WebUI defaults
        assert!(config.webui.enabled);
        assert_eq!(config.webui.path_prefix, "/ui");

        // Logging defaults
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
    }

    // Test 3: Environment variable expansion
    #[test]
    fn test_env_var_expansion() {
        // Set environment variables for test
        std::env::set_var("TEST_ADMIN_PASSWORD", "env_secret");
        std::env::set_var("TEST_DB_PATH", "/var/data/test.db");

        let yaml = r#"
auth:
  admin_password: "${TEST_ADMIN_PASSWORD}"

database:
  path: "${TEST_DB_PATH}"
"#;

        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config.auth.admin_password, Some("env_secret".to_string()));
        assert_eq!(config.database.path, "/var/data/test.db");

        // Clean up
        std::env::remove_var("TEST_ADMIN_PASSWORD");
        std::env::remove_var("TEST_DB_PATH");
    }

    // Test 4: from_env loads config from environment variables
    #[test]
    fn test_from_env() {
        // Set environment variables
        std::env::set_var("REGISTRY_FIREWALL_SERVER_HOST", "localhost");
        std::env::set_var("REGISTRY_FIREWALL_SERVER_PORT", "9999");
        std::env::set_var("REGISTRY_FIREWALL_DATABASE_PATH", "/env/test.db");
        std::env::set_var("REGISTRY_FIREWALL_AUTH_ENABLED", "false");
        std::env::set_var("REGISTRY_FIREWALL_AUTH_ADMIN_PASSWORD", "admin123");
        std::env::set_var("REGISTRY_FIREWALL_OTEL_ENABLED", "true");
        std::env::set_var("REGISTRY_FIREWALL_OTEL_ENDPOINT", "http://otel:4317");

        let config = Config::from_env().unwrap();

        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 9999);
        assert_eq!(config.database.path, "/env/test.db");
        assert!(!config.auth.enabled);
        assert_eq!(config.auth.admin_password, Some("admin123".to_string()));
        assert!(config.otel.enabled);
        assert_eq!(config.otel.endpoint, Some("http://otel:4317".to_string()));

        // Clean up
        std::env::remove_var("REGISTRY_FIREWALL_SERVER_HOST");
        std::env::remove_var("REGISTRY_FIREWALL_SERVER_PORT");
        std::env::remove_var("REGISTRY_FIREWALL_DATABASE_PATH");
        std::env::remove_var("REGISTRY_FIREWALL_AUTH_ENABLED");
        std::env::remove_var("REGISTRY_FIREWALL_AUTH_ADMIN_PASSWORD");
        std::env::remove_var("REGISTRY_FIREWALL_OTEL_ENABLED");
        std::env::remove_var("REGISTRY_FIREWALL_OTEL_ENDPOINT");
    }

    // Test 5: Parse error for invalid YAML
    #[test]
    fn test_parse_error_invalid_yaml() {
        let yaml = r#"
server:
  port: "not_a_number"
"#;

        let result = Config::from_yaml(yaml);
        assert!(result.is_err());
        match result {
            Err(ConfigError::Parse(msg)) => {
                assert!(msg.contains("Failed to parse YAML"));
            }
            _ => panic!("Expected ConfigError::Parse"),
        }
    }

    // Test 6: RetryConfig default values
    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();

        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_secs, 5);
        assert_eq!(config.max_backoff_secs, 300);
        assert!((config.backoff_multiplier - 2.0).abs() < f64::EPSILON);
        assert!(config.jitter);
    }

    // Test 7: RateLimitConfig default values
    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();

        assert_eq!(config.min_interval_ms, 1000);
        assert_eq!(config.max_concurrent, 2);
        assert_eq!(config.rate_limit_wait_secs, 60);
    }

    // Test 8: Config serialization round-trip
    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config::default();

        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(config, parsed);
    }

    // Test 9: Empty YAML results in defaults
    #[test]
    fn test_empty_yaml_defaults() {
        let yaml = "{}";
        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config, Config::default());
    }

    // Test 10: Multiple registry plugins
    #[test]
    fn test_multiple_registry_plugins() {
        let yaml = r#"
registry_plugins:
  pypi:
    enabled: true
    path_prefix: "/pypi"
    upstream: "https://pypi.org"
  cargo:
    enabled: true
    path_prefix: "/cargo"
    upstream: "https://index.crates.io"
    options:
      dl_upstream: "https://static.crates.io/crates"
  go:
    enabled: false
    path_prefix: "/go"
    upstream: "https://proxy.golang.org"
"#;

        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config.registry_plugins.len(), 3);

        let pypi = config.registry_plugins.get("pypi").unwrap();
        assert!(pypi.enabled);
        assert_eq!(pypi.upstream, "https://pypi.org");

        let cargo = config.registry_plugins.get("cargo").unwrap();
        assert!(cargo.enabled);
        assert_eq!(
            cargo.options.get("dl_upstream"),
            Some(&"https://static.crates.io/crates".to_string())
        );

        let go = config.registry_plugins.get("go").unwrap();
        assert!(!go.enabled);
    }

    // Test 11: Multiple security plugins
    #[test]
    fn test_multiple_security_plugins() {
        let yaml = r#"
security_plugins:
  osv:
    enabled: true
    sync_interval_secs: 3600
    ecosystems: ["pypi"]
  openssf_malicious:
    enabled: true
    sync_interval_secs: 1800
    ecosystems: ["pypi", "npm"]
  custom_blocklist:
    enabled: true
    sync_interval_secs: 300
    options:
      file_path: "/config/blocklist.yaml"
"#;

        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config.security_plugins.len(), 3);

        let osv = config.security_plugins.get("osv").unwrap();
        assert_eq!(osv.sync_interval_secs, 3600);

        let openssf = config.security_plugins.get("openssf_malicious").unwrap();
        assert_eq!(openssf.ecosystems, vec!["pypi", "npm"]);

        let custom = config.security_plugins.get("custom_blocklist").unwrap();
        assert_eq!(
            custom.options.get("file_path"),
            Some(&"/config/blocklist.yaml".to_string())
        );
    }

    // Test 12: Redis cache config
    #[test]
    fn test_redis_cache_config() {
        let yaml = r#"
cache:
  plugin: "redis"
  redis:
    url: "redis://localhost:6379"
    prefix: "cache:"
"#;

        let config = Config::from_yaml(yaml).unwrap();

        assert_eq!(config.cache.plugin, "redis");
        let redis = config.cache.redis.as_ref().unwrap();
        assert_eq!(redis.url, "redis://localhost:6379");
        assert_eq!(redis.prefix, "cache:");
    }
}
