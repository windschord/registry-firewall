//! Minimum age plugin
//!
//! This module provides a security filter that blocks packages that are too new.
//! It checks the publication date of packages and blocks those published within
//! a configurable minimum age threshold.
//!
//! This is a real-time check plugin - it does not require syncing as it queries
//! registry APIs directly when checking packages.
//!
//! # Example
//!
//! ```ignore
//! use registry_firewall::plugins::security::minage::{MinAgePlugin, MinAgeConfig};
//!
//! let config = MinAgeConfig {
//!     min_age_hours: 72, // 3 days
//!     ..Default::default()
//! };
//! let plugin = MinAgePlugin::new(config);
//!
//! // Package published 1 hour ago would be blocked
//! if let Some(reason) = plugin.check_package("pypi", "new-pkg", "1.0.0").await {
//!     println!("Package blocked: {}", reason.reason);
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::SyncError;
use crate::models::{BlockReason, BlockedPackage, Severity, SyncResult, SyncStatus};
use crate::sync::HttpClientWithRateLimit;

use super::SecuritySourcePlugin;

/// Minimum age plugin configuration
#[derive(Debug, Clone)]
pub struct MinAgeConfig {
    /// Minimum age in hours before a package is allowed
    pub min_age_hours: u64,
    /// Supported ecosystems
    pub ecosystems: Vec<String>,
    /// Whether to block if age cannot be determined (default: false)
    pub block_unknown: bool,
}

impl Default for MinAgeConfig {
    fn default() -> Self {
        Self {
            min_age_hours: 72, // 3 days
            ecosystems: vec!["pypi".into(), "cargo".into()],
            block_unknown: false,
        }
    }
}

/// Publication date provider trait for testing
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PublishDateProvider: Send + Sync {
    /// Get the publication date for a package version
    async fn get_publish_date(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<DateTime<Utc>>;
}

/// Real publish date provider that queries registry APIs
pub struct RegistryPublishDateProvider {
    http_client: Arc<HttpClientWithRateLimit>,
}

impl RegistryPublishDateProvider {
    pub fn new(http_client: Arc<HttpClientWithRateLimit>) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl PublishDateProvider for RegistryPublishDateProvider {
    async fn get_publish_date(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<DateTime<Utc>> {
        let normalized_eco = normalize_ecosystem(ecosystem);

        match normalized_eco.as_str() {
            "pypi" => self.get_pypi_publish_date(package, version).await,
            "cargo" => self.get_crates_publish_date(package, version).await,
            _ => None,
        }
    }
}

impl RegistryPublishDateProvider {
    /// Get publish date from PyPI API
    async fn get_pypi_publish_date(&self, package: &str, version: &str) -> Option<DateTime<Utc>> {
        let url = format!("https://pypi.org/pypi/{}/{}/json", package, version);

        match self.http_client.get(&url).await {
            Ok(bytes) => {
                let response: PyPiResponse = match serde_json::from_slice(&bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(package = package, version = version, error = %e, "Failed to parse PyPI response");
                        return None;
                    }
                };

                // Try to parse the upload_time
                if let Some(upload_time) =
                    response.urls.first().and_then(|u| u.upload_time.as_ref())
                {
                    DateTime::parse_from_rfc3339(upload_time)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                        .or_else(|| {
                            // Try alternate format without timezone
                            chrono::NaiveDateTime::parse_from_str(upload_time, "%Y-%m-%dT%H:%M:%S")
                                .ok()
                                .map(|dt| dt.and_utc())
                        })
                } else {
                    None
                }
            }
            Err(e) => {
                warn!(package = package, version = version, error = %e, "Failed to get PyPI publish date");
                None
            }
        }
    }

    /// Get publish date from crates.io API
    async fn get_crates_publish_date(&self, package: &str, version: &str) -> Option<DateTime<Utc>> {
        let url = format!("https://crates.io/api/v1/crates/{}/{}", package, version);

        match self.http_client.get(&url).await {
            Ok(bytes) => {
                let response: CratesResponse = match serde_json::from_slice(&bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(package = package, version = version, error = %e, "Failed to parse crates.io response");
                        return None;
                    }
                };

                DateTime::parse_from_rfc3339(&response.version.created_at)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }
            Err(e) => {
                warn!(package = package, version = version, error = %e, "Failed to get crates.io publish date");
                None
            }
        }
    }
}

/// PyPI API response structure
#[derive(Debug, serde::Deserialize)]
struct PyPiResponse {
    #[serde(default)]
    urls: Vec<PyPiUrl>,
}

#[derive(Debug, serde::Deserialize)]
struct PyPiUrl {
    upload_time: Option<String>,
}

/// Crates.io API response structure
#[derive(Debug, serde::Deserialize)]
struct CratesResponse {
    version: CratesVersion,
}

#[derive(Debug, serde::Deserialize)]
struct CratesVersion {
    created_at: String,
}

/// Minimum age plugin
pub struct MinAgePlugin<P: PublishDateProvider = RegistryPublishDateProvider> {
    config: MinAgeConfig,
    provider: P,
    sync_status: RwLock<SyncStatus>,
}

impl MinAgePlugin<RegistryPublishDateProvider> {
    /// Create a new MinAge plugin with default registry provider
    pub fn new(config: MinAgeConfig) -> Result<Self, SyncError> {
        let http_client = HttpClientWithRateLimit::new(Default::default())?;
        Ok(Self {
            sync_status: RwLock::new(SyncStatus::new("minage")),
            config,
            provider: RegistryPublishDateProvider::new(Arc::new(http_client)),
        })
    }
}

impl<P: PublishDateProvider> MinAgePlugin<P> {
    /// Create a new MinAge plugin with a custom provider (for testing)
    pub fn with_provider(config: MinAgeConfig, provider: P) -> Self {
        Self {
            sync_status: RwLock::new(SyncStatus::new("minage")),
            config,
            provider,
        }
    }

    /// Check if a publish date is too new
    fn is_too_new(&self, publish_date: DateTime<Utc>) -> bool {
        let min_age = ChronoDuration::hours(self.config.min_age_hours as i64);
        let cutoff = Utc::now() - min_age;
        publish_date > cutoff
    }
}

#[async_trait]
impl<P: PublishDateProvider + 'static> SecuritySourcePlugin for MinAgePlugin<P> {
    fn name(&self) -> &str {
        "minage"
    }

    fn supported_ecosystems(&self) -> &[String] {
        &self.config.ecosystems
    }

    async fn sync(&self) -> Result<SyncResult, SyncError> {
        // No sync needed - real-time checking
        let mut status = self.sync_status.write().await;
        *status = status.clone().success(0);
        Ok(SyncResult::skipped())
    }

    fn sync_interval(&self) -> Duration {
        // No sync needed, return a large interval
        Duration::from_secs(86400) // 24 hours (not used)
    }

    fn sync_status(&self) -> SyncStatus {
        self.sync_status
            .try_read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| SyncStatus::new("minage"))
    }

    async fn check_package(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<BlockReason> {
        let normalized_eco = normalize_ecosystem(ecosystem);

        // Check if ecosystem is supported
        if !self
            .config
            .ecosystems
            .iter()
            .any(|e| normalize_ecosystem(e) == normalized_eco)
        {
            return None;
        }

        // Get publish date
        match self
            .provider
            .get_publish_date(&normalized_eco, package, version)
            .await
        {
            Some(publish_date) => {
                if self.is_too_new(publish_date) {
                    let age_hours = (Utc::now() - publish_date).num_hours();
                    let reason = format!(
                        "Package version too new ({}h old, minimum {}h required)",
                        age_hours, self.config.min_age_hours
                    );
                    debug!(
                        ecosystem = ecosystem,
                        package = package,
                        version = version,
                        age_hours = age_hours,
                        "Blocking new package"
                    );
                    Some(BlockReason::new("minage", &reason).with_severity(Severity::Medium))
                } else {
                    None
                }
            }
            None => {
                if self.config.block_unknown {
                    Some(
                        BlockReason::new("minage", "Unable to determine package age")
                            .with_severity(Severity::Low),
                    )
                } else {
                    None
                }
            }
        }
    }

    async fn get_blocked_packages(&self, _ecosystem: &str) -> Vec<BlockedPackage> {
        // Real-time check - no stored blocked packages
        Vec::new()
    }
}

/// Normalize ecosystem name
fn normalize_ecosystem(ecosystem: &str) -> String {
    match ecosystem.to_lowercase().as_str() {
        "pypi" => "pypi".to_string(),
        "crates.io" | "cargo" => "cargo".to_string(),
        "go" => "go".to_string(),
        other => other.to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SyncStatusValue;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    /// Test publish date provider that returns configured dates
    struct TestPublishDateProvider {
        dates: Mutex<HashMap<(String, String, String), DateTime<Utc>>>,
    }

    impl TestPublishDateProvider {
        fn new() -> Self {
            Self {
                dates: Mutex::new(HashMap::new()),
            }
        }

        async fn set_date(
            &self,
            ecosystem: &str,
            package: &str,
            version: &str,
            date: DateTime<Utc>,
        ) {
            self.dates.lock().await.insert(
                (
                    ecosystem.to_string(),
                    package.to_string(),
                    version.to_string(),
                ),
                date,
            );
        }
    }

    #[async_trait]
    impl PublishDateProvider for TestPublishDateProvider {
        async fn get_publish_date(
            &self,
            ecosystem: &str,
            package: &str,
            version: &str,
        ) -> Option<DateTime<Utc>> {
            self.dates
                .lock()
                .await
                .get(&(
                    ecosystem.to_string(),
                    package.to_string(),
                    version.to_string(),
                ))
                .cloned()
        }
    }

    // Test 1: Plugin creation
    #[test]
    fn test_minage_plugin_creation() {
        let config = MinAgeConfig::default();
        let provider = TestPublishDateProvider::new();
        let plugin = MinAgePlugin::with_provider(config, provider);
        assert_eq!(plugin.name(), "minage");
    }

    // Test 2: Default configuration
    #[test]
    fn test_minage_config_defaults() {
        let config = MinAgeConfig::default();
        assert_eq!(config.min_age_hours, 72);
        assert!(config.ecosystems.contains(&"pypi".to_string()));
        assert!(config.ecosystems.contains(&"cargo".to_string()));
        assert!(!config.block_unknown);
    }

    // Test 3: Sync returns skipped
    #[tokio::test]
    async fn test_sync_returns_skipped() {
        let config = MinAgeConfig::default();
        let provider = TestPublishDateProvider::new();
        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin.sync().await;
        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert!(sync_result.skipped);
        assert_eq!(sync_result.records_updated, 0);
    }

    // Test 4: Old package is allowed
    #[tokio::test]
    async fn test_old_package_allowed() {
        let config = MinAgeConfig {
            min_age_hours: 72,
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();

        // Set package published 100 hours ago
        let old_date = Utc::now() - ChronoDuration::hours(100);
        provider
            .set_date("pypi", "old-package", "1.0.0", old_date)
            .await;

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin.check_package("pypi", "old-package", "1.0.0").await;
        assert!(result.is_none());
    }

    // Test 5: New package is blocked
    #[tokio::test]
    async fn test_new_package_blocked() {
        let config = MinAgeConfig {
            min_age_hours: 72,
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();

        // Set package published 10 hours ago
        let new_date = Utc::now() - ChronoDuration::hours(10);
        provider
            .set_date("pypi", "new-package", "1.0.0", new_date)
            .await;

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin.check_package("pypi", "new-package", "1.0.0").await;
        assert!(result.is_some());
        let reason = result.unwrap();
        assert_eq!(reason.source, "minage");
        assert!(reason.reason.contains("too new"));
        assert_eq!(reason.severity, Severity::Medium);
    }

    // Test 6: Package at exactly minimum age is allowed
    #[tokio::test]
    async fn test_package_at_min_age_allowed() {
        let config = MinAgeConfig {
            min_age_hours: 72,
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();

        // Set package published exactly 73 hours ago (just over threshold)
        let date = Utc::now() - ChronoDuration::hours(73);
        provider
            .set_date("pypi", "edge-package", "1.0.0", date)
            .await;

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin.check_package("pypi", "edge-package", "1.0.0").await;
        assert!(result.is_none());
    }

    // Test 7: Unknown package with block_unknown=false is allowed
    #[tokio::test]
    async fn test_unknown_package_allowed_by_default() {
        let config = MinAgeConfig {
            min_age_hours: 72,
            block_unknown: false,
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();
        // No date set for this package

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin
            .check_package("pypi", "unknown-package", "1.0.0")
            .await;
        assert!(result.is_none());
    }

    // Test 8: Unknown package with block_unknown=true is blocked
    #[tokio::test]
    async fn test_unknown_package_blocked_when_configured() {
        let config = MinAgeConfig {
            min_age_hours: 72,
            block_unknown: true,
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();
        // No date set for this package

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin
            .check_package("pypi", "unknown-package", "1.0.0")
            .await;
        assert!(result.is_some());
        let reason = result.unwrap();
        assert!(reason.reason.contains("Unable to determine"));
        assert_eq!(reason.severity, Severity::Low);
    }

    // Test 9: Unsupported ecosystem returns None
    #[tokio::test]
    async fn test_unsupported_ecosystem() {
        let config = MinAgeConfig {
            ecosystems: vec!["pypi".to_string()], // Only pypi
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();

        // Even with a date set, cargo ecosystem should not be checked
        let new_date = Utc::now() - ChronoDuration::hours(1);
        provider
            .set_date("cargo", "new-package", "1.0.0", new_date)
            .await;

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin.check_package("cargo", "new-package", "1.0.0").await;
        assert!(result.is_none());
    }

    // Test 10: Get blocked packages returns empty
    #[tokio::test]
    async fn test_get_blocked_packages_empty() {
        let config = MinAgeConfig::default();
        let provider = TestPublishDateProvider::new();
        let plugin = MinAgePlugin::with_provider(config, provider);

        let blocked = plugin.get_blocked_packages("pypi").await;
        assert!(blocked.is_empty());
    }

    // Test 11: Sync status
    #[tokio::test]
    async fn test_sync_status() {
        let config = MinAgeConfig::default();
        let provider = TestPublishDateProvider::new();
        let plugin = MinAgePlugin::with_provider(config, provider);

        // Initial status
        let status = plugin.sync_status();
        assert_eq!(status.source, "minage");
        assert_eq!(status.status, SyncStatusValue::Pending);

        // After sync
        plugin.sync().await.unwrap();
        let status = plugin.sync_status();
        assert_eq!(status.status, SyncStatusValue::Success);
    }

    // Test 12: Ecosystem normalization
    #[test]
    fn test_ecosystem_normalization() {
        assert_eq!(normalize_ecosystem("PyPI"), "pypi");
        assert_eq!(normalize_ecosystem("PYPI"), "pypi");
        assert_eq!(normalize_ecosystem("Cargo"), "cargo");
        assert_eq!(normalize_ecosystem("crates.io"), "cargo");
        assert_eq!(normalize_ecosystem("Go"), "go");
    }

    // Test 13: Custom min age hours
    #[tokio::test]
    async fn test_custom_min_age() {
        let config = MinAgeConfig {
            min_age_hours: 24, // Only 24 hours
            ..Default::default()
        };
        let provider = TestPublishDateProvider::new();

        // Package published 30 hours ago - should be allowed with 24h threshold
        let date = Utc::now() - ChronoDuration::hours(30);
        provider
            .set_date("pypi", "test-package", "1.0.0", date)
            .await;

        let plugin = MinAgePlugin::with_provider(config, provider);

        let result = plugin.check_package("pypi", "test-package", "1.0.0").await;
        assert!(result.is_none());
    }
}
