//! Security source plugin trait definition
//!
//! This module defines the trait that all security source plugins must implement.
//! Security source plugins provide vulnerability and malware data from external
//! sources like OSV, OpenSSF Malicious Packages, and custom blocklists.

use async_trait::async_trait;
use std::time::Duration;

use crate::error::SyncError;
use crate::models::{BlockReason, BlockedPackage, SyncResult, SyncStatus};

/// Trait for security source plugins
///
/// Security source plugins are responsible for:
/// - Syncing vulnerability/malware data from external sources
/// - Checking if packages are blocked
/// - Providing lists of blocked packages by ecosystem
///
/// # Example
///
/// ```ignore
/// use registry_firewall::plugins::security::SecuritySourcePlugin;
/// use registry_firewall::error::SyncError;
/// use registry_firewall::models::{BlockReason, BlockedPackage, SyncResult, SyncStatus};
///
/// struct MySecurityPlugin {
///     // plugin state
/// }
///
/// #[async_trait]
/// impl SecuritySourcePlugin for MySecurityPlugin {
///     fn name(&self) -> &str {
///         "my-plugin"
///     }
///
///     fn supported_ecosystems(&self) -> &[String] {
///         &["pypi".to_string(), "cargo".to_string()]
///     }
///
///     async fn sync(&self) -> Result<SyncResult, SyncError> {
///         // Sync logic here
///         Ok(SyncResult::success(100))
///     }
///
///     // ... other methods
/// }
/// ```
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait SecuritySourcePlugin: Send + Sync {
    /// Get the plugin name
    ///
    /// This should be a unique identifier for the plugin (e.g., "osv", "openssf", "custom")
    fn name(&self) -> &str;

    /// Get the list of ecosystems this plugin supports
    ///
    /// Examples: ["pypi", "cargo", "go", "docker"]
    fn supported_ecosystems(&self) -> &[String];

    /// Synchronize data from the external source
    ///
    /// This method should:
    /// - Fetch latest data from the external source
    /// - Handle retries and rate limiting
    /// - Update internal state
    /// - Return the number of records updated
    ///
    /// # Returns
    ///
    /// - `Ok(SyncResult)` with records updated and skip status
    /// - `Err(SyncError)` if sync fails
    async fn sync(&self) -> Result<SyncResult, SyncError>;

    /// Get the sync interval for this plugin
    ///
    /// The scheduler will use this to determine how often to call `sync()`
    fn sync_interval(&self) -> Duration;

    /// Get the current sync status
    ///
    /// Returns information about the last sync, including:
    /// - When it occurred
    /// - Whether it succeeded
    /// - Number of records
    fn sync_status(&self) -> SyncStatus;

    /// Check if a specific package version is blocked
    ///
    /// # Arguments
    ///
    /// * `ecosystem` - The package ecosystem (pypi, cargo, go, docker)
    /// * `package` - The package name
    /// * `version` - The package version
    ///
    /// # Returns
    ///
    /// - `Some(BlockReason)` if the package is blocked
    /// - `None` if the package is not blocked
    async fn check_package(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<BlockReason>;

    /// Get all blocked packages for an ecosystem
    ///
    /// # Arguments
    ///
    /// * `ecosystem` - The package ecosystem to query
    ///
    /// # Returns
    ///
    /// A vector of blocked packages for the specified ecosystem
    async fn get_blocked_packages(&self, ecosystem: &str) -> Vec<BlockedPackage>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;

    // Test 1: MockSecuritySourcePlugin can be created
    #[tokio::test]
    async fn test_mock_plugin_creation() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_name().return_const("test-plugin".to_string());

        assert_eq!(mock.name(), "test-plugin");
    }

    // Test 2: Mock plugin returns supported ecosystems
    #[tokio::test]
    async fn test_mock_plugin_supported_ecosystems() {
        let mut mock = MockSecuritySourcePlugin::new();
        let ecosystems = vec!["pypi".to_string(), "cargo".to_string()];

        mock.expect_supported_ecosystems().return_const(ecosystems);

        let result = mock.supported_ecosystems();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"pypi".to_string()));
        assert!(result.contains(&"cargo".to_string()));
    }

    // Test 3: Mock plugin sync returns success
    #[tokio::test]
    async fn test_mock_plugin_sync_success() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_sync()
            .returning(|| Ok(SyncResult::success(100)));

        let result = mock.sync().await;
        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert_eq!(sync_result.records_updated, 100);
        assert!(!sync_result.skipped);
    }

    // Test 4: Mock plugin sync returns skipped
    #[tokio::test]
    async fn test_mock_plugin_sync_skipped() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_sync().returning(|| Ok(SyncResult::skipped()));

        let result = mock.sync().await;
        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert!(sync_result.skipped);
    }

    // Test 5: Mock plugin sync returns error
    #[tokio::test]
    async fn test_mock_plugin_sync_error() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_sync()
            .returning(|| Err(SyncError::NetworkTimeout));

        let result = mock.sync().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncError::NetworkTimeout));
    }

    // Test 6: Mock plugin sync interval
    #[tokio::test]
    async fn test_mock_plugin_sync_interval() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_sync_interval()
            .returning(|| Duration::from_secs(3600));

        let interval = mock.sync_interval();
        assert_eq!(interval, Duration::from_secs(3600));
    }

    // Test 7: Mock plugin check_package returns block reason
    #[tokio::test]
    async fn test_mock_plugin_check_package_blocked() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_check_package()
            .withf(|eco, pkg, ver| eco == "pypi" && pkg == "malicious-pkg" && ver == "1.0.0")
            .returning(|_, _, _| {
                Some(
                    BlockReason::new("test-plugin", "Known malware")
                        .with_severity(Severity::Critical)
                        .with_advisory_id("MAL-2024-001"),
                )
            });

        let result = mock.check_package("pypi", "malicious-pkg", "1.0.0").await;
        assert!(result.is_some());
        let reason = result.unwrap();
        assert_eq!(reason.source, "test-plugin");
        assert_eq!(reason.reason, "Known malware");
        assert_eq!(reason.severity, Severity::Critical);
        assert_eq!(reason.advisory_id, Some("MAL-2024-001".to_string()));
    }

    // Test 8: Mock plugin check_package returns None for safe package
    #[tokio::test]
    async fn test_mock_plugin_check_package_safe() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_check_package().returning(|_, _, _| None);

        let result = mock.check_package("pypi", "safe-pkg", "1.0.0").await;
        assert!(result.is_none());
    }

    // Test 9: Mock plugin get_blocked_packages returns list
    #[tokio::test]
    async fn test_mock_plugin_get_blocked_packages() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_get_blocked_packages()
            .withf(|eco| eco == "pypi")
            .returning(|_| {
                vec![
                    BlockedPackage::new("pypi", "malicious-pkg", "1.0.0", "test-plugin")
                        .with_reason("Known malware"),
                    BlockedPackage::new("pypi", "vulnerable-pkg", "2.0.0", "test-plugin")
                        .with_reason("Critical vulnerability"),
                ]
            });

        let result = mock.get_blocked_packages("pypi").await;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].package, "malicious-pkg");
        assert_eq!(result[1].package, "vulnerable-pkg");
    }

    // Test 10: Mock plugin get_blocked_packages returns empty for unsupported ecosystem
    #[tokio::test]
    async fn test_mock_plugin_get_blocked_packages_empty() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_get_blocked_packages().returning(|_| vec![]);

        let result = mock.get_blocked_packages("unknown").await;
        assert!(result.is_empty());
    }

    // Test 11: Mock plugin sync_status
    #[tokio::test]
    async fn test_mock_plugin_sync_status() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_sync_status()
            .returning(|| SyncStatus::new("test-plugin").success(500));

        let status = mock.sync_status();
        assert_eq!(status.source, "test-plugin");
        assert_eq!(status.records_count, 500);
    }

    // Test 12: Multiple calls to mock plugin work correctly
    #[tokio::test]
    async fn test_mock_plugin_multiple_calls() {
        let mut mock = MockSecuritySourcePlugin::new();

        mock.expect_name().return_const("test-plugin".to_string());

        assert_eq!(mock.name(), "test-plugin");
        assert_eq!(mock.name(), "test-plugin");
        assert_eq!(mock.name(), "test-plugin");
    }
}
