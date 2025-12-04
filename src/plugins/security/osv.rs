//! OSV (Open Source Vulnerabilities) database plugin
//!
//! This module provides integration with the OSV database for vulnerability information.
//! It downloads and parses OSV data from Google Cloud Storage buckets.
//!
//! # Data Source
//!
//! OSV data is available at: `https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip`
//!
//! Supported ecosystems:
//! - PyPI
//! - Go
//! - crates.io
//!
//! # Example
//!
//! ```ignore
//! use registry_firewall::plugins::security::osv::{OsvPlugin, OsvConfig};
//!
//! let plugin = OsvPlugin::new(OsvConfig::default());
//! plugin.sync().await?;
//!
//! if let Some(reason) = plugin.check_package("pypi", "requests", "2.30.0").await {
//!     println!("Package blocked: {}", reason.reason);
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zip::ZipArchive;

use crate::config::{RateLimitConfig, RetryConfig};
use crate::error::SyncError;
use crate::models::{BlockReason, BlockedPackage, Severity, SyncResult, SyncStatus};
use crate::sync::{ConditionalResponse, HttpClientWithRateLimit, RetryManager};

use super::SecuritySourcePlugin;

/// Default base URL for OSV data
pub const DEFAULT_OSV_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";

/// OSV plugin configuration
#[derive(Debug, Clone)]
pub struct OsvConfig {
    /// Base URL for OSV data (default: GCS bucket)
    pub base_url: String,
    /// Sync interval in seconds
    pub sync_interval_secs: u64,
    /// Target ecosystems to sync
    pub ecosystems: Vec<String>,
    /// Minimum severity to include (None = all)
    pub min_severity: Option<Severity>,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Rate limit configuration
    pub rate_limit: RateLimitConfig,
}

impl Default for OsvConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_OSV_BASE_URL.to_string(),
            sync_interval_secs: 3600, // 1 hour
            ecosystems: vec![
                "PyPI".to_string(),
                "Go".to_string(),
                "crates.io".to_string(),
            ],
            min_severity: Some(Severity::Medium),
            retry: RetryConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Cache state for each ecosystem
#[derive(Debug, Clone, Default)]
struct EcosystemCache {
    /// ETag from last response
    etag: Option<String>,
    /// Last-Modified from last response
    last_modified: Option<String>,
}

/// Internal cache state
#[derive(Debug, Default)]
struct OsvCacheState {
    /// Per-ecosystem cache headers
    ecosystems: HashMap<String, EcosystemCache>,
}

/// In-memory blocked packages store
#[derive(Debug, Default)]
struct BlockedPackagesStore {
    /// Blocked packages by ecosystem -> package name -> version -> entry
    packages: HashMap<String, HashMap<String, HashMap<String, OsvBlockEntry>>>,
}

/// OSV block entry with full details
#[derive(Debug, Clone)]
struct OsvBlockEntry {
    advisory_id: String,
    reason: String,
    severity: Severity,
}

/// OSV plugin for vulnerability detection
pub struct OsvPlugin {
    config: OsvConfig,
    http_client: Arc<HttpClientWithRateLimit>,
    retry_manager: RetryManager,
    cache_state: RwLock<OsvCacheState>,
    blocked_packages: RwLock<BlockedPackagesStore>,
    sync_status: RwLock<SyncStatus>,
}

impl OsvPlugin {
    /// Create a new OSV plugin with the given configuration
    pub fn new(config: OsvConfig) -> Result<Self, SyncError> {
        let http_client = HttpClientWithRateLimit::new(config.rate_limit.clone())?;
        let retry_manager = RetryManager::new(config.retry.clone());

        Ok(Self {
            sync_status: RwLock::new(SyncStatus::new("osv")),
            config,
            http_client: Arc::new(http_client),
            retry_manager,
            cache_state: RwLock::new(OsvCacheState::default()),
            blocked_packages: RwLock::new(BlockedPackagesStore::default()),
        })
    }

    /// Create a new OSV plugin with a custom HTTP client (for testing)
    #[cfg(test)]
    pub fn with_http_client(config: OsvConfig, http_client: Arc<HttpClientWithRateLimit>) -> Self {
        let retry_manager = RetryManager::new(config.retry.clone());

        Self {
            sync_status: RwLock::new(SyncStatus::new("osv")),
            config,
            http_client,
            retry_manager,
            cache_state: RwLock::new(OsvCacheState::default()),
            blocked_packages: RwLock::new(BlockedPackagesStore::default()),
        }
    }

    /// Set cache ETag for testing
    #[cfg(test)]
    pub async fn set_cache_etag(&self, ecosystem: &str, etag: &str) {
        let mut cache = self.cache_state.write().await;
        cache
            .ecosystems
            .entry(ecosystem.to_string())
            .or_default()
            .etag = Some(etag.to_string());
    }

    /// Sync a single ecosystem
    async fn sync_ecosystem(&self, ecosystem: &str) -> Result<u64, SyncError> {
        let url = format!("{}/{}/all.zip", self.config.base_url, ecosystem);

        // Get cached headers
        let (etag, last_modified) = {
            let cache = self.cache_state.read().await;
            let cached = cache.ecosystems.get(ecosystem);
            (
                cached.and_then(|c| c.etag.clone()),
                cached.and_then(|c| c.last_modified.clone()),
            )
        };

        debug!(ecosystem = ecosystem, url = url, "Syncing OSV data");

        // Fetch with retry
        let response = self
            .retry_manager
            .execute(|| async {
                self.http_client
                    .get_with_cache_headers(&url, etag.as_deref(), last_modified.as_deref())
                    .await
            })
            .await?;

        match response {
            ConditionalResponse::NotModified => {
                debug!(ecosystem = ecosystem, "OSV data not modified (304)");
                Ok(0)
            }
            ConditionalResponse::Modified {
                body,
                etag: new_etag,
                last_modified: new_last_modified,
            } => {
                // Update cache headers
                let mut cache = self.cache_state.write().await;
                let entry = cache.ecosystems.entry(ecosystem.to_string()).or_default();
                entry.etag = new_etag;
                entry.last_modified = new_last_modified;
                drop(cache);

                // Parse ZIP and update blocked packages
                let records = self.process_osv_zip(&body, ecosystem).await?;
                info!(ecosystem = ecosystem, records = records, "Updated OSV data");

                Ok(records)
            }
        }
    }

    /// Process OSV ZIP file and update blocked packages
    async fn process_osv_zip(&self, data: &[u8], ecosystem: &str) -> Result<u64, SyncError> {
        let cursor = std::io::Cursor::new(data);
        let mut archive = ZipArchive::new(cursor)
            .map_err(|e| SyncError::InvalidData(format!("Failed to open ZIP: {}", e)))?;

        let mut records = 0u64;
        let mut new_packages: HashMap<String, HashMap<String, OsvBlockEntry>> = HashMap::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| {
                SyncError::InvalidData(format!("Failed to read ZIP entry {}: {}", i, e))
            })?;

            // Only process .json files
            let name = file.name().to_string();
            if !name.ends_with(".json") {
                continue;
            }

            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| SyncError::InvalidData(format!("Failed to read {}: {}", name, e)))?;

            // Parse OSV entry
            match serde_json::from_str::<OsvEntry>(&contents) {
                Ok(entry) => {
                    // Process affected packages
                    for affected in &entry.affected {
                        // Map ecosystem names
                        let entry_ecosystem = normalize_ecosystem(&affected.package.ecosystem);
                        let target_ecosystem = normalize_ecosystem(ecosystem);

                        if entry_ecosystem != target_ecosystem {
                            continue;
                        }

                        // Extract severity
                        let severity = entry.extract_severity();

                        // Check minimum severity filter
                        if let Some(min_sev) = &self.config.min_severity {
                            if severity < *min_sev {
                                continue;
                            }
                        }

                        // Extract affected versions
                        let versions =
                            extract_affected_versions(&affected.ranges, &affected.versions);

                        for version in versions {
                            let pkg_name = affected.package.name.to_lowercase();
                            new_packages.entry(pkg_name.clone()).or_default().insert(
                                version.clone(),
                                OsvBlockEntry {
                                    advisory_id: entry.id.clone(),
                                    reason: entry
                                        .summary
                                        .clone()
                                        .unwrap_or_else(|| format!("Vulnerability {}", entry.id)),
                                    severity,
                                },
                            );
                            records += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(file = name, error = %e, "Failed to parse OSV entry");
                }
            }
        }

        // Update blocked packages store
        let mut store = self.blocked_packages.write().await;
        store
            .packages
            .insert(normalize_ecosystem(ecosystem), new_packages);

        Ok(records)
    }
}

#[async_trait]
impl SecuritySourcePlugin for OsvPlugin {
    fn name(&self) -> &str {
        "osv"
    }

    fn supported_ecosystems(&self) -> &[String] {
        &self.config.ecosystems
    }

    async fn sync(&self) -> Result<SyncResult, SyncError> {
        // Update status to in-progress
        {
            let mut status = self.sync_status.write().await;
            *status = status.clone().in_progress();
        }

        let mut total_records = 0u64;
        let mut had_updates = false;

        for ecosystem in &self.config.ecosystems {
            match self.sync_ecosystem(ecosystem).await {
                Ok(records) => {
                    if records > 0 {
                        had_updates = true;
                        total_records += records;
                    }
                }
                Err(e) => {
                    error!(ecosystem = ecosystem, error = %e, "Failed to sync OSV ecosystem");
                    // Update status to failed
                    let mut status = self.sync_status.write().await;
                    *status = status.clone().failed(e.to_string());
                    return Err(e);
                }
            }
        }

        // Update status to success
        let mut status = self.sync_status.write().await;
        *status = status.clone().success(total_records);

        Ok(SyncResult {
            records_updated: total_records,
            skipped: !had_updates,
            message: None,
        })
    }

    fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.config.sync_interval_secs)
    }

    fn sync_status(&self) -> SyncStatus {
        // Use try_read to avoid blocking, return default if locked
        self.sync_status
            .try_read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| SyncStatus::new("osv"))
    }

    async fn check_package(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<BlockReason> {
        let store = self.blocked_packages.read().await;
        let normalized_eco = normalize_ecosystem(ecosystem);
        let normalized_pkg = package.to_lowercase();

        store
            .packages
            .get(&normalized_eco)
            .and_then(|pkgs| pkgs.get(&normalized_pkg))
            .and_then(|versions| versions.get(version))
            .map(|entry| {
                BlockReason::new("osv", &entry.reason)
                    .with_severity(entry.severity)
                    .with_advisory_id(&entry.advisory_id)
            })
    }

    async fn get_blocked_packages(&self, ecosystem: &str) -> Vec<BlockedPackage> {
        let store = self.blocked_packages.read().await;
        let normalized_eco = normalize_ecosystem(ecosystem);

        store
            .packages
            .get(&normalized_eco)
            .map(|pkgs| {
                pkgs.iter()
                    .flat_map(|(pkg_name, versions)| {
                        let pkg_name = pkg_name.clone();
                        let normalized_eco = normalized_eco.clone();
                        versions.iter().map(move |(version, entry)| {
                            BlockedPackage::new(&normalized_eco, &pkg_name, version, "osv")
                                .with_reason(&entry.reason)
                                .with_severity(entry.severity)
                                .with_advisory_id(&entry.advisory_id)
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Normalize ecosystem name for consistent comparison
fn normalize_ecosystem(ecosystem: &str) -> String {
    match ecosystem.to_lowercase().as_str() {
        "pypi" => "pypi".to_string(),
        "go" => "go".to_string(),
        "crates.io" | "cargo" => "crates.io".to_string(),
        other => other.to_lowercase(),
    }
}

/// Extract affected versions from ranges and explicit version lists
fn extract_affected_versions(ranges: &[Range], explicit_versions: &[String]) -> Vec<String> {
    let mut versions = Vec::new();

    // Add explicit versions
    versions.extend(explicit_versions.iter().cloned());

    // For SEMVER ranges, we can't enumerate all versions without a registry lookup
    // In a real implementation, this would query the registry for all versions
    // and filter based on the range. For now, we only use explicit versions.

    // TODO: Implement semver range matching against registry version list
    for _range in ranges {
        // Range matching would go here
    }

    versions
}

// ============================================================================
// OSV JSON Schema Types
// ============================================================================

/// OSV vulnerability entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvEntry {
    /// Unique vulnerability ID (e.g., "GHSA-xxx", "CVE-xxx")
    pub id: String,

    /// Summary of the vulnerability
    pub summary: Option<String>,

    /// Detailed description
    pub details: Option<String>,

    /// Affected packages
    #[serde(default)]
    pub affected: Vec<Affected>,

    /// Severity information
    pub severity: Option<Vec<OsvSeverity>>,

    /// Database-specific severity
    pub database_specific: Option<DatabaseSpecific>,
}

impl OsvEntry {
    /// Extract the highest severity from the entry
    fn extract_severity(&self) -> Severity {
        // Try severity array first
        if let Some(severities) = &self.severity {
            for sev in severities {
                if let Some(score) = &sev.score {
                    // CVSS score ranges
                    if let Ok(score_val) = score.parse::<f64>() {
                        return match score_val {
                            x if x >= 9.0 => Severity::Critical,
                            x if x >= 7.0 => Severity::High,
                            x if x >= 4.0 => Severity::Medium,
                            x if x > 0.0 => Severity::Low,
                            _ => Severity::Unknown,
                        };
                    }
                }
            }
        }

        // Try database_specific severity (GitHub format)
        if let Some(db_specific) = &self.database_specific {
            if let Some(sev) = &db_specific.severity {
                return match sev.to_uppercase().as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MODERATE" | "MEDIUM" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Unknown,
                };
            }
        }

        Severity::Unknown
    }
}

/// OSV severity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvSeverity {
    /// Severity type (e.g., "CVSS_V3")
    #[serde(rename = "type")]
    pub severity_type: Option<String>,

    /// Severity score
    pub score: Option<String>,
}

/// Database-specific information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSpecific {
    /// Severity string (GitHub format)
    pub severity: Option<String>,
}

/// Affected package information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    /// Package identification
    pub package: Package,

    /// Version ranges
    #[serde(default)]
    pub ranges: Vec<Range>,

    /// Explicit affected versions
    #[serde(default)]
    pub versions: Vec<String>,
}

/// Package identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Ecosystem (PyPI, Go, crates.io, etc.)
    pub ecosystem: String,

    /// Package name
    pub name: String,
}

/// Version range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    /// Range type (SEMVER, GIT, ECOSYSTEM)
    #[serde(rename = "type")]
    pub range_type: String,

    /// Range events
    #[serde(default)]
    pub events: Vec<Event>,
}

/// Range event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Event {
    /// Introduced version
    Introduced { introduced: String },
    /// Fixed version
    Fixed { fixed: String },
    /// Last affected version
    LastAffected { last_affected: String },
    /// Limit version
    Limit { limit: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SyncStatusValue;
    use std::io::Write;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Create a test ZIP file containing OSV entries
    fn create_test_zip(entries: Vec<(&str, &str)>) -> Vec<u8> {
        let mut buffer = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buffer));
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            for (name, content) in entries {
                zip.start_file(name, options).unwrap();
                zip.write_all(content.as_bytes()).unwrap();
            }

            zip.finish().unwrap();
        }
        buffer
    }

    /// Create a sample OSV JSON entry
    fn sample_osv_entry(id: &str, ecosystem: &str, package: &str, versions: Vec<&str>) -> String {
        serde_json::json!({
            "id": id,
            "summary": format!("Test vulnerability for {}", package),
            "affected": [{
                "package": {
                    "ecosystem": ecosystem,
                    "name": package
                },
                "versions": versions
            }],
            "database_specific": {
                "severity": "HIGH"
            }
        })
        .to_string()
    }

    // Test 1: OSV plugin creation
    #[test]
    fn test_osv_plugin_creation() {
        let config = OsvConfig::default();
        let plugin = OsvPlugin::new(config).unwrap();
        assert_eq!(plugin.name(), "osv");
    }

    // Test 2: Default configuration values
    #[test]
    fn test_osv_config_defaults() {
        let config = OsvConfig::default();
        assert_eq!(config.base_url, DEFAULT_OSV_BASE_URL);
        assert_eq!(config.sync_interval_secs, 3600);
        assert!(config.ecosystems.contains(&"PyPI".to_string()));
        assert!(config.ecosystems.contains(&"Go".to_string()));
        assert!(config.ecosystems.contains(&"crates.io".to_string()));
        assert_eq!(config.min_severity, Some(Severity::Medium));
    }

    // Test 3: Sync interval returns correct duration
    #[tokio::test]
    async fn test_sync_interval() {
        let config = OsvConfig {
            sync_interval_secs: 7200,
            ..Default::default()
        };
        let plugin = OsvPlugin::new(config).unwrap();
        assert_eq!(plugin.sync_interval(), Duration::from_secs(7200));
    }

    // Test 4: Supported ecosystems
    #[tokio::test]
    async fn test_supported_ecosystems() {
        let config = OsvConfig {
            ecosystems: vec!["pypi".to_string(), "cargo".to_string()],
            ..Default::default()
        };
        let plugin = OsvPlugin::new(config).unwrap();
        let ecosystems = plugin.supported_ecosystems();
        assert_eq!(ecosystems.len(), 2);
        assert!(ecosystems.contains(&"pypi".to_string()));
        assert!(ecosystems.contains(&"cargo".to_string()));
    }

    // Test 5: 304 Not Modified skips sync
    #[tokio::test]
    async fn test_sync_skips_when_not_modified() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .and(header("If-None-Match", "\"abc123\""))
            .respond_with(ResponseTemplate::new(304))
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            min_severity: None,
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();
        plugin.set_cache_etag("PyPI", "\"abc123\"").await;

        let result = plugin.sync().await;
        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert!(sync_result.skipped);
        assert_eq!(sync_result.records_updated, 0);
    }

    // Test 6: Normal sync with ZIP data
    #[tokio::test]
    async fn test_sync_processes_zip_data() {
        let mock_server = MockServer::start().await;

        let osv_entry = sample_osv_entry(
            "GHSA-test-1234",
            "PyPI",
            "vulnerable-pkg",
            vec!["1.0.0", "1.0.1"],
        );
        let zip_data = create_test_zip(vec![("GHSA-test-1234.json", &osv_entry)]);

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(zip_data)
                    .insert_header("ETag", "\"xyz789\""),
            )
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            min_severity: None,
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();
        let result = plugin.sync().await;

        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert!(!sync_result.skipped);
        assert_eq!(sync_result.records_updated, 2);
    }

    // Test 7: Check package returns block reason for vulnerable package
    #[tokio::test]
    async fn test_check_package_blocked() {
        let mock_server = MockServer::start().await;

        let osv_entry = sample_osv_entry("GHSA-test-1234", "PyPI", "requests", vec!["2.30.0"]);
        let zip_data = create_test_zip(vec![("GHSA-test-1234.json", &osv_entry)]);

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_data))
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            min_severity: None,
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();
        plugin.sync().await.unwrap();

        let result = plugin.check_package("pypi", "requests", "2.30.0").await;
        assert!(result.is_some());
        let reason = result.unwrap();
        assert_eq!(reason.source, "osv");
        assert_eq!(reason.advisory_id, Some("GHSA-test-1234".to_string()));
        assert_eq!(reason.severity, Severity::High);
    }

    // Test 8: Check package returns None for safe package
    #[tokio::test]
    async fn test_check_package_safe() {
        let config = OsvConfig::default();
        let plugin = OsvPlugin::new(config).unwrap();

        let result = plugin.check_package("pypi", "safe-pkg", "1.0.0").await;
        assert!(result.is_none());
    }

    // Test 9: Get blocked packages returns list
    #[tokio::test]
    async fn test_get_blocked_packages() {
        let mock_server = MockServer::start().await;

        let osv_entry = sample_osv_entry(
            "GHSA-test-1234",
            "PyPI",
            "malicious-pkg",
            vec!["1.0.0", "1.1.0"],
        );
        let zip_data = create_test_zip(vec![("GHSA-test-1234.json", &osv_entry)]);

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_data))
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            min_severity: None,
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();
        plugin.sync().await.unwrap();

        let blocked = plugin.get_blocked_packages("pypi").await;
        assert_eq!(blocked.len(), 2);
        assert!(blocked.iter().all(|b| b.package == "malicious-pkg"));
    }

    // Test 10: Network error during sync
    #[tokio::test]
    async fn test_sync_network_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();
        let result = plugin.sync().await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncError::ServerError(503)));
    }

    // Test 11: Severity filtering
    #[tokio::test]
    async fn test_severity_filtering() {
        let mock_server = MockServer::start().await;

        // Low severity entry
        let low_entry = serde_json::json!({
            "id": "LOW-1",
            "summary": "Low severity issue",
            "affected": [{
                "package": {
                    "ecosystem": "PyPI",
                    "name": "low-pkg"
                },
                "versions": ["1.0.0"]
            }],
            "database_specific": {
                "severity": "LOW"
            }
        })
        .to_string();

        // High severity entry
        let high_entry = serde_json::json!({
            "id": "HIGH-1",
            "summary": "High severity issue",
            "affected": [{
                "package": {
                    "ecosystem": "PyPI",
                    "name": "high-pkg"
                },
                "versions": ["1.0.0"]
            }],
            "database_specific": {
                "severity": "HIGH"
            }
        })
        .to_string();

        let zip_data = create_test_zip(vec![
            ("LOW-1.json", &low_entry),
            ("HIGH-1.json", &high_entry),
        ]);

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_data))
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            min_severity: Some(Severity::Medium), // Filter out LOW
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();
        plugin.sync().await.unwrap();

        // Low severity should be filtered out
        let low_result = plugin.check_package("pypi", "low-pkg", "1.0.0").await;
        assert!(low_result.is_none());

        // High severity should be included
        let high_result = plugin.check_package("pypi", "high-pkg", "1.0.0").await;
        assert!(high_result.is_some());
    }

    // Test 12: Ecosystem normalization
    #[test]
    fn test_ecosystem_normalization() {
        assert_eq!(normalize_ecosystem("PyPI"), "pypi");
        assert_eq!(normalize_ecosystem("PYPI"), "pypi");
        assert_eq!(normalize_ecosystem("pypi"), "pypi");
        assert_eq!(normalize_ecosystem("Go"), "go");
        assert_eq!(normalize_ecosystem("crates.io"), "crates.io");
        assert_eq!(normalize_ecosystem("cargo"), "crates.io");
    }

    // Test 13: OSV entry severity extraction
    #[test]
    fn test_osv_entry_severity_extraction() {
        // CVSS score
        let entry_cvss = OsvEntry {
            id: "TEST-1".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            severity: Some(vec![OsvSeverity {
                severity_type: Some("CVSS_V3".to_string()),
                score: Some("9.5".to_string()),
            }]),
            database_specific: None,
        };
        assert_eq!(entry_cvss.extract_severity(), Severity::Critical);

        // Database specific
        let entry_db = OsvEntry {
            id: "TEST-2".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            severity: None,
            database_specific: Some(DatabaseSpecific {
                severity: Some("MODERATE".to_string()),
            }),
        };
        assert_eq!(entry_db.extract_severity(), Severity::Medium);

        // Unknown
        let entry_unknown = OsvEntry {
            id: "TEST-3".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            severity: None,
            database_specific: None,
        };
        assert_eq!(entry_unknown.extract_severity(), Severity::Unknown);
    }

    // Test 14: Sync status tracking
    #[tokio::test]
    async fn test_sync_status_tracking() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/PyPI/all.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(create_test_zip(vec![])))
            .mount(&mock_server)
            .await;

        let config = OsvConfig {
            base_url: mock_server.uri(),
            ecosystems: vec!["PyPI".to_string()],
            retry: RetryConfig {
                max_retries: 0,
                ..Default::default()
            },
            rate_limit: RateLimitConfig {
                min_interval_ms: 0,
                ..Default::default()
            },
            ..Default::default()
        };

        let plugin = OsvPlugin::new(config).unwrap();

        // Initial status
        let status = plugin.sync_status();
        assert_eq!(status.source, "osv");
        assert_eq!(status.status, SyncStatusValue::Pending);

        // After sync
        plugin.sync().await.unwrap();
        let status = plugin.sync_status();
        assert_eq!(status.status, SyncStatusValue::Success);
    }
}
