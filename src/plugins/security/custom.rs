//! Custom blocklist plugin
//!
//! This module provides custom blocklist functionality that allows users to
//! define their own blocking rules via YAML configuration files.
//!
//! # Configuration File Format
//!
//! ```yaml
//! rules:
//!   - ecosystem: pypi
//!     package: malicious-package
//!     version: "1.0.0"
//!     reason: "Known malware"
//!
//!   - ecosystem: pypi
//!     package: vulnerable-lib
//!     version: ">=1.0.0, <2.0.0"  # Semver range
//!     reason: "Security vulnerability in v1.x"
//!
//!   - ecosystem: cargo
//!     package: "evil-*"  # Wildcard pattern
//!     reason: "Blocked by prefix pattern"
//! ```
//!
//! # Example
//!
//! ```ignore
//! use registry_firewall::plugins::security::custom::{CustomBlocklistPlugin, CustomBlocklistConfig};
//!
//! let plugin = CustomBlocklistPlugin::new(CustomBlocklistConfig::default())?;
//! plugin.sync().await?;
//!
//! if let Some(reason) = plugin.check_package("pypi", "malicious-pkg", "1.0.0").await {
//!     println!("Package blocked: {}", reason.reason);
//! }
//! ```

use async_trait::async_trait;
use glob::Pattern;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::error::SyncError;
use crate::models::{BlockReason, BlockedPackage, Severity, SyncResult, SyncStatus};

use super::SecuritySourcePlugin;

/// Custom blocklist configuration
#[derive(Debug, Clone)]
pub struct CustomBlocklistConfig {
    /// Path to the YAML blocklist file
    pub file_path: PathBuf,
    /// Sync interval for reloading the file (seconds)
    pub sync_interval_secs: u64,
    /// Supported ecosystems
    pub ecosystems: Vec<String>,
}

impl Default for CustomBlocklistConfig {
    fn default() -> Self {
        Self {
            file_path: PathBuf::from("/config/custom-blocklist.yaml"),
            sync_interval_secs: 300, // 5 minutes
            ecosystems: vec!["pypi".into(), "cargo".into(), "go".into(), "docker".into()],
        }
    }
}

/// YAML file structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlocklistFile {
    /// List of blocking rules
    #[serde(default)]
    pub rules: Vec<BlockRule>,
}

/// A blocking rule from the YAML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRule {
    /// Target ecosystem (pypi, cargo, go, docker)
    pub ecosystem: String,
    /// Package name or pattern (supports wildcards like "evil-*")
    pub package: String,
    /// Version or version range (optional, all versions if omitted)
    #[serde(default)]
    pub version: Option<String>,
    /// Reason for blocking
    pub reason: String,
    /// Severity (defaults to High)
    #[serde(default)]
    pub severity: Option<String>,
}

/// Parsed rule for efficient matching
#[derive(Debug, Clone)]
struct ParsedRule {
    ecosystem: String,
    package_pattern: PackagePattern,
    version_matcher: VersionMatcher,
    reason: String,
    severity: Severity,
}

/// Pattern for matching package names
#[derive(Debug, Clone)]
enum PackagePattern {
    /// Exact package name match
    Exact(String),
    /// Glob pattern match
    Glob(Pattern),
}

impl PackagePattern {
    fn parse(pattern: &str) -> Self {
        if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
            if let Ok(p) = Pattern::new(&pattern.to_lowercase()) {
                return PackagePattern::Glob(p);
            }
        }
        PackagePattern::Exact(pattern.to_lowercase())
    }

    fn matches(&self, package: &str) -> bool {
        let pkg_lower = package.to_lowercase();
        match self {
            PackagePattern::Exact(name) => name == &pkg_lower,
            PackagePattern::Glob(pattern) => pattern.matches(&pkg_lower),
        }
    }
}

/// Matcher for version specifications
#[derive(Debug, Clone)]
enum VersionMatcher {
    /// Match all versions
    Any,
    /// Match exact version
    Exact(String),
    /// Match semver range
    SemverRange(VersionReq),
}

impl VersionMatcher {
    fn parse(version: Option<&str>) -> Self {
        match version {
            None | Some("") => VersionMatcher::Any,
            Some(v) => {
                // Try to parse as semver range first
                if v.contains('>')
                    || v.contains('<')
                    || v.contains(',')
                    || v.contains('^')
                    || v.contains('~')
                {
                    if let Ok(req) = VersionReq::parse(v) {
                        return VersionMatcher::SemverRange(req);
                    }
                }
                // Fall back to exact match
                VersionMatcher::Exact(v.to_string())
            }
        }
    }

    fn matches(&self, version: &str) -> bool {
        match self {
            VersionMatcher::Any => true,
            VersionMatcher::Exact(v) => v == version,
            VersionMatcher::SemverRange(req) => {
                if let Ok(ver) = Version::parse(version) {
                    req.matches(&ver)
                } else {
                    // If version can't be parsed, try loose comparison
                    false
                }
            }
        }
    }
}

/// In-memory store for parsed rules
#[derive(Debug, Default)]
struct RulesStore {
    /// Parsed rules indexed by ecosystem
    rules_by_ecosystem: HashMap<String, Vec<ParsedRule>>,
    /// Total rule count
    rule_count: u64,
}

/// Custom blocklist plugin
pub struct CustomBlocklistPlugin {
    config: CustomBlocklistConfig,
    rules: RwLock<RulesStore>,
    sync_status: RwLock<SyncStatus>,
}

impl CustomBlocklistPlugin {
    /// Create a new custom blocklist plugin
    pub fn new(config: CustomBlocklistConfig) -> Self {
        Self {
            config,
            rules: RwLock::new(RulesStore::default()),
            sync_status: RwLock::new(SyncStatus::new("custom")),
        }
    }

    /// Load and parse the blocklist file
    async fn load_blocklist(&self) -> Result<BlocklistFile, SyncError> {
        let path = &self.config.file_path;

        if !path.exists() {
            debug!(path = ?path, "Blocklist file does not exist, using empty rules");
            return Ok(BlocklistFile::default());
        }

        let contents = tokio::fs::read_to_string(path).await.map_err(|e| {
            SyncError::InvalidData(format!("Failed to read blocklist file {:?}: {}", path, e))
        })?;

        let blocklist: BlocklistFile = serde_yaml::from_str(&contents).map_err(|e| {
            SyncError::InvalidData(format!("Failed to parse blocklist YAML: {}", e))
        })?;

        Ok(blocklist)
    }

    /// Parse a block rule into an efficient matcher
    fn parse_rule(&self, rule: &BlockRule) -> ParsedRule {
        let severity = rule
            .severity
            .as_ref()
            .map(|s| match s.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" | "MODERATE" => Severity::Medium,
                "LOW" => Severity::Low,
                _ => Severity::High,
            })
            .unwrap_or(Severity::High);

        ParsedRule {
            ecosystem: normalize_ecosystem(&rule.ecosystem),
            package_pattern: PackagePattern::parse(&rule.package),
            version_matcher: VersionMatcher::parse(rule.version.as_deref()),
            reason: rule.reason.clone(),
            severity,
        }
    }

    /// Update rules store with parsed rules
    async fn update_rules(&self, blocklist: BlocklistFile) -> u64 {
        let mut rules_by_ecosystem: HashMap<String, Vec<ParsedRule>> = HashMap::new();

        for rule in &blocklist.rules {
            let parsed = self.parse_rule(rule);
            rules_by_ecosystem
                .entry(parsed.ecosystem.clone())
                .or_default()
                .push(parsed);
        }

        let rule_count = blocklist.rules.len() as u64;

        let mut store = self.rules.write().await;
        store.rules_by_ecosystem = rules_by_ecosystem;
        store.rule_count = rule_count;

        rule_count
    }

    /// Find matching rule for a package
    async fn find_matching_rule(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<ParsedRule> {
        let store = self.rules.read().await;
        let normalized_eco = normalize_ecosystem(ecosystem);

        if let Some(rules) = store.rules_by_ecosystem.get(&normalized_eco) {
            for rule in rules {
                if rule.package_pattern.matches(package) && rule.version_matcher.matches(version) {
                    return Some(rule.clone());
                }
            }
        }

        None
    }
}

#[async_trait]
impl SecuritySourcePlugin for CustomBlocklistPlugin {
    fn name(&self) -> &str {
        "custom"
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

        // Load and parse blocklist
        let blocklist = match self.load_blocklist().await {
            Ok(bl) => bl,
            Err(e) => {
                let mut status = self.sync_status.write().await;
                *status = status.clone().failed(e.to_string());
                return Err(e);
            }
        };

        // Update rules
        let rule_count = self.update_rules(blocklist).await;

        // Update status
        let mut status = self.sync_status.write().await;
        *status = status.clone().success(rule_count);

        info!(rules = rule_count, "Loaded custom blocklist rules");
        Ok(SyncResult::success(rule_count))
    }

    fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.config.sync_interval_secs)
    }

    fn sync_status(&self) -> SyncStatus {
        self.sync_status
            .try_read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| SyncStatus::new("custom"))
    }

    async fn check_package(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<BlockReason> {
        self.find_matching_rule(ecosystem, package, version)
            .await
            .map(|rule| BlockReason::new("custom", &rule.reason).with_severity(rule.severity))
    }

    async fn get_blocked_packages(&self, ecosystem: &str) -> Vec<BlockedPackage> {
        let store = self.rules.read().await;
        let normalized_eco = normalize_ecosystem(ecosystem);

        store
            .rules_by_ecosystem
            .get(&normalized_eco)
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|rule| {
                        // For patterns, we can't enumerate all packages
                        // Only return exact matches
                        match &rule.package_pattern {
                            PackagePattern::Exact(name) => {
                                let version = match &rule.version_matcher {
                                    VersionMatcher::Exact(v) => v.clone(),
                                    _ => "*".to_string(),
                                };
                                Some(
                                    BlockedPackage::new(&normalized_eco, name, &version, "custom")
                                        .with_reason(&rule.reason)
                                        .with_severity(rule.severity),
                                )
                            }
                            PackagePattern::Glob(_) => None, // Can't enumerate glob patterns
                        }
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
        "crates.io" | "cargo" => "cargo".to_string(),
        "docker" => "docker".to_string(),
        other => other.to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SyncStatusValue;
    use tempfile::TempDir;

    // Test 1: Plugin creation
    #[test]
    fn test_custom_plugin_creation() {
        let config = CustomBlocklistConfig::default();
        let plugin = CustomBlocklistPlugin::new(config);
        assert_eq!(plugin.name(), "custom");
    }

    // Test 2: Default configuration
    #[test]
    fn test_custom_config_defaults() {
        let config = CustomBlocklistConfig::default();
        assert_eq!(config.sync_interval_secs, 300);
        assert!(config.ecosystems.contains(&"pypi".to_string()));
        assert!(config.ecosystems.contains(&"cargo".to_string()));
        assert!(config.ecosystems.contains(&"go".to_string()));
        assert!(config.ecosystems.contains(&"docker".to_string()));
    }

    // Test 3: Sync interval
    #[tokio::test]
    async fn test_sync_interval() {
        let config = CustomBlocklistConfig {
            sync_interval_secs: 600,
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        assert_eq!(plugin.sync_interval(), Duration::from_secs(600));
    }

    // Test 4: Load YAML file with exact package match
    #[tokio::test]
    async fn test_load_yaml_exact_match() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: malicious-package
    version: "1.0.0"
    reason: "Known malware"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);

        let result = plugin.sync().await;
        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert_eq!(sync_result.records_updated, 1);

        // Check exact match
        let block = plugin
            .check_package("pypi", "malicious-package", "1.0.0")
            .await;
        assert!(block.is_some());
        let reason = block.unwrap();
        assert_eq!(reason.source, "custom");
        assert_eq!(reason.reason, "Known malware");

        // Different version should not match
        let block = plugin
            .check_package("pypi", "malicious-package", "2.0.0")
            .await;
        assert!(block.is_none());
    }

    // Test 5: Semver range matching
    #[tokio::test]
    async fn test_semver_range_matching() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: vulnerable-lib
    version: ">=1.0.0, <2.0.0"
    reason: "Vulnerability in v1.x"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        // 1.0.0 should match
        let block = plugin
            .check_package("pypi", "vulnerable-lib", "1.0.0")
            .await;
        assert!(block.is_some());

        // 1.5.0 should match
        let block = plugin
            .check_package("pypi", "vulnerable-lib", "1.5.0")
            .await;
        assert!(block.is_some());

        // 1.9.9 should match
        let block = plugin
            .check_package("pypi", "vulnerable-lib", "1.9.9")
            .await;
        assert!(block.is_some());

        // 2.0.0 should NOT match
        let block = plugin
            .check_package("pypi", "vulnerable-lib", "2.0.0")
            .await;
        assert!(block.is_none());

        // 0.9.0 should NOT match
        let block = plugin
            .check_package("pypi", "vulnerable-lib", "0.9.0")
            .await;
        assert!(block.is_none());
    }

    // Test 6: Wildcard pattern matching
    #[tokio::test]
    async fn test_wildcard_pattern_matching() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: cargo
    package: "evil-*"
    reason: "Blocked by prefix pattern"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        // Matching patterns
        let block = plugin.check_package("cargo", "evil-pkg", "1.0.0").await;
        assert!(block.is_some());

        let block = plugin.check_package("cargo", "evil-lib", "2.0.0").await;
        assert!(block.is_some());

        let block = plugin
            .check_package("cargo", "evil-something-else", "0.1.0")
            .await;
        assert!(block.is_some());

        // Non-matching
        let block = plugin.check_package("cargo", "good-pkg", "1.0.0").await;
        assert!(block.is_none());

        let block = plugin.check_package("cargo", "not-evil", "1.0.0").await;
        assert!(block.is_none());
    }

    // Test 7: Block all versions when version is omitted
    #[tokio::test]
    async fn test_block_all_versions() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: totally-blocked
    reason: "All versions blocked"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        // Any version should match
        let block = plugin
            .check_package("pypi", "totally-blocked", "1.0.0")
            .await;
        assert!(block.is_some());

        let block = plugin
            .check_package("pypi", "totally-blocked", "99.99.99")
            .await;
        assert!(block.is_some());

        let block = plugin
            .check_package("pypi", "totally-blocked", "0.0.1-alpha")
            .await;
        assert!(block.is_some());
    }

    // Test 8: Multiple ecosystems
    #[tokio::test]
    async fn test_multiple_ecosystems() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: malware
    reason: "PyPI malware"
  - ecosystem: cargo
    package: malware
    reason: "Cargo malware"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        // PyPI should match
        let block = plugin.check_package("pypi", "malware", "1.0.0").await;
        assert!(block.is_some());
        assert_eq!(block.unwrap().reason, "PyPI malware");

        // Cargo should match
        let block = plugin.check_package("cargo", "malware", "1.0.0").await;
        assert!(block.is_some());
        assert_eq!(block.unwrap().reason, "Cargo malware");

        // Go should NOT match
        let block = plugin.check_package("go", "malware", "1.0.0").await;
        assert!(block.is_none());
    }

    // Test 9: Case insensitive package matching
    #[tokio::test]
    async fn test_case_insensitive_matching() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: MixedCase-Package
    reason: "Case test"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        // Should match regardless of case
        let block = plugin
            .check_package("pypi", "mixedcase-package", "1.0.0")
            .await;
        assert!(block.is_some());

        let block = plugin
            .check_package("pypi", "MIXEDCASE-PACKAGE", "1.0.0")
            .await;
        assert!(block.is_some());

        let block = plugin
            .check_package("pypi", "MixedCase-Package", "1.0.0")
            .await;
        assert!(block.is_some());
    }

    // Test 10: Empty/missing file
    #[tokio::test]
    async fn test_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.yaml");

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);

        // Should succeed with empty rules
        let result = plugin.sync().await;
        assert!(result.is_ok());
        let sync_result = result.unwrap();
        assert_eq!(sync_result.records_updated, 0);

        // No packages should be blocked
        let block = plugin.check_package("pypi", "any-package", "1.0.0").await;
        assert!(block.is_none());
    }

    // Test 11: Sync status tracking
    #[tokio::test]
    async fn test_sync_status() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: test
    reason: "Test"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);

        // Initial status
        let status = plugin.sync_status();
        assert_eq!(status.source, "custom");
        assert_eq!(status.status, SyncStatusValue::Pending);

        // After sync
        plugin.sync().await.unwrap();
        let status = plugin.sync_status();
        assert_eq!(status.status, SyncStatusValue::Success);
        assert_eq!(status.records_count, 1);
    }

    // Test 12: Get blocked packages
    #[tokio::test]
    async fn test_get_blocked_packages() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: blocked1
    version: "1.0.0"
    reason: "Blocked 1"
  - ecosystem: pypi
    package: blocked2
    reason: "Blocked 2"
  - ecosystem: pypi
    package: "pattern-*"
    reason: "Pattern (should not appear)"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        let blocked = plugin.get_blocked_packages("pypi").await;
        // Only exact matches should be returned (not patterns)
        assert_eq!(blocked.len(), 2);
        assert!(blocked.iter().any(|b| b.package == "blocked1"));
        assert!(blocked.iter().any(|b| b.package == "blocked2"));
    }

    // Test 13: Ecosystem normalization
    #[test]
    fn test_ecosystem_normalization() {
        assert_eq!(normalize_ecosystem("PyPI"), "pypi");
        assert_eq!(normalize_ecosystem("PYPI"), "pypi");
        assert_eq!(normalize_ecosystem("Cargo"), "cargo");
        assert_eq!(normalize_ecosystem("crates.io"), "cargo");
        assert_eq!(normalize_ecosystem("Go"), "go");
        assert_eq!(normalize_ecosystem("Docker"), "docker");
    }

    // Test 14: Package pattern parsing
    #[test]
    fn test_package_pattern_parsing() {
        // Exact match
        let pattern = PackagePattern::parse("my-package");
        assert!(pattern.matches("my-package"));
        assert!(pattern.matches("My-Package")); // case insensitive
        assert!(!pattern.matches("other-package"));

        // Glob pattern
        let pattern = PackagePattern::parse("evil-*");
        assert!(pattern.matches("evil-pkg"));
        assert!(pattern.matches("evil-lib"));
        assert!(!pattern.matches("good-pkg"));

        // Question mark pattern
        let pattern = PackagePattern::parse("pkg-?");
        assert!(pattern.matches("pkg-a"));
        assert!(pattern.matches("pkg-1"));
        assert!(!pattern.matches("pkg-ab"));
    }

    // Test 15: Version matcher parsing
    #[test]
    fn test_version_matcher_parsing() {
        // Any version
        let matcher = VersionMatcher::parse(None);
        assert!(matcher.matches("1.0.0"));
        assert!(matcher.matches("99.99.99"));

        // Exact version
        let matcher = VersionMatcher::parse(Some("1.0.0"));
        assert!(matcher.matches("1.0.0"));
        assert!(!matcher.matches("1.0.1"));

        // Semver range
        let matcher = VersionMatcher::parse(Some(">=1.0.0, <2.0.0"));
        assert!(matcher.matches("1.0.0"));
        assert!(matcher.matches("1.5.0"));
        assert!(!matcher.matches("2.0.0"));
        assert!(!matcher.matches("0.9.0"));
    }

    // Test 16: Severity configuration
    #[tokio::test]
    async fn test_severity_configuration() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("blocklist.yaml");

        let yaml_content = r#"
rules:
  - ecosystem: pypi
    package: critical-issue
    reason: "Critical"
    severity: "CRITICAL"
  - ecosystem: pypi
    package: medium-issue
    reason: "Medium"
    severity: "MEDIUM"
  - ecosystem: pypi
    package: default-severity
    reason: "Default (High)"
"#;
        tokio::fs::write(&file_path, yaml_content).await.unwrap();

        let config = CustomBlocklistConfig {
            file_path: file_path.clone(),
            ..Default::default()
        };
        let plugin = CustomBlocklistPlugin::new(config);
        plugin.sync().await.unwrap();

        let block = plugin
            .check_package("pypi", "critical-issue", "1.0.0")
            .await;
        assert_eq!(block.unwrap().severity, Severity::Critical);

        let block = plugin.check_package("pypi", "medium-issue", "1.0.0").await;
        assert_eq!(block.unwrap().severity, Severity::Medium);

        let block = plugin
            .check_package("pypi", "default-severity", "1.0.0")
            .await;
        assert_eq!(block.unwrap().severity, Severity::High);
    }
}
