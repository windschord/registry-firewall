//! OpenSSF Malicious Packages plugin
//!
//! This module provides integration with the OpenSSF Malicious Packages repository
//! for known malware detection.
//!
//! # Data Source
//!
//! The malicious packages repository is at: `https://github.com/ossf/malicious-packages.git`
//!
//! The repository contains OSV-format JSON files in `osv/{ecosystem}/` directories.
//!
//! # Example
//!
//! ```ignore
//! use registry_firewall::plugins::security::openssf::{OpenSsfPlugin, OpenSsfConfig};
//!
//! let plugin = OpenSsfPlugin::new(OpenSsfConfig::default())?;
//! plugin.sync().await?;
//!
//! if let Some(reason) = plugin.check_package("pypi", "malicious-pkg", "1.0.0").await {
//!     println!("Package blocked: {}", reason.reason);
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::RetryConfig;
use crate::error::SyncError;
use crate::models::{BlockReason, BlockedPackage, Severity, SyncResult, SyncStatus};
use crate::sync::RetryManager;

use super::SecuritySourcePlugin;

/// Default repository URL for OpenSSF Malicious Packages
pub const DEFAULT_REPO_URL: &str = "https://github.com/ossf/malicious-packages.git";

/// OpenSSF plugin configuration
#[derive(Debug, Clone)]
pub struct OpenSsfConfig {
    /// Sync interval in seconds (default: 1800 = 30 minutes)
    pub sync_interval_secs: u64,
    /// Target ecosystems
    pub ecosystems: Vec<String>,
    /// Local repository path
    pub repo_path: PathBuf,
    /// Retry configuration
    pub retry: RetryConfig,
    /// Git operation timeout in seconds
    pub git_timeout_secs: u64,
    /// Repository URL (for testing)
    pub repo_url: String,
}

impl Default for OpenSsfConfig {
    fn default() -> Self {
        Self {
            sync_interval_secs: 1800, // 30 minutes
            ecosystems: vec!["pypi".into(), "npm".into(), "crates.io".into()],
            repo_path: PathBuf::from("/data/openssf-malicious"),
            retry: RetryConfig {
                max_retries: 3,
                initial_backoff_secs: 10,
                max_backoff_secs: 120,
                ..Default::default()
            },
            git_timeout_secs: 300,
            repo_url: DEFAULT_REPO_URL.to_string(),
        }
    }
}

/// Repository state for caching
#[derive(Debug, Default)]
struct RepoState {
    /// Last commit hash
    last_commit: Option<String>,
}

/// In-memory blocked packages store
#[derive(Debug, Default)]
struct BlockedPackagesStore {
    /// Blocked packages by ecosystem -> package name -> version -> entry
    packages: HashMap<String, HashMap<String, HashMap<String, MalwareEntry>>>,
}

/// Malware entry with details
#[derive(Debug, Clone)]
struct MalwareEntry {
    advisory_id: String,
    reason: String,
}

/// OpenSSF Malicious Packages plugin
pub struct OpenSsfPlugin {
    config: OpenSsfConfig,
    retry_manager: RetryManager,
    repo_state: RwLock<RepoState>,
    blocked_packages: RwLock<BlockedPackagesStore>,
    sync_status: RwLock<SyncStatus>,
}

impl OpenSsfPlugin {
    /// Create a new OpenSSF plugin with the given configuration
    pub fn new(config: OpenSsfConfig) -> Self {
        let retry_manager = RetryManager::new(config.retry.clone());

        Self {
            sync_status: RwLock::new(SyncStatus::new("openssf")),
            retry_manager,
            config,
            repo_state: RwLock::new(RepoState::default()),
            blocked_packages: RwLock::new(BlockedPackagesStore::default()),
        }
    }

    /// Perform sparse clone of the repository
    async fn git_clone_sparse(&self) -> Result<(), SyncError> {
        let repo_path = &self.config.repo_path;
        let repo_url = &self.config.repo_url;

        // Create parent directory if needed
        if let Some(parent) = repo_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                SyncError::InvalidData(format!("Failed to create directory: {}", e))
            })?;
        }

        // shallow clone (depth=1) with sparse checkout
        let output = Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                repo_url,
            ])
            .arg(repo_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SyncError::Network(format!("Git clone failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SyncError::Network(format!("Git clone failed: {}", stderr)));
        }

        // Set up sparse checkout for required ecosystems
        let sparse_paths: Vec<String> = self
            .config
            .ecosystems
            .iter()
            .map(|eco| format!("osv/{}", normalize_ecosystem(eco)))
            .collect();

        let output = Command::new("git")
            .current_dir(repo_path)
            .args(["sparse-checkout", "set"])
            .args(&sparse_paths)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SyncError::Network(format!("Git sparse-checkout failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SyncError::Network(format!(
                "Git sparse-checkout failed: {}",
                stderr
            )));
        }

        info!("Cloned OpenSSF repository to {:?}", repo_path);
        Ok(())
    }

    /// Pull latest changes from the repository
    async fn git_pull(&self) -> Result<(), SyncError> {
        let repo_path = &self.config.repo_path;

        // Fetch latest
        let output = Command::new("git")
            .current_dir(repo_path)
            .args(["fetch", "--depth", "1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SyncError::Network(format!("Git fetch failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SyncError::Network(format!("Git fetch failed: {}", stderr)));
        }

        // Reset to origin/main
        let output = Command::new("git")
            .current_dir(repo_path)
            .args(["reset", "--hard", "origin/main"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SyncError::Network(format!("Git reset failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SyncError::Network(format!("Git reset failed: {}", stderr)));
        }

        debug!("Pulled latest changes from OpenSSF repository");
        Ok(())
    }

    /// Get the current HEAD commit hash
    async fn get_head_commit(&self) -> Result<String, SyncError> {
        let output = Command::new("git")
            .current_dir(&self.config.repo_path)
            .args(["rev-parse", "HEAD"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SyncError::Network(format!("Git rev-parse failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SyncError::Network(format!(
                "Git rev-parse failed: {}",
                stderr
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Parse all OSV files in the repository and update blocked packages
    async fn parse_and_update(&self) -> Result<u64, SyncError> {
        let mut records = 0u64;
        let mut new_packages: HashMap<String, HashMap<String, HashMap<String, MalwareEntry>>> =
            HashMap::new();

        for ecosystem in &self.config.ecosystems {
            let normalized_eco = normalize_ecosystem(ecosystem);
            let osv_dir = self.config.repo_path.join("osv").join(&normalized_eco);

            if !osv_dir.exists() {
                debug!(ecosystem = ecosystem, "OSV directory not found, skipping");
                continue;
            }

            let eco_records = self.parse_ecosystem_dir(&osv_dir, &normalized_eco).await?;

            for (pkg_name, versions) in eco_records {
                new_packages
                    .entry(normalized_eco.clone())
                    .or_default()
                    .insert(pkg_name, versions);
                records += 1;
            }
        }

        // Update store
        let mut store = self.blocked_packages.write().await;
        store.packages = new_packages;

        Ok(records)
    }

    /// Parse OSV files in an ecosystem directory
    async fn parse_ecosystem_dir(
        &self,
        dir: &PathBuf,
        ecosystem: &str,
    ) -> Result<HashMap<String, HashMap<String, MalwareEntry>>, SyncError> {
        let mut packages: HashMap<String, HashMap<String, MalwareEntry>> = HashMap::new();

        let mut entries = tokio::fs::read_dir(dir).await.map_err(|e| {
            SyncError::InvalidData(format!("Failed to read directory {:?}: {}", dir, e))
        })?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| SyncError::InvalidData(format!("Failed to read directory entry: {}", e)))?
        {
            let path = entry.path();

            // Only process .json files
            if path.extension().is_some_and(|e| e == "json") {
                match self.parse_osv_file(&path, ecosystem).await {
                    Ok(Some((pkg_name, versions))) => {
                        packages.insert(pkg_name, versions);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(path = ?path, error = %e, "Failed to parse OSV file");
                    }
                }
            }
        }

        Ok(packages)
    }

    /// Parse a single OSV file and extract package info
    async fn parse_osv_file(
        &self,
        path: &PathBuf,
        ecosystem: &str,
    ) -> Result<Option<(String, HashMap<String, MalwareEntry>)>, SyncError> {
        let mut file = tokio::fs::File::open(path).await.map_err(|e| {
            SyncError::InvalidData(format!("Failed to open file {:?}: {}", path, e))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).await.map_err(|e| {
            SyncError::InvalidData(format!("Failed to read file {:?}: {}", path, e))
        })?;

        let entry: OsvEntry = serde_json::from_str(&contents)
            .map_err(|e| SyncError::InvalidData(format!("Failed to parse {:?}: {}", path, e)))?;

        // Find affected package for this ecosystem
        for affected in &entry.affected {
            let affected_eco = normalize_ecosystem(&affected.package.ecosystem);
            if affected_eco != ecosystem {
                continue;
            }

            let pkg_name = affected.package.name.to_lowercase();
            let mut versions = HashMap::new();

            // Add explicit versions
            for version in &affected.versions {
                versions.insert(
                    version.clone(),
                    MalwareEntry {
                        advisory_id: entry.id.clone(),
                        reason: entry
                            .summary
                            .clone()
                            .unwrap_or_else(|| format!("Malware: {}", entry.id)),
                    },
                );
            }

            if !versions.is_empty() {
                return Ok(Some((pkg_name, versions)));
            }
        }

        Ok(None)
    }
}

#[async_trait]
impl SecuritySourcePlugin for OpenSsfPlugin {
    fn name(&self) -> &str {
        "openssf"
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

        let repo_path = &self.config.repo_path;

        // Clone or pull repository
        let git_result = self
            .retry_manager
            .execute(|| async {
                if repo_path.exists() {
                    self.git_pull().await
                } else {
                    self.git_clone_sparse().await
                }
            })
            .await;

        if let Err(e) = git_result {
            let mut status = self.sync_status.write().await;
            *status = status.clone().failed(e.to_string());
            return Err(e);
        }

        // Check if we need to parse (commit changed)
        let current_commit = self.get_head_commit().await?;
        let state = self.repo_state.read().await;

        if state.last_commit.as_ref() == Some(&current_commit) {
            info!("OpenSSF repository unchanged, skipping parse");
            let mut status = self.sync_status.write().await;
            *status = status.clone().success(0);
            return Ok(SyncResult::skipped());
        }
        drop(state);

        // Parse OSV files and update database
        let records = self.parse_and_update().await?;

        // Update state
        let mut state = self.repo_state.write().await;
        state.last_commit = Some(current_commit);
        drop(state);

        // Update status
        let mut status = self.sync_status.write().await;
        *status = status.clone().success(records);

        info!(records = records, "Updated OpenSSF malware data");
        Ok(SyncResult::success(records))
    }

    fn sync_interval(&self) -> Duration {
        Duration::from_secs(self.config.sync_interval_secs)
    }

    fn sync_status(&self) -> SyncStatus {
        self.sync_status
            .try_read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| SyncStatus::new("openssf"))
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
                BlockReason::new("openssf", &entry.reason)
                    .with_severity(Severity::Critical) // Malware is always critical
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
                            BlockedPackage::new(&normalized_eco, &pkg_name, version, "openssf")
                                .with_reason(&entry.reason)
                                .with_severity(Severity::Critical)
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
        "npm" => "npm".to_string(),
        other => other.to_lowercase(),
    }
}

// ============================================================================
// OSV JSON Schema Types (reused from OSV plugin)
// ============================================================================

/// OSV vulnerability entry (simplified for OpenSSF)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvEntry {
    /// Unique vulnerability ID (e.g., "MAL-2024-001")
    id: String,

    /// Summary of the issue
    summary: Option<String>,

    /// Affected packages
    #[serde(default)]
    affected: Vec<Affected>,
}

/// Affected package information
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Affected {
    /// Package identification
    package: Package,

    /// Explicit affected versions
    #[serde(default)]
    versions: Vec<String>,
}

/// Package identification
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Package {
    /// Ecosystem (PyPI, npm, crates.io, etc.)
    ecosystem: String,

    /// Package name
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SyncStatusValue;
    use std::io::Write;
    use tempfile::TempDir;

    /// Create a test repository structure with OSV files
    #[allow(dead_code)]
    async fn create_test_repo(
        dir: &TempDir,
        entries: Vec<(&str, &str, &str)>,
    ) -> Result<(), std::io::Error> {
        // Initialize git repo
        let output = Command::new("git")
            .current_dir(dir.path())
            .args(["init"])
            .output()
            .await?;
        assert!(output.status.success());

        // Configure git user
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.email", "test@test.com"])
            .output()
            .await?;
        Command::new("git")
            .current_dir(dir.path())
            .args(["config", "user.name", "Test"])
            .output()
            .await?;

        // Create OSV directory structure
        for (ecosystem, filename, content) in entries {
            let eco_dir = dir.path().join("osv").join(ecosystem);
            tokio::fs::create_dir_all(&eco_dir).await?;

            let file_path = eco_dir.join(filename);
            let mut file = std::fs::File::create(&file_path)?;
            file.write_all(content.as_bytes())?;
        }

        // Commit
        Command::new("git")
            .current_dir(dir.path())
            .args(["add", "."])
            .output()
            .await?;
        Command::new("git")
            .current_dir(dir.path())
            .args(["commit", "-m", "Initial commit"])
            .output()
            .await?;

        Ok(())
    }

    /// Create a sample OSV malware entry
    fn sample_malware_entry(
        id: &str,
        ecosystem: &str,
        package: &str,
        versions: Vec<&str>,
    ) -> String {
        serde_json::json!({
            "id": id,
            "summary": format!("Malware in {}", package),
            "affected": [{
                "package": {
                    "ecosystem": ecosystem,
                    "name": package
                },
                "versions": versions
            }]
        })
        .to_string()
    }

    // Test 1: Plugin creation
    #[test]
    fn test_openssf_plugin_creation() {
        let config = OpenSsfConfig::default();
        let plugin = OpenSsfPlugin::new(config);
        assert_eq!(plugin.name(), "openssf");
    }

    // Test 2: Default configuration
    #[test]
    fn test_openssf_config_defaults() {
        let config = OpenSsfConfig::default();
        assert_eq!(config.sync_interval_secs, 1800);
        assert_eq!(config.git_timeout_secs, 300);
        assert!(config.ecosystems.contains(&"pypi".to_string()));
        assert!(config.ecosystems.contains(&"npm".to_string()));
        assert!(config.ecosystems.contains(&"crates.io".to_string()));
    }

    // Test 3: Sync interval
    #[tokio::test]
    async fn test_sync_interval() {
        let config = OpenSsfConfig {
            sync_interval_secs: 3600,
            ..Default::default()
        };
        let plugin = OpenSsfPlugin::new(config);
        assert_eq!(plugin.sync_interval(), Duration::from_secs(3600));
    }

    // Test 4: Supported ecosystems
    #[tokio::test]
    async fn test_supported_ecosystems() {
        let config = OpenSsfConfig {
            ecosystems: vec!["pypi".to_string(), "npm".to_string()],
            ..Default::default()
        };
        let plugin = OpenSsfPlugin::new(config);
        let ecosystems = plugin.supported_ecosystems();
        assert_eq!(ecosystems.len(), 2);
        assert!(ecosystems.contains(&"pypi".to_string()));
        assert!(ecosystems.contains(&"npm".to_string()));
    }

    // Test 5: Check package returns None for safe package (no data)
    #[tokio::test]
    async fn test_check_package_safe() {
        let config = OpenSsfConfig::default();
        let plugin = OpenSsfPlugin::new(config);

        let result = plugin.check_package("pypi", "safe-pkg", "1.0.0").await;
        assert!(result.is_none());
    }

    // Test 6: Get blocked packages returns empty when no data
    #[tokio::test]
    async fn test_get_blocked_packages_empty() {
        let config = OpenSsfConfig::default();
        let plugin = OpenSsfPlugin::new(config);

        let blocked = plugin.get_blocked_packages("pypi").await;
        assert!(blocked.is_empty());
    }

    // Test 7: Ecosystem normalization
    #[test]
    fn test_ecosystem_normalization() {
        assert_eq!(normalize_ecosystem("PyPI"), "pypi");
        assert_eq!(normalize_ecosystem("PYPI"), "pypi");
        assert_eq!(normalize_ecosystem("npm"), "npm");
        assert_eq!(normalize_ecosystem("NPM"), "npm");
        assert_eq!(normalize_ecosystem("crates.io"), "crates.io");
        assert_eq!(normalize_ecosystem("cargo"), "crates.io");
        assert_eq!(normalize_ecosystem("Go"), "go");
    }

    // Test 8: Parse OSV file
    #[tokio::test]
    async fn test_parse_osv_file() {
        let temp_dir = TempDir::new().unwrap();
        let osv_content = sample_malware_entry(
            "MAL-2024-001",
            "pypi",
            "malicious-pkg",
            vec!["1.0.0", "1.0.1"],
        );

        // Create file
        let osv_dir = temp_dir.path().join("osv").join("pypi");
        tokio::fs::create_dir_all(&osv_dir).await.unwrap();
        let file_path = osv_dir.join("MAL-2024-001.json");
        tokio::fs::write(&file_path, osv_content).await.unwrap();

        let config = OpenSsfConfig {
            repo_path: temp_dir.path().to_path_buf(),
            ecosystems: vec!["pypi".to_string()],
            ..Default::default()
        };
        let plugin = OpenSsfPlugin::new(config);

        let result = plugin.parse_osv_file(&file_path, "pypi").await.unwrap();
        assert!(result.is_some());

        let (pkg_name, versions) = result.unwrap();
        assert_eq!(pkg_name, "malicious-pkg");
        assert_eq!(versions.len(), 2);
        assert!(versions.contains_key("1.0.0"));
        assert!(versions.contains_key("1.0.1"));
    }

    // Test 9: Parse and update with real files
    #[tokio::test]
    async fn test_parse_and_update() {
        let temp_dir = TempDir::new().unwrap();
        let osv_content = sample_malware_entry("MAL-2024-001", "pypi", "evil-pkg", vec!["2.0.0"]);

        // Create directory structure
        let osv_dir = temp_dir.path().join("osv").join("pypi");
        tokio::fs::create_dir_all(&osv_dir).await.unwrap();
        tokio::fs::write(osv_dir.join("MAL-2024-001.json"), osv_content)
            .await
            .unwrap();

        let config = OpenSsfConfig {
            repo_path: temp_dir.path().to_path_buf(),
            ecosystems: vec!["pypi".to_string()],
            ..Default::default()
        };
        let plugin = OpenSsfPlugin::new(config);

        let records = plugin.parse_and_update().await.unwrap();
        assert_eq!(records, 1);

        // Check package should now return the malware
        let result = plugin.check_package("pypi", "evil-pkg", "2.0.0").await;
        assert!(result.is_some());
        let reason = result.unwrap();
        assert_eq!(reason.source, "openssf");
        assert_eq!(reason.severity, Severity::Critical);
        assert_eq!(reason.advisory_id, Some("MAL-2024-001".to_string()));
    }

    // Test 10: Initial sync status
    #[tokio::test]
    async fn test_initial_sync_status() {
        let config = OpenSsfConfig::default();
        let plugin = OpenSsfPlugin::new(config);

        let status = plugin.sync_status();
        assert_eq!(status.source, "openssf");
        assert_eq!(status.status, SyncStatusValue::Pending);
    }

    // Test 11: Get blocked packages after parse
    #[tokio::test]
    async fn test_get_blocked_packages_after_parse() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple malware entries
        let entry1 = sample_malware_entry("MAL-2024-001", "pypi", "malware1", vec!["1.0.0"]);
        let entry2 =
            sample_malware_entry("MAL-2024-002", "pypi", "malware2", vec!["2.0.0", "2.1.0"]);

        let osv_dir = temp_dir.path().join("osv").join("pypi");
        tokio::fs::create_dir_all(&osv_dir).await.unwrap();
        tokio::fs::write(osv_dir.join("MAL-2024-001.json"), entry1)
            .await
            .unwrap();
        tokio::fs::write(osv_dir.join("MAL-2024-002.json"), entry2)
            .await
            .unwrap();

        let config = OpenSsfConfig {
            repo_path: temp_dir.path().to_path_buf(),
            ecosystems: vec!["pypi".to_string()],
            ..Default::default()
        };
        let plugin = OpenSsfPlugin::new(config);

        plugin.parse_and_update().await.unwrap();

        let blocked = plugin.get_blocked_packages("pypi").await;
        assert_eq!(blocked.len(), 3); // 1 from entry1 + 2 from entry2
    }

    // Test 12: Case-insensitive package matching
    #[tokio::test]
    async fn test_case_insensitive_package_matching() {
        let temp_dir = TempDir::new().unwrap();
        let osv_content =
            sample_malware_entry("MAL-2024-001", "pypi", "MixedCase-Pkg", vec!["1.0.0"]);

        let osv_dir = temp_dir.path().join("osv").join("pypi");
        tokio::fs::create_dir_all(&osv_dir).await.unwrap();
        tokio::fs::write(osv_dir.join("MAL-2024-001.json"), osv_content)
            .await
            .unwrap();

        let config = OpenSsfConfig {
            repo_path: temp_dir.path().to_path_buf(),
            ecosystems: vec!["pypi".to_string()],
            ..Default::default()
        };
        let plugin = OpenSsfPlugin::new(config);
        plugin.parse_and_update().await.unwrap();

        // Check with lowercase
        let result = plugin.check_package("pypi", "mixedcase-pkg", "1.0.0").await;
        assert!(result.is_some());

        // Check with uppercase
        let result = plugin.check_package("pypi", "MIXEDCASE-PKG", "1.0.0").await;
        assert!(result.is_some());
    }
}
