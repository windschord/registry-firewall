//! npm registry plugin
//!
//! This module implements the npm registry proxy.
//!
//! npm registry API:
//! - Package metadata: GET /{package}
//! - Scoped package metadata: GET /@{scope}%2F{package} or GET /@{scope}/{package}
//! - Tarball: GET /{package}/-/{package}-{version}.tgz
//! - Scoped tarball: GET /@{scope}/{package}/-/{package}-{version}.tgz

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{FilterError, ParseError, ProxyError};
use crate::models::block::BlockedVersion;
use crate::models::package::PackageRequest;

use super::traits::{RegistryPlugin, RegistryResponse, RequestContext};

/// Configuration for npm plugin
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NpmConfig {
    /// Upstream npm registry URL (default: https://registry.npmjs.org)
    pub upstream: String,

    /// Path prefix for this plugin (default: /npm)
    pub path_prefix: String,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            upstream: "https://registry.npmjs.org".to_string(),
            path_prefix: "/npm".to_string(),
            cache_ttl_secs: 86400,
        }
    }
}

/// npm registry proxy plugin
pub struct NpmPlugin {
    config: NpmConfig,
    client: Client,
    /// Cache for ETag headers (reserved for future use)
    #[allow(dead_code)]
    cache_state: Arc<RwLock<std::collections::HashMap<String, CacheState>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CacheState {
    etag: Option<String>,
}

impl NpmPlugin {
    /// Create a new npm plugin with default configuration
    pub fn new() -> Self {
        Self::with_config(NpmConfig::default())
    }

    /// Create a new npm plugin with custom configuration
    pub fn with_config(config: NpmConfig) -> Self {
        let client = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            cache_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Parse package name from path (handles scoped packages)
    ///
    /// Examples:
    /// - /npm/lodash -> lodash
    /// - /npm/@types/node -> @types/node
    /// - /npm/@types%2Fnode -> @types/node
    fn parse_package_name(&self, path: &str) -> Result<String, ParseError> {
        // Remove the prefix
        let path = path.strip_prefix(&self.config.path_prefix).unwrap_or(path);
        let path = path.trim_start_matches('/');

        if path.is_empty() {
            return Err(ParseError::MissingParameter("package name".to_string()));
        }

        // Check if it's a tarball request
        if path.contains("/-/") {
            return Err(ParseError::InvalidPath(
                "Use parse_tarball_path for tarball requests".to_string(),
            ));
        }

        // Handle scoped packages (@scope/package or @scope%2Fpackage)
        let package = if path.starts_with('@') {
            // URL decode %2F to /
            path.replace("%2F", "/").replace("%2f", "/")
        } else {
            // Regular package, might have version suffix
            path.split('/').next().unwrap_or(path).to_string()
        };

        // For scoped packages, extract just the scope/name part
        let package = if package.starts_with('@') {
            let parts: Vec<&str> = package.splitn(2, '/').collect();
            if parts.len() == 2 {
                // Check if there's a version path after the package name
                let name_part = parts[1].split('/').next().unwrap_or(parts[1]);
                format!("{}/{}", parts[0], name_part)
            } else {
                return Err(ParseError::InvalidPath(format!(
                    "Invalid scoped package: {}",
                    package
                )));
            }
        } else {
            package
        };

        Ok(package)
    }

    /// Parse tarball download path
    ///
    /// Examples:
    /// - /npm/lodash/-/lodash-4.17.21.tgz -> (lodash, 4.17.21)
    /// - /npm/@types/node/-/node-18.0.0.tgz -> (@types/node, 18.0.0)
    fn parse_tarball_path(&self, path: &str) -> Result<(String, String), ParseError> {
        // Remove the prefix
        let path = path.strip_prefix(&self.config.path_prefix).unwrap_or(path);
        let path = path.trim_start_matches('/');

        // Find the /-/ separator
        let parts: Vec<&str> = path.splitn(2, "/-/").collect();
        if parts.len() != 2 {
            return Err(ParseError::InvalidPath(format!(
                "Expected /-/ in tarball path: {}",
                path
            )));
        }

        let package = parts[0].replace("%2F", "/").replace("%2f", "/");
        let filename = parts[1];

        // Extract version from filename
        // filename format: {package_name}-{version}.tgz
        // For scoped packages: {name}-{version}.tgz (without scope)
        let version = Self::parse_version_from_filename(&package, filename)?;

        Ok((package, version))
    }

    /// Extract version from tarball filename
    fn parse_version_from_filename(package: &str, filename: &str) -> Result<String, ParseError> {
        // Remove .tgz extension
        let base = filename
            .strip_suffix(".tgz")
            .ok_or_else(|| ParseError::InvalidPath("Expected .tgz extension".to_string()))?;

        // Get the package name without scope
        let name_without_scope = if package.starts_with('@') {
            package.split('/').nth(1).unwrap_or(package)
        } else {
            package
        };

        // Remove package name prefix to get version
        // filename: {name}-{version}
        let prefix = format!("{}-", name_without_scope);
        let version = base.strip_prefix(&prefix).ok_or_else(|| {
            ParseError::InvalidPath(format!(
                "Filename {} doesn't match package {}",
                filename, package
            ))
        })?;

        Ok(version.to_string())
    }

    /// Normalize package name for consistent comparison
    ///
    /// npm package names are case-insensitive for comparison purposes
    pub fn normalize_package_name(name: &str) -> String {
        name.to_lowercase()
    }

    /// Filter JSON metadata to remove blocked versions
    ///
    /// npm package metadata contains a "versions" object with version keys
    pub fn filter_json_metadata(
        &self,
        json: &str,
        blocked: &[BlockedVersion],
    ) -> Result<String, FilterError> {
        let mut doc: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| FilterError::InvalidFormat(format!("Invalid JSON: {}", e)))?;

        // Remove blocked versions from "versions" object
        if let Some(versions) = doc.get_mut("versions").and_then(|v| v.as_object_mut()) {
            for bv in blocked {
                versions.remove(&bv.version);
            }
        }

        // Remove blocked versions from "time" object (version publish times)
        if let Some(time) = doc.get_mut("time").and_then(|v| v.as_object_mut()) {
            for bv in blocked {
                time.remove(&bv.version);
            }
        }

        // Update dist-tags if they point to blocked versions
        // First, get the latest available version from the versions object using semantic versioning
        let latest_available: Option<String> = doc
            .get("versions")
            .and_then(|v| v.as_object())
            .and_then(|versions| {
                // Parse versions using semver crate and find the highest version
                let mut parsed_versions: Vec<(semver::Version, &str)> = versions
                    .keys()
                    .filter_map(|s| semver::Version::parse(s).ok().map(|v| (v, s.as_str())))
                    .collect();
                // Sort by semver in descending order (highest first)
                parsed_versions.sort_by(|a, b| b.0.cmp(&a.0));
                parsed_versions.first().map(|(_, s)| (*s).to_string())
            });

        if let Some(dist_tags) = doc.get_mut("dist-tags").and_then(|v| v.as_object_mut()) {
            let blocked_versions: std::collections::HashSet<_> =
                blocked.iter().map(|bv| &bv.version).collect();

            // Find tags pointing to blocked versions and update them
            let tags_to_update: Vec<String> = dist_tags
                .iter()
                .filter_map(|(tag, version)| {
                    if let Some(v) = version.as_str() {
                        if blocked_versions.contains(&v.to_string()) {
                            return Some(tag.clone());
                        }
                    }
                    None
                })
                .collect();

            // Update blocked tags to point to the latest available version,
            // or remove them if no versions are available
            match latest_available {
                Some(latest) => {
                    for tag in tags_to_update {
                        dist_tags.insert(tag, serde_json::Value::String(latest.clone()));
                    }
                }
                None => {
                    // All versions are blocked, remove the affected dist-tags
                    for tag in tags_to_update {
                        dist_tags.remove(&tag);
                    }
                }
            }
        }

        serde_json::to_string(&doc)
            .map_err(|e| FilterError::InvalidFormat(format!("Failed to serialize JSON: {}", e)))
    }
}

impl Default for NpmPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryPlugin for NpmPlugin {
    fn name(&self) -> &str {
        "npm"
    }

    fn path_prefix(&self) -> &str {
        &self.config.path_prefix
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }

    fn parse_request(&self, path: &str, _method: &str) -> Result<PackageRequest, ParseError> {
        // Check if it's a tarball request
        if path.contains("/-/") {
            let (package, version) = self.parse_tarball_path(path)?;
            return Ok(PackageRequest::download("npm", package, version, path));
        }

        // Otherwise it's a metadata request
        let package = self.parse_package_name(path)?;
        Ok(PackageRequest::metadata("npm", package, path))
    }

    async fn handle_request(
        &self,
        ctx: &RequestContext,
        path: &str,
        _method: &str,
        _headers: &[(String, String)],
    ) -> Result<RegistryResponse, ProxyError> {
        // Parse the request
        let pkg_req = self.parse_request(path, "GET")?;

        // Check security plugins for blocked packages/versions
        let mut blocked_versions = Vec::new();
        for plugin in &ctx.security_plugins {
            if let Some(version) = &pkg_req.version {
                if let Some(reason) = plugin
                    .check_package(&pkg_req.ecosystem, &pkg_req.name, version)
                    .await
                {
                    return Ok(RegistryResponse::blocked(&reason.reason));
                }
            } else {
                // For metadata requests, collect all blocked versions
                let blocked = plugin.get_blocked_packages(&pkg_req.ecosystem).await;
                for pkg in blocked {
                    let normalized_name = Self::normalize_package_name(&pkg.package);
                    let normalized_req = Self::normalize_package_name(&pkg_req.name);
                    if normalized_name == normalized_req {
                        blocked_versions.push(BlockedVersion::new(
                            &pkg.version,
                            pkg.reason.unwrap_or_else(|| "Blocked".to_string()),
                        ));
                    }
                }
            }
        }

        // Build upstream URL
        let upstream_path = path.strip_prefix(&self.config.path_prefix).unwrap_or(path);
        let upstream_url = format!("{}{}", self.config.upstream, upstream_path);

        // Fetch from upstream
        let response = self
            .client
            .get(&upstream_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(ProxyError::Upstream)?;

        if !response.status().is_success() {
            if response.status().as_u16() == 404 {
                return Ok(RegistryResponse::not_found());
            }
            return Ok(RegistryResponse::new(
                response.status().as_u16(),
                Bytes::from(format!("Upstream error: {}", response.status())),
            ));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        let body = response.bytes().await.map_err(ProxyError::Upstream)?;

        // Filter metadata if needed
        if pkg_req.is_metadata() && !blocked_versions.is_empty() {
            let filtered = self.filter_metadata(&body, &blocked_versions)?;
            return Ok(RegistryResponse::ok(filtered).with_content_type(content_type));
        }

        Ok(RegistryResponse::ok(body).with_content_type(content_type))
    }

    fn filter_metadata(
        &self,
        metadata: &[u8],
        blocked: &[BlockedVersion],
    ) -> Result<Vec<u8>, FilterError> {
        let json = std::str::from_utf8(metadata)
            .map_err(|e| FilterError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        let filtered = self.filter_json_metadata(json, blocked)?;
        Ok(filtered.into_bytes())
    }

    fn cache_key(&self, package: &str, version: Option<&str>) -> String {
        let normalized = Self::normalize_package_name(package);
        match version {
            Some(v) => format!("npm:{}:{}", normalized, v),
            None => format!("npm:{}:metadata", normalized),
        }
    }

    fn upstream_url(&self) -> &str {
        &self.config.upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::package::RequestType;

    // Test 1: Plugin name, ecosystem, and path prefix
    #[test]
    fn test_npm_plugin_name() {
        let plugin = NpmPlugin::new();
        assert_eq!(plugin.name(), "npm");
        assert_eq!(plugin.ecosystem(), "npm");
        assert_eq!(plugin.path_prefix(), "/npm");
    }

    // Test 2: Default configuration values
    #[test]
    fn test_npm_config_defaults() {
        let config = NpmConfig::default();
        assert_eq!(config.upstream, "https://registry.npmjs.org");
        assert_eq!(config.path_prefix, "/npm");
        assert_eq!(config.cache_ttl_secs, 86400);
    }

    // Test 3: Custom configuration support
    #[test]
    fn test_custom_config() {
        let config = NpmConfig {
            upstream: "https://custom.registry.com".to_string(),
            path_prefix: "/custom-npm".to_string(),
            cache_ttl_secs: 3600,
        };
        let plugin = NpmPlugin::with_config(config);

        assert_eq!(plugin.upstream_url(), "https://custom.registry.com");
        assert_eq!(plugin.path_prefix(), "/custom-npm");
    }

    // Test 4: Parse simple package metadata request
    #[test]
    fn test_parse_simple_package_request() {
        let plugin = NpmPlugin::new();

        let req = plugin.parse_request("/npm/lodash", "GET").unwrap();
        assert_eq!(req.ecosystem, "npm");
        assert_eq!(req.name, "lodash");
        assert_eq!(req.request_type, RequestType::Metadata);
        assert!(req.is_metadata());
    }

    // Test 5: Parse scoped package metadata request
    #[test]
    fn test_parse_scoped_package_request() {
        let plugin = NpmPlugin::new();

        // Standard format
        let req = plugin.parse_request("/npm/@types/node", "GET").unwrap();
        assert_eq!(req.ecosystem, "npm");
        assert_eq!(req.name, "@types/node");
        assert!(req.is_metadata());

        // URL encoded format
        let req = plugin.parse_request("/npm/@types%2Fnode", "GET").unwrap();
        assert_eq!(req.name, "@types/node");
    }

    // Test 6: Parse tarball download request
    #[test]
    fn test_parse_tarball_request() {
        let plugin = NpmPlugin::new();

        let req = plugin
            .parse_request("/npm/lodash/-/lodash-4.17.21.tgz", "GET")
            .unwrap();
        assert_eq!(req.ecosystem, "npm");
        assert_eq!(req.name, "lodash");
        assert_eq!(req.version, Some("4.17.21".to_string()));
        assert_eq!(req.request_type, RequestType::Download);
        assert!(req.is_download());
    }

    // Test 7: Parse scoped package tarball request
    #[test]
    fn test_parse_scoped_tarball_request() {
        let plugin = NpmPlugin::new();

        let req = plugin
            .parse_request("/npm/@types/node/-/node-18.0.0.tgz", "GET")
            .unwrap();
        assert_eq!(req.name, "@types/node");
        assert_eq!(req.version, Some("18.0.0".to_string()));
        assert!(req.is_download());
    }

    // Test 8: Package name normalization (case insensitive)
    #[test]
    fn test_normalize_package_name() {
        assert_eq!(NpmPlugin::normalize_package_name("Lodash"), "lodash");
        assert_eq!(NpmPlugin::normalize_package_name("LODASH"), "lodash");
        assert_eq!(
            NpmPlugin::normalize_package_name("@Types/Node"),
            "@types/node"
        );
    }

    // Test 9: Invalid path returns error
    #[test]
    fn test_parse_invalid_path() {
        let plugin = NpmPlugin::new();

        let err = plugin.parse_request("/npm/", "GET");
        assert!(err.is_err());
    }

    // Test 10: Cache key generation
    #[test]
    fn test_cache_key_generation() {
        let plugin = NpmPlugin::new();

        assert_eq!(
            plugin.cache_key("lodash", Some("4.17.21")),
            "npm:lodash:4.17.21"
        );
        assert_eq!(plugin.cache_key("lodash", None), "npm:lodash:metadata");
        assert_eq!(
            plugin.cache_key("@types/node", Some("18.0.0")),
            "npm:@types/node:18.0.0"
        );
    }

    // Test 11: Filter JSON metadata removes blocked versions
    #[test]
    fn test_filter_json_removes_blocked_versions() {
        let plugin = NpmPlugin::new();

        let json = r#"{
            "name": "lodash",
            "versions": {
                "4.17.20": {"version": "4.17.20"},
                "4.17.21": {"version": "4.17.21"},
                "4.17.22": {"version": "4.17.22"}
            },
            "time": {
                "4.17.20": "2020-01-01T00:00:00Z",
                "4.17.21": "2021-01-01T00:00:00Z",
                "4.17.22": "2022-01-01T00:00:00Z"
            },
            "dist-tags": {
                "latest": "4.17.21"
            }
        }"#;

        let blocked = vec![BlockedVersion::new("4.17.21", "vulnerability")];
        let filtered = plugin.filter_json_metadata(json, &blocked).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&filtered).unwrap();

        // 4.17.21 should be removed from versions
        let versions = doc["versions"].as_object().unwrap();
        assert!(versions.contains_key("4.17.20"));
        assert!(!versions.contains_key("4.17.21"));
        assert!(versions.contains_key("4.17.22"));

        // 4.17.21 should be removed from time
        let time = doc["time"].as_object().unwrap();
        assert!(!time.contains_key("4.17.21"));

        // dist-tags.latest should be updated to 4.17.22 (highest available) since 4.17.21 was blocked
        let latest = doc["dist-tags"]["latest"].as_str().unwrap();
        assert_eq!(
            latest, "4.17.22",
            "dist-tags.latest should be updated to the highest available version"
        );
    }

    // Test 12: filter_metadata trait method implementation
    #[test]
    fn test_filter_metadata() {
        let plugin = NpmPlugin::new();
        let json = r#"{"name":"pkg","versions":{"1.0.0":{},"1.0.1":{}}}"#;

        let blocked = vec![BlockedVersion::new("1.0.1", "test block")];
        let result = plugin.filter_metadata(json.as_bytes(), &blocked).unwrap();
        let filtered: serde_json::Value = serde_json::from_slice(&result).unwrap();

        let versions = filtered["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"));
        assert!(!versions.contains_key("1.0.1"));
    }

    // Test 13: RegistryResponse::blocked creates 403 response
    #[test]
    fn test_registry_response_blocked() {
        let resp = RegistryResponse::blocked("malware detected");
        assert_eq!(resp.status, 403);
        assert!(String::from_utf8_lossy(&resp.body).contains("malware detected"));
    }

    // Test 14: Parse version from various filename formats
    #[test]
    fn test_parse_version_from_filename() {
        // Simple package
        let version = NpmPlugin::parse_version_from_filename("lodash", "lodash-4.17.21.tgz");
        assert_eq!(version.unwrap(), "4.17.21");

        // Scoped package
        let version = NpmPlugin::parse_version_from_filename("@types/node", "node-18.0.0.tgz");
        assert_eq!(version.unwrap(), "18.0.0");

        // Pre-release version
        let version = NpmPlugin::parse_version_from_filename("pkg", "pkg-1.0.0-beta.1.tgz");
        assert_eq!(version.unwrap(), "1.0.0-beta.1");
    }

    // Test 15: URL encoded scoped package paths
    #[test]
    fn test_url_encoded_scoped_packages() {
        let plugin = NpmPlugin::new();

        // Various URL encodings
        let req = plugin.parse_request("/npm/@babel%2Fcore", "GET").unwrap();
        assert_eq!(req.name, "@babel/core");

        let req = plugin.parse_request("/npm/@babel%2fcore", "GET").unwrap();
        assert_eq!(req.name, "@babel/core");
    }

    // Test 16: All versions blocked - dist-tags should be removed
    #[test]
    fn test_filter_json_all_versions_blocked() {
        let plugin = NpmPlugin::new();

        let json = r#"{
            "name": "malicious-pkg",
            "versions": {
                "1.0.0": {"version": "1.0.0"},
                "1.0.1": {"version": "1.0.1"}
            },
            "dist-tags": {
                "latest": "1.0.1",
                "stable": "1.0.0"
            }
        }"#;

        // Block all versions
        let blocked = vec![
            BlockedVersion::new("1.0.0", "malware"),
            BlockedVersion::new("1.0.1", "malware"),
        ];
        let filtered = plugin.filter_json_metadata(json, &blocked).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&filtered).unwrap();

        // All versions should be removed
        let versions = doc["versions"].as_object().unwrap();
        assert!(versions.is_empty(), "All versions should be removed");

        // dist-tags pointing to blocked versions should be removed
        let dist_tags = doc["dist-tags"].as_object().unwrap();
        assert!(
            !dist_tags.contains_key("latest"),
            "latest tag should be removed when all versions blocked"
        );
        assert!(
            !dist_tags.contains_key("stable"),
            "stable tag should be removed when all versions blocked"
        );
    }

    // Test 17: Non-semver versions should be handled gracefully
    #[test]
    fn test_filter_json_non_semver_versions() {
        let plugin = NpmPlugin::new();

        let json = r#"{
            "name": "legacy-pkg",
            "versions": {
                "1.0.0": {"version": "1.0.0"},
                "2.0.0": {"version": "2.0.0"},
                "latest": {"version": "latest"},
                "dev": {"version": "dev"}
            },
            "dist-tags": {
                "latest": "latest"
            }
        }"#;

        // Block the non-semver "latest" version
        let blocked = vec![BlockedVersion::new("latest", "invalid version")];
        let filtered = plugin.filter_json_metadata(json, &blocked).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&filtered).unwrap();

        // Non-semver version should be removed
        let versions = doc["versions"].as_object().unwrap();
        assert!(!versions.contains_key("latest"));
        assert!(versions.contains_key("1.0.0"));
        assert!(versions.contains_key("2.0.0"));
        assert!(versions.contains_key("dev")); // Not blocked

        // dist-tags.latest should be updated to highest semver version (2.0.0)
        let latest = doc["dist-tags"]["latest"].as_str().unwrap();
        assert_eq!(
            latest, "2.0.0",
            "Should fall back to highest semver-compliant version"
        );
    }

    // Test 18: Missing dist-tags should be handled gracefully
    #[test]
    fn test_filter_json_missing_dist_tags() {
        let plugin = NpmPlugin::new();

        let json = r#"{
            "name": "no-dist-tags",
            "versions": {
                "1.0.0": {"version": "1.0.0"},
                "1.0.1": {"version": "1.0.1"}
            }
        }"#;

        let blocked = vec![BlockedVersion::new("1.0.1", "vulnerability")];
        let result = plugin.filter_json_metadata(json, &blocked);

        // Should not panic and should complete successfully
        assert!(result.is_ok());
        let filtered = result.unwrap();
        let doc: serde_json::Value = serde_json::from_str(&filtered).unwrap();

        // Version should still be filtered
        let versions = doc["versions"].as_object().unwrap();
        assert!(versions.contains_key("1.0.0"));
        assert!(!versions.contains_key("1.0.1"));
    }

    // Test 19: Empty versions object should be handled
    #[test]
    fn test_filter_json_empty_versions() {
        let plugin = NpmPlugin::new();

        let json = r#"{
            "name": "empty-pkg",
            "versions": {},
            "dist-tags": {
                "latest": "1.0.0"
            }
        }"#;

        let blocked = vec![BlockedVersion::new("1.0.0", "test")];
        let result = plugin.filter_json_metadata(json, &blocked);

        assert!(result.is_ok());
    }
}
