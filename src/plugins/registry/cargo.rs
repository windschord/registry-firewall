//! Cargo registry plugin
//!
//! This module implements the Cargo Sparse Index protocol.

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{FilterError, ParseError, ProxyError};
use crate::models::block::BlockedVersion;
use crate::models::package::{PackageRequest, RequestType};

use super::traits::{RegistryPlugin, RegistryResponse, RequestContext};

/// Configuration for Cargo plugin
#[derive(Debug, Clone)]
pub struct CargoConfig {
    /// Upstream index URL (default: https://index.crates.io)
    pub index_upstream: String,

    /// Upstream download URL (default: https://static.crates.io/crates)
    pub download_upstream: String,

    /// Path prefix for this plugin (default: /cargo)
    pub path_prefix: String,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for CargoConfig {
    fn default() -> Self {
        Self {
            index_upstream: "https://index.crates.io".to_string(),
            download_upstream: "https://static.crates.io/crates".to_string(),
            path_prefix: "/cargo".to_string(),
            cache_ttl_secs: 86400,
        }
    }
}

/// Cargo request type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoRequestType {
    /// Index metadata request
    Index,
    /// Crate download request
    Download,
    /// Config.json request
    Config,
}

/// Cargo index entry (one line in the index file)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Crate name
    pub name: String,

    /// Crate version
    #[serde(rename = "vers")]
    pub version: String,

    /// Dependencies
    #[serde(default)]
    pub deps: Vec<Dependency>,

    /// SHA256 checksum
    #[serde(rename = "cksum")]
    pub checksum: String,

    /// Features
    #[serde(default)]
    pub features: std::collections::HashMap<String, Vec<String>>,

    /// Whether the crate is yanked
    #[serde(default)]
    pub yanked: bool,

    /// Links field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<String>,
}

/// Dependency in index entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Dependency name
    pub name: String,

    /// Version requirement
    pub req: String,

    /// Features to enable
    #[serde(default)]
    pub features: Vec<String>,

    /// Whether this is optional
    #[serde(default)]
    pub optional: bool,

    /// Whether default features are enabled
    #[serde(default = "default_true")]
    pub default_features: bool,

    /// Target platform
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Dependency kind
    #[serde(default)]
    pub kind: String,

    /// Registry URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,

    /// Package name (if different from name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Cargo Sparse Index proxy plugin
pub struct CargoPlugin {
    config: CargoConfig,
    client: Client,
    /// Cache state (reserved for future use)
    #[allow(dead_code)]
    cache_state: Arc<RwLock<std::collections::HashMap<String, CacheState>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CacheState {
    etag: Option<String>,
    last_modified: Option<String>,
}

impl CargoPlugin {
    /// Create a new Cargo plugin with default configuration
    pub fn new() -> Self {
        Self::with_config(CargoConfig::default())
    }

    /// Create a new Cargo plugin with custom configuration
    pub fn with_config(config: CargoConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            cache_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Calculate the index path prefix for a crate name
    ///
    /// According to the Cargo sparse index specification:
    /// - 1 character: 1/{name}
    /// - 2 characters: 2/{name}
    /// - 3 characters: 3/{first letter}/{name}
    /// - 4+ characters: {first two}/{next two}/{name}
    pub fn index_prefix(name: &str) -> String {
        let lower = name.to_lowercase();
        let char_count = lower.chars().count();
        match char_count {
            0 => String::new(),
            1 => format!("1/{}", lower),
            2 => format!("2/{}", lower),
            3 => {
                let first: String = lower.chars().take(1).collect();
                format!("3/{}/{}", first, lower)
            }
            _ => {
                let first_two: String = lower.chars().take(2).collect();
                let next_two: String = lower.chars().skip(2).take(2).collect();
                format!("{}/{}/{}", first_two, next_two, lower)
            }
        }
    }

    /// Parse a Cargo request path
    pub fn parse_cargo_path(
        &self,
        path: &str,
    ) -> Result<(String, CargoRequestType, Option<String>), ParseError> {
        let path = path
            .strip_prefix(&self.config.path_prefix)
            .unwrap_or(path)
            .trim_start_matches('/');

        // Config request
        if path == "config.json" {
            return Ok(("config".to_string(), CargoRequestType::Config, None));
        }

        // Download request: crates/{name}/{version}/download
        // or: crates/{name}/{name}-{version}.crate
        if let Some(rest) = path.strip_prefix("crates/") {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 2 {
                let name = parts[0];

                // Check for {name}/{version}/download format
                if parts.len() >= 3 && parts[2] == "download" {
                    let version = parts[1];
                    return Ok((
                        name.to_string(),
                        CargoRequestType::Download,
                        Some(version.to_string()),
                    ));
                }

                // Check for {name}/{name}-{version}.crate format
                if parts.len() >= 2 {
                    let filename = parts[parts.len() - 1];
                    if let Some(version) = Self::parse_crate_filename(name, filename) {
                        return Ok((name.to_string(), CargoRequestType::Download, Some(version)));
                    }
                }
            }
            return Err(ParseError::InvalidPath(format!(
                "Invalid crates download path: {}",
                path
            )));
        }

        // Index request: {prefix}/{name} (e.g., se/rd/serde)
        // The crate name is the last component
        let parts: Vec<&str> = path.split('/').collect();
        if !parts.is_empty() {
            let name = parts.last().unwrap();
            if !name.is_empty() {
                return Ok((name.to_string(), CargoRequestType::Index, None));
            }
        }

        Err(ParseError::InvalidPath(format!(
            "Invalid Cargo path: {}",
            path
        )))
    }

    /// Parse version from a crate filename
    fn parse_crate_filename(name: &str, filename: &str) -> Option<String> {
        // Format: {name}-{version}.crate
        let prefix = format!("{}-", name);
        if filename.starts_with(&prefix) && filename.ends_with(".crate") {
            let version = filename.strip_prefix(&prefix)?.strip_suffix(".crate")?;
            return Some(version.to_string());
        }
        None
    }

    /// Filter JSON Lines index to remove blocked versions
    pub fn filter_json_lines(&self, content: &str, blocked: &[BlockedVersion]) -> String {
        content
            .lines()
            .filter(|line| {
                if line.trim().is_empty() {
                    return true;
                }
                // Parse each line as JSON
                if let Ok(entry) = serde_json::from_str::<IndexEntry>(line) {
                    !blocked.iter().any(|bv| bv.version == entry.version)
                } else {
                    // Keep unparseable lines
                    true
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for CargoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryPlugin for CargoPlugin {
    fn name(&self) -> &str {
        "cargo"
    }

    fn path_prefix(&self) -> &str {
        &self.config.path_prefix
    }

    fn ecosystem(&self) -> &str {
        "cargo"
    }

    fn parse_request(&self, path: &str, _method: &str) -> Result<PackageRequest, ParseError> {
        let (name, req_type, version) = self.parse_cargo_path(path)?;

        let request_type = match req_type {
            CargoRequestType::Index | CargoRequestType::Config => RequestType::Metadata,
            CargoRequestType::Download => RequestType::Download,
        };

        Ok(PackageRequest {
            ecosystem: "cargo".to_string(),
            name,
            version,
            request_type,
            path: path.to_string(),
        })
    }

    async fn handle_request(
        &self,
        ctx: &RequestContext,
        path: &str,
        _method: &str,
        _headers: &[(String, String)],
    ) -> Result<RegistryResponse, ProxyError> {
        let (name, req_type, version) = self.parse_cargo_path(path)?;

        // Check security plugins for blocked packages/versions
        let mut blocked_versions = Vec::new();
        for plugin in &ctx.security_plugins {
            if let Some(ver) = &version {
                if let Some(reason) = plugin.check_package("cargo", &name, ver).await {
                    return Ok(RegistryResponse::blocked(&reason.reason));
                }
            } else if req_type == CargoRequestType::Index {
                // For index requests, collect all blocked versions
                let blocked = plugin.get_blocked_packages("cargo").await;
                for pkg in blocked {
                    if pkg.package.to_lowercase() == name.to_lowercase() {
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

        let upstream_url = match req_type {
            CargoRequestType::Download => {
                format!("{}{}", self.config.download_upstream, upstream_path)
            }
            _ => format!("{}{}", self.config.index_upstream, upstream_path),
        };

        // Fetch from upstream
        let response = self
            .client
            .get(&upstream_url)
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

        // Filter index if needed
        if req_type == CargoRequestType::Index && !blocked_versions.is_empty() {
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
        let content = std::str::from_utf8(metadata)
            .map_err(|e| FilterError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        let filtered = self.filter_json_lines(content, blocked);
        Ok(filtered.into_bytes())
    }

    fn cache_key(&self, package: &str, version: Option<&str>) -> String {
        let lower = package.to_lowercase();
        match version {
            Some(v) => format!("cargo:{}:{}", lower, v),
            None => format!("cargo:{}:index", lower),
        }
    }

    fn upstream_url(&self) -> &str {
        &self.config.index_upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Plugin name, ecosystem, and path prefix
    #[test]
    fn test_cargo_plugin_name() {
        let plugin = CargoPlugin::new();
        assert_eq!(plugin.name(), "cargo");
        assert_eq!(plugin.ecosystem(), "cargo");
        assert_eq!(plugin.path_prefix(), "/cargo");
    }

    // Test 2: Index prefix for 1-character crate names
    #[test]
    fn test_index_prefix_1_char() {
        assert_eq!(CargoPlugin::index_prefix("a"), "1/a");
    }

    // Test 3: Index prefix for 2-character crate names
    #[test]
    fn test_index_prefix_2_chars() {
        assert_eq!(CargoPlugin::index_prefix("ab"), "2/ab");
    }

    // Test 4: Index prefix for 3-character crate names
    #[test]
    fn test_index_prefix_3_chars() {
        assert_eq!(CargoPlugin::index_prefix("abc"), "3/a/abc");
    }

    // Test 5: Index prefix for 4+ character crate names
    #[test]
    fn test_index_prefix_4_plus_chars() {
        assert_eq!(CargoPlugin::index_prefix("serde"), "se/rd/serde");
        assert_eq!(CargoPlugin::index_prefix("tokio"), "to/ki/tokio");
        assert_eq!(CargoPlugin::index_prefix("SERDE"), "se/rd/serde");
    }

    // Test 6: Parse sparse index metadata request
    #[test]
    fn test_parse_index_request() {
        let plugin = CargoPlugin::new();
        let req = plugin.parse_request("/cargo/se/rd/serde", "GET").unwrap();

        assert_eq!(req.ecosystem, "cargo");
        assert_eq!(req.name, "serde");
        assert_eq!(req.version, None);
        assert_eq!(req.request_type, RequestType::Metadata);
    }

    // Test 7: Parse crate download request with version
    #[test]
    fn test_parse_download_request() {
        let plugin = CargoPlugin::new();
        let req = plugin
            .parse_request("/cargo/crates/serde/1.0.0/download", "GET")
            .unwrap();

        assert_eq!(req.ecosystem, "cargo");
        assert_eq!(req.name, "serde");
        assert_eq!(req.version, Some("1.0.0".to_string()));
        assert_eq!(req.request_type, RequestType::Download);
    }

    // Test 8: Parse .crate file download request
    #[test]
    fn test_parse_crate_file_request() {
        let plugin = CargoPlugin::new();
        let req = plugin
            .parse_request("/cargo/crates/serde/serde-1.0.0.crate", "GET")
            .unwrap();

        assert_eq!(req.name, "serde");
        assert_eq!(req.version, Some("1.0.0".to_string()));
    }

    // Test 9: Parse config.json request
    #[test]
    fn test_parse_config_request() {
        let plugin = CargoPlugin::new();
        let req = plugin.parse_request("/cargo/config.json", "GET").unwrap();

        assert_eq!(req.name, "config");
        assert_eq!(req.request_type, RequestType::Metadata);
    }

    // Test 10: Invalid path returns error
    #[test]
    fn test_parse_invalid_path() {
        let plugin = CargoPlugin::new();
        let err = plugin.parse_request("/cargo/", "GET");
        assert!(err.is_err());
    }

    // Test 11: JSON Lines filtering removes blocked versions
    #[test]
    fn test_filter_json_lines() {
        let plugin = CargoPlugin::new();
        let content = r#"{"name":"serde","vers":"1.0.0","cksum":"abc","deps":[],"features":{}}
{"name":"serde","vers":"1.0.1","cksum":"def","deps":[],"features":{}}
{"name":"serde","vers":"1.0.2","cksum":"ghi","deps":[],"features":{}}"#;

        let blocked = vec![BlockedVersion::new("1.0.1", "vulnerability")];
        let filtered = plugin.filter_json_lines(content, &blocked);

        assert!(filtered.contains("1.0.0"));
        assert!(!filtered.contains("1.0.1"));
        assert!(filtered.contains("1.0.2"));
    }

    // Test 12: filter_metadata trait method implementation
    #[test]
    fn test_filter_metadata() {
        let plugin = CargoPlugin::new();
        let content = r#"{"name":"test","vers":"1.0.0","cksum":"a","deps":[],"features":{}}
{"name":"test","vers":"1.0.1","cksum":"b","deps":[],"features":{}}"#;

        let blocked = vec![BlockedVersion::new("1.0.1", "test")];
        let result = plugin
            .filter_metadata(content.as_bytes(), &blocked)
            .unwrap();
        let filtered = String::from_utf8(result).unwrap();

        assert!(filtered.contains("1.0.0"));
        assert!(!filtered.contains("1.0.1"));
    }

    // Test 13: Cache key generation with case normalization
    #[test]
    fn test_cache_key_generation() {
        let plugin = CargoPlugin::new();

        assert_eq!(
            plugin.cache_key("serde", Some("1.0.0")),
            "cargo:serde:1.0.0"
        );
        assert_eq!(plugin.cache_key("Serde", None), "cargo:serde:index");
    }

    // Test 14: Default configuration values
    #[test]
    fn test_config_defaults() {
        let config = CargoConfig::default();
        assert_eq!(config.index_upstream, "https://index.crates.io");
        assert_eq!(config.download_upstream, "https://static.crates.io/crates");
        assert_eq!(config.path_prefix, "/cargo");
    }

    // Test 15: IndexEntry JSON serialization roundtrip
    #[test]
    fn test_index_entry_serialization() {
        let entry = IndexEntry {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            deps: vec![],
            checksum: "abc123".to_string(),
            features: std::collections::HashMap::new(),
            yanked: false,
            links: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("serde"));
        assert!(json.contains("1.0.0"));

        let parsed: IndexEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "serde");
        assert_eq!(parsed.version, "1.0.0");
    }
}
