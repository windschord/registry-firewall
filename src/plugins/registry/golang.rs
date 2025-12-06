//! Go Module proxy plugin
//!
//! This module implements the Go Module Proxy protocol.

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{FilterError, ParseError, ProxyError};
use crate::models::block::BlockedVersion;
use crate::models::package::{PackageRequest, RequestType};

use super::traits::{RegistryPlugin, RegistryResponse, RequestContext};

/// Configuration for Go Module plugin
#[derive(Debug, Clone)]
pub struct GoModuleConfig {
    /// Upstream Go proxy URL (default: https://proxy.golang.org)
    pub upstream: String,

    /// Path prefix for this plugin (default: /go)
    pub path_prefix: String,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for GoModuleConfig {
    fn default() -> Self {
        Self {
            upstream: "https://proxy.golang.org".to_string(),
            path_prefix: "/go".to_string(),
            cache_ttl_secs: 86400,
        }
    }
}

/// Go Module request type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoRequestType {
    /// List of versions: /@v/list
    List,
    /// Version info: /@v/{version}.info
    Info,
    /// go.mod file: /@v/{version}.mod
    Mod,
    /// Source zip: /@v/{version}.zip
    Zip,
    /// Latest version: /@latest
    Latest,
}

/// Go Module proxy plugin
pub struct GoModulePlugin {
    config: GoModuleConfig,
    client: Client,
    /// Cache for version lists (reserved for future use)
    #[allow(dead_code)]
    cache_state: Arc<RwLock<std::collections::HashMap<String, Vec<String>>>>,
}

impl GoModulePlugin {
    /// Create a new Go Module plugin with default configuration
    pub fn new() -> Self {
        Self::with_config(GoModuleConfig::default())
    }

    /// Create a new Go Module plugin with custom configuration
    pub fn with_config(config: GoModuleConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            cache_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Escape a module path for use in URLs (Go module proxy protocol)
    ///
    /// Upper case letters are escaped to !{lower} format.
    /// For example: github.com/Azure/azure-sdk -> github.com/!azure/azure-sdk
    pub fn escape_module_path(path: &str) -> String {
        let mut result = String::with_capacity(path.len() + 10);
        for c in path.chars() {
            if c.is_ascii_uppercase() {
                result.push('!');
                result.push(c.to_ascii_lowercase());
            } else {
                result.push(c);
            }
        }
        result
    }

    /// Unescape a module path from URL format
    pub fn unescape_module_path(path: &str) -> String {
        let mut result = String::with_capacity(path.len());
        let mut chars = path.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '!' {
                if let Some(next) = chars.next() {
                    result.push(next.to_ascii_uppercase());
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Parse a Go module request path
    pub fn parse_go_path(&self, path: &str) -> Result<(String, GoRequestType, Option<String>), ParseError> {
        // Remove the prefix
        let path = path
            .strip_prefix(&self.config.path_prefix)
            .unwrap_or(path)
            .trim_start_matches('/');

        // Find @v or @latest
        if let Some(at_pos) = path.rfind("/@v/") {
            let module = &path[..at_pos];
            let rest = &path[at_pos + 4..]; // Skip "/@v/"

            // Parse the version part
            if rest == "list" {
                return Ok((
                    Self::unescape_module_path(module),
                    GoRequestType::List,
                    None,
                ));
            } else if let Some(version) = rest.strip_suffix(".info") {
                return Ok((
                    Self::unescape_module_path(module),
                    GoRequestType::Info,
                    Some(version.to_string()),
                ));
            } else if let Some(version) = rest.strip_suffix(".mod") {
                return Ok((
                    Self::unescape_module_path(module),
                    GoRequestType::Mod,
                    Some(version.to_string()),
                ));
            } else if let Some(version) = rest.strip_suffix(".zip") {
                return Ok((
                    Self::unescape_module_path(module),
                    GoRequestType::Zip,
                    Some(version.to_string()),
                ));
            }
        } else if let Some(at_pos) = path.rfind("/@latest") {
            let module = &path[..at_pos];
            return Ok((
                Self::unescape_module_path(module),
                GoRequestType::Latest,
                None,
            ));
        }

        Err(ParseError::InvalidPath(format!(
            "Invalid Go module path: {}",
            path
        )))
    }

    /// Filter version list to remove blocked versions
    pub fn filter_version_list(&self, list: &str, blocked: &[BlockedVersion]) -> String {
        list.lines()
            .filter(|line| {
                let version = line.trim();
                !blocked.iter().any(|bv| bv.version == version)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for GoModulePlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryPlugin for GoModulePlugin {
    fn name(&self) -> &str {
        "go"
    }

    fn path_prefix(&self) -> &str {
        &self.config.path_prefix
    }

    fn ecosystem(&self) -> &str {
        "go"
    }

    fn parse_request(&self, path: &str, _method: &str) -> Result<PackageRequest, ParseError> {
        let (module, req_type, version) = self.parse_go_path(path)?;

        let request_type = match req_type {
            GoRequestType::List | GoRequestType::Latest => RequestType::Metadata,
            GoRequestType::Info | GoRequestType::Mod | GoRequestType::Zip => RequestType::Download,
        };

        Ok(PackageRequest {
            ecosystem: "go".to_string(),
            name: module,
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
        let _pkg_req = self.parse_request(path, "GET")?;
        let (module, req_type, version) = self.parse_go_path(path)?;

        // Check security plugins for blocked packages/versions
        let mut blocked_versions = Vec::new();
        for plugin in &ctx.security_plugins {
            if let Some(ver) = &version {
                if let Some(reason) = plugin.check_package("go", &module, ver).await {
                    return Ok(RegistryResponse::blocked(&reason.reason));
                }
            } else {
                // For list requests, collect all blocked versions
                let blocked = plugin.get_blocked_packages("go").await;
                for pkg in blocked {
                    if pkg.package == module {
                        blocked_versions.push(BlockedVersion::new(
                            &pkg.version,
                            pkg.reason.unwrap_or_else(|| "Blocked".to_string()),
                        ));
                    }
                }
            }
        }

        // Build upstream URL
        let upstream_path = path
            .strip_prefix(&self.config.path_prefix)
            .unwrap_or(path);
        let upstream_url = format!("{}{}", self.config.upstream, upstream_path);

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
            .unwrap_or("text/plain")
            .to_string();

        let body = response.bytes().await.map_err(ProxyError::Upstream)?;

        // Filter version list if this is a list request
        if req_type == GoRequestType::List && !blocked_versions.is_empty() {
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
        let list = std::str::from_utf8(metadata)
            .map_err(|e| FilterError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        let filtered = self.filter_version_list(list, blocked);
        Ok(filtered.into_bytes())
    }

    fn cache_key(&self, package: &str, version: Option<&str>) -> String {
        match version {
            Some(v) => format!("go:{}:{}", package, v),
            None => format!("go:{}:list", package),
        }
    }

    fn upstream_url(&self) -> &str {
        &self.config.upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_plugin_name() {
        let plugin = GoModulePlugin::new();
        assert_eq!(plugin.name(), "go");
        assert_eq!(plugin.ecosystem(), "go");
        assert_eq!(plugin.path_prefix(), "/go");
    }

    #[test]
    fn test_escape_module_path() {
        assert_eq!(
            GoModulePlugin::escape_module_path("github.com/Azure/azure-sdk"),
            "github.com/!azure/azure-sdk"
        );
        assert_eq!(
            GoModulePlugin::escape_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
        assert_eq!(
            GoModulePlugin::escape_module_path("GitHub.com/TEST"),
            "!git!hub.com/!t!e!s!t"
        );
    }

    #[test]
    fn test_unescape_module_path() {
        assert_eq!(
            GoModulePlugin::unescape_module_path("github.com/!azure/azure-sdk"),
            "github.com/Azure/azure-sdk"
        );
        assert_eq!(
            GoModulePlugin::unescape_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
    }

    #[test]
    fn test_parse_list_request() {
        let plugin = GoModulePlugin::new();
        let req = plugin
            .parse_request("/go/github.com/gin-gonic/gin/@v/list", "GET")
            .unwrap();

        assert_eq!(req.ecosystem, "go");
        assert_eq!(req.name, "github.com/gin-gonic/gin");
        assert_eq!(req.version, None);
        assert_eq!(req.request_type, RequestType::Metadata);
    }

    #[test]
    fn test_parse_info_request() {
        let plugin = GoModulePlugin::new();
        let req = plugin
            .parse_request("/go/github.com/gin-gonic/gin/@v/v1.9.1.info", "GET")
            .unwrap();

        assert_eq!(req.ecosystem, "go");
        assert_eq!(req.name, "github.com/gin-gonic/gin");
        assert_eq!(req.version, Some("v1.9.1".to_string()));
        assert_eq!(req.request_type, RequestType::Download);
    }

    #[test]
    fn test_parse_mod_request() {
        let plugin = GoModulePlugin::new();
        let req = plugin
            .parse_request("/go/github.com/gin-gonic/gin/@v/v1.9.1.mod", "GET")
            .unwrap();

        assert_eq!(req.name, "github.com/gin-gonic/gin");
        assert_eq!(req.version, Some("v1.9.1".to_string()));
    }

    #[test]
    fn test_parse_zip_request() {
        let plugin = GoModulePlugin::new();
        let req = plugin
            .parse_request("/go/github.com/gin-gonic/gin/@v/v1.9.1.zip", "GET")
            .unwrap();

        assert_eq!(req.name, "github.com/gin-gonic/gin");
        assert_eq!(req.version, Some("v1.9.1".to_string()));
    }

    #[test]
    fn test_parse_latest_request() {
        let plugin = GoModulePlugin::new();
        let req = plugin
            .parse_request("/go/github.com/gin-gonic/gin/@latest", "GET")
            .unwrap();

        assert_eq!(req.name, "github.com/gin-gonic/gin");
        assert_eq!(req.version, None);
        assert_eq!(req.request_type, RequestType::Metadata);
    }

    #[test]
    fn test_parse_escaped_path() {
        let plugin = GoModulePlugin::new();
        let req = plugin
            .parse_request("/go/github.com/!azure/azure-sdk/@v/list", "GET")
            .unwrap();

        assert_eq!(req.name, "github.com/Azure/azure-sdk");
    }

    #[test]
    fn test_parse_invalid_path() {
        let plugin = GoModulePlugin::new();
        let err = plugin.parse_request("/go/invalid/path", "GET");
        assert!(err.is_err());
    }

    #[test]
    fn test_filter_version_list() {
        let plugin = GoModulePlugin::new();
        let list = "v1.0.0\nv1.1.0\nv1.2.0\nv1.3.0";

        let blocked = vec![
            BlockedVersion::new("v1.1.0", "vulnerability"),
            BlockedVersion::new("v1.3.0", "malware"),
        ];

        let filtered = plugin.filter_version_list(list, &blocked);

        assert!(filtered.contains("v1.0.0"));
        assert!(!filtered.contains("v1.1.0"));
        assert!(filtered.contains("v1.2.0"));
        assert!(!filtered.contains("v1.3.0"));
    }

    #[test]
    fn test_filter_metadata() {
        let plugin = GoModulePlugin::new();
        let list = "v1.0.0\nv1.1.0\nv1.2.0";

        let blocked = vec![BlockedVersion::new("v1.1.0", "test")];
        let result = plugin.filter_metadata(list.as_bytes(), &blocked).unwrap();
        let filtered = String::from_utf8(result).unwrap();

        assert!(filtered.contains("v1.0.0"));
        assert!(!filtered.contains("v1.1.0"));
        assert!(filtered.contains("v1.2.0"));
    }

    #[test]
    fn test_cache_key_generation() {
        let plugin = GoModulePlugin::new();

        assert_eq!(
            plugin.cache_key("github.com/gin-gonic/gin", Some("v1.9.1")),
            "go:github.com/gin-gonic/gin:v1.9.1"
        );
        assert_eq!(
            plugin.cache_key("github.com/gin-gonic/gin", None),
            "go:github.com/gin-gonic/gin:list"
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = GoModuleConfig::default();
        assert_eq!(config.upstream, "https://proxy.golang.org");
        assert_eq!(config.path_prefix, "/go");
    }
}
