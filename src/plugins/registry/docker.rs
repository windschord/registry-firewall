//! Docker registry plugin
//!
//! This module implements the Docker Registry API v2 proxy.

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

/// Configuration for Docker plugin
#[derive(Debug, Clone)]
pub struct DockerConfig {
    /// Upstream registry URL (default: https://registry-1.docker.io)
    pub upstream: String,

    /// Auth service URL (default: https://auth.docker.io)
    pub auth_service: String,

    /// Path prefix for this plugin (default: /v2)
    pub path_prefix: String,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            upstream: "https://registry-1.docker.io".to_string(),
            auth_service: "https://auth.docker.io".to_string(),
            path_prefix: "/v2".to_string(),
            cache_ttl_secs: 3600,
        }
    }
}

/// Docker request type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerRequestType {
    /// API version check: /v2/
    VersionCheck,
    /// Manifest request: /v2/{name}/manifests/{reference}
    Manifest,
    /// Blob request: /v2/{name}/blobs/{digest}
    Blob,
    /// Tag list: /v2/{name}/tags/list
    TagList,
    /// Catalog: /v2/_catalog
    Catalog,
}

/// Docker tag list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagList {
    /// Repository name
    pub name: String,

    /// List of tags
    pub tags: Vec<String>,
}

/// Docker registry proxy plugin
pub struct DockerPlugin {
    config: DockerConfig,
    client: Client,
    /// Cached auth tokens (reserved for future use)
    #[allow(dead_code)]
    auth_tokens: Arc<RwLock<std::collections::HashMap<String, AuthToken>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AuthToken {
    token: String,
    expires_at: std::time::Instant,
}

impl DockerPlugin {
    /// Create a new Docker plugin with default configuration
    pub fn new() -> Self {
        Self::with_config(DockerConfig::default())
    }

    /// Create a new Docker plugin with custom configuration
    pub fn with_config(config: DockerConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            auth_tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Parse a Docker registry request path
    pub fn parse_docker_path(
        &self,
        path: &str,
    ) -> Result<(String, DockerRequestType, Option<String>), ParseError> {
        let path = path
            .strip_prefix(&self.config.path_prefix)
            .unwrap_or(path)
            .trim_start_matches('/');

        // Version check: empty or /
        if path.is_empty() || path == "/" {
            return Ok(("".to_string(), DockerRequestType::VersionCheck, None));
        }

        // Catalog: _catalog
        if path == "_catalog" {
            return Ok(("".to_string(), DockerRequestType::Catalog, None));
        }

        // Parse {name}/manifests/{reference}, {name}/blobs/{digest}, {name}/tags/list
        // Name can contain slashes (e.g., library/nginx, myrepo/myimage)

        // Find the operation part
        if let Some(pos) = path.rfind("/manifests/") {
            let name = &path[..pos];
            let reference = &path[pos + 11..]; // Skip "/manifests/"
            return Ok((
                name.to_string(),
                DockerRequestType::Manifest,
                Some(reference.to_string()),
            ));
        }

        if let Some(pos) = path.rfind("/blobs/") {
            let name = &path[..pos];
            let digest = &path[pos + 7..]; // Skip "/blobs/"
            return Ok((
                name.to_string(),
                DockerRequestType::Blob,
                Some(digest.to_string()),
            ));
        }

        if let Some(pos) = path.rfind("/tags/list") {
            let name = &path[..pos];
            return Ok((name.to_string(), DockerRequestType::TagList, None));
        }

        Err(ParseError::InvalidPath(format!(
            "Invalid Docker registry path: {}",
            path
        )))
    }

    /// Normalize image name (add library/ prefix for official images)
    pub fn normalize_image_name(name: &str) -> String {
        if !name.contains('/') {
            format!("library/{}", name)
        } else {
            name.to_string()
        }
    }

    /// Parse digest from a reference
    pub fn parse_digest(reference: &str) -> Option<String> {
        if reference.starts_with("sha256:") {
            Some(reference.to_string())
        } else {
            None
        }
    }

    /// Check if reference is a tag (not a digest)
    pub fn is_tag(reference: &str) -> bool {
        !reference.starts_with("sha256:")
    }

    /// Filter tag list to remove blocked versions
    pub fn filter_tag_list(&self, tag_list: &TagList, blocked: &[BlockedVersion]) -> TagList {
        TagList {
            name: tag_list.name.clone(),
            tags: tag_list
                .tags
                .iter()
                .filter(|tag| !blocked.iter().any(|bv| &bv.version == *tag))
                .cloned()
                .collect(),
        }
    }
}

impl Default for DockerPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryPlugin for DockerPlugin {
    fn name(&self) -> &str {
        "docker"
    }

    fn path_prefix(&self) -> &str {
        &self.config.path_prefix
    }

    fn ecosystem(&self) -> &str {
        "docker"
    }

    fn parse_request(&self, path: &str, _method: &str) -> Result<PackageRequest, ParseError> {
        let (name, req_type, reference) = self.parse_docker_path(path)?;

        let request_type = match req_type {
            DockerRequestType::VersionCheck | DockerRequestType::Catalog => RequestType::Metadata,
            DockerRequestType::TagList => RequestType::TagList,
            DockerRequestType::Manifest => RequestType::Manifest,
            DockerRequestType::Blob => RequestType::Blob,
        };

        let normalized_name = if name.is_empty() {
            name
        } else {
            Self::normalize_image_name(&name)
        };

        Ok(PackageRequest {
            ecosystem: "docker".to_string(),
            name: normalized_name,
            version: reference,
            request_type,
            path: path.to_string(),
        })
    }

    async fn handle_request(
        &self,
        ctx: &RequestContext,
        path: &str,
        _method: &str,
        headers: &[(String, String)],
    ) -> Result<RegistryResponse, ProxyError> {
        let (name, req_type, reference) = self.parse_docker_path(path)?;

        // Check security plugins for blocked packages/versions
        let mut blocked_versions = Vec::new();
        for plugin in &ctx.security_plugins {
            if let Some(ref tag) = reference {
                // Only check if it's a tag (not a digest)
                if Self::is_tag(tag) {
                    let normalized = Self::normalize_image_name(&name);
                    if let Some(reason) = plugin.check_package("docker", &normalized, tag).await {
                        return Ok(RegistryResponse::blocked(&reason.reason));
                    }
                }
            } else if req_type == DockerRequestType::TagList {
                let normalized = Self::normalize_image_name(&name);
                let blocked = plugin.get_blocked_packages("docker").await;
                for pkg in blocked {
                    if pkg.package == normalized {
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
        let upstream_url = format!("{}/v2{}", self.config.upstream, upstream_path);

        // Build request with forwarded headers
        let mut request = self.client.get(&upstream_url);

        // Forward relevant headers
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            if key_lower == "authorization"
                || key_lower == "accept"
                || key_lower.starts_with("docker-")
            {
                request = request.header(key, value);
            }
        }

        // Fetch from upstream
        let response = request.send().await.map_err(ProxyError::Upstream)?;

        // Handle authentication challenge
        if response.status().as_u16() == 401 {
            // Return the WWW-Authenticate header for client to handle
            let mut resp = RegistryResponse::new(401, Bytes::from_static(b"Unauthorized"));
            if let Some(auth_header) = response.headers().get("www-authenticate") {
                if let Ok(value) = auth_header.to_str() {
                    resp = resp.with_header("WWW-Authenticate", value);
                }
            }
            return Ok(resp);
        }

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

        // Forward Docker-specific headers
        let mut resp_headers = Vec::new();
        for (key, value) in response.headers() {
            let key_str = key.as_str().to_lowercase();
            if key_str.starts_with("docker-") || key_str == "etag" {
                if let Ok(v) = value.to_str() {
                    resp_headers.push((key.as_str().to_string(), v.to_string()));
                }
            }
        }

        let body = response.bytes().await.map_err(ProxyError::Upstream)?;

        // Filter tag list if needed
        if req_type == DockerRequestType::TagList && !blocked_versions.is_empty() {
            let filtered = self.filter_metadata(&body, &blocked_versions)?;
            let mut resp = RegistryResponse::ok(filtered).with_content_type(content_type);
            for (k, v) in resp_headers {
                resp = resp.with_header(k, v);
            }
            return Ok(resp);
        }

        let mut resp = RegistryResponse::ok(body).with_content_type(content_type);
        for (k, v) in resp_headers {
            resp = resp.with_header(k, v);
        }
        Ok(resp)
    }

    fn filter_metadata(
        &self,
        metadata: &[u8],
        blocked: &[BlockedVersion],
    ) -> Result<Vec<u8>, FilterError> {
        let content = std::str::from_utf8(metadata)
            .map_err(|e| FilterError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        let tag_list: TagList = serde_json::from_str(content)
            .map_err(|e| FilterError::Parse(format!("Invalid JSON: {}", e)))?;

        let filtered = self.filter_tag_list(&tag_list, blocked);
        let json = serde_json::to_vec(&filtered)
            .map_err(|e| FilterError::Parse(format!("Serialization error: {}", e)))?;

        Ok(json)
    }

    fn cache_key(&self, package: &str, version: Option<&str>) -> String {
        let normalized = Self::normalize_image_name(package);
        match version {
            Some(v) => format!("docker:{}:{}", normalized, v),
            None => format!("docker:{}:tags", normalized),
        }
    }

    fn upstream_url(&self) -> &str {
        &self.config.upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Plugin name, ecosystem, and path prefix
    #[test]
    fn test_docker_plugin_name() {
        let plugin = DockerPlugin::new();
        assert_eq!(plugin.name(), "docker");
        assert_eq!(plugin.ecosystem(), "docker");
        assert_eq!(plugin.path_prefix(), "/v2");
    }

    // Test 2: Image name normalization adds library/ prefix
    #[test]
    fn test_normalize_image_name() {
        assert_eq!(DockerPlugin::normalize_image_name("nginx"), "library/nginx");
        assert_eq!(
            DockerPlugin::normalize_image_name("library/nginx"),
            "library/nginx"
        );
        assert_eq!(
            DockerPlugin::normalize_image_name("myrepo/myimage"),
            "myrepo/myimage"
        );
    }

    // Test 3: Parse API version check request (/v2/)
    #[test]
    fn test_parse_version_check() {
        let plugin = DockerPlugin::new();
        let req = plugin.parse_request("/v2/", "GET").unwrap();

        assert_eq!(req.ecosystem, "docker");
        assert_eq!(req.name, "");
        assert_eq!(req.request_type, RequestType::Metadata);
    }

    // Test 4: Parse manifest request by tag
    #[test]
    fn test_parse_manifest_request() {
        let plugin = DockerPlugin::new();
        let req = plugin
            .parse_request("/v2/library/nginx/manifests/latest", "GET")
            .unwrap();

        assert_eq!(req.ecosystem, "docker");
        assert_eq!(req.name, "library/nginx");
        assert_eq!(req.version, Some("latest".to_string()));
        assert_eq!(req.request_type, RequestType::Manifest);
    }

    // Test 5: Parse manifest request by digest
    #[test]
    fn test_parse_manifest_by_digest() {
        let plugin = DockerPlugin::new();
        let req = plugin
            .parse_request("/v2/library/nginx/manifests/sha256:abc123", "GET")
            .unwrap();

        assert_eq!(req.name, "library/nginx");
        assert_eq!(req.version, Some("sha256:abc123".to_string()));
    }

    // Test 6: Parse blob download request
    #[test]
    fn test_parse_blob_request() {
        let plugin = DockerPlugin::new();
        let req = plugin
            .parse_request("/v2/library/nginx/blobs/sha256:abc123", "GET")
            .unwrap();

        assert_eq!(req.name, "library/nginx");
        assert_eq!(req.version, Some("sha256:abc123".to_string()));
        assert_eq!(req.request_type, RequestType::Blob);
    }

    // Test 7: Parse tags list request
    #[test]
    fn test_parse_tags_list() {
        let plugin = DockerPlugin::new();
        let req = plugin
            .parse_request("/v2/library/nginx/tags/list", "GET")
            .unwrap();

        assert_eq!(req.name, "library/nginx");
        assert_eq!(req.version, None);
        assert_eq!(req.request_type, RequestType::TagList);
    }

    // Test 8: Parse catalog request
    #[test]
    fn test_parse_catalog() {
        let plugin = DockerPlugin::new();
        let req = plugin.parse_request("/v2/_catalog", "GET").unwrap();

        assert_eq!(req.name, "");
        assert_eq!(req.request_type, RequestType::Metadata);
    }

    // Test 9: Short image names normalized to library/
    #[test]
    fn test_parse_short_image_name() {
        let plugin = DockerPlugin::new();
        let req = plugin
            .parse_request("/v2/nginx/manifests/latest", "GET")
            .unwrap();

        // Short names get normalized to library/
        assert_eq!(req.name, "library/nginx");
    }

    // Test 10: Invalid path returns error
    #[test]
    fn test_parse_invalid_path() {
        let plugin = DockerPlugin::new();
        let err = plugin.parse_request("/v2/nginx/invalid", "GET");
        assert!(err.is_err());
    }

    // Test 11: Tag vs digest detection
    #[test]
    fn test_is_tag() {
        assert!(DockerPlugin::is_tag("latest"));
        assert!(DockerPlugin::is_tag("v1.0.0"));
        assert!(!DockerPlugin::is_tag("sha256:abc123"));
    }

    // Test 12: Digest parsing from reference
    #[test]
    fn test_parse_digest() {
        assert_eq!(
            DockerPlugin::parse_digest("sha256:abc123"),
            Some("sha256:abc123".to_string())
        );
        assert_eq!(DockerPlugin::parse_digest("latest"), None);
    }

    // Test 13: Tag list filtering removes blocked versions
    #[test]
    fn test_filter_tag_list() {
        let plugin = DockerPlugin::new();
        let tag_list = TagList {
            name: "library/nginx".to_string(),
            tags: vec![
                "1.20".to_string(),
                "1.21".to_string(),
                "1.22".to_string(),
                "latest".to_string(),
            ],
        };

        let blocked = vec![BlockedVersion::new("1.21", "vulnerability")];
        let filtered = plugin.filter_tag_list(&tag_list, &blocked);

        assert_eq!(filtered.name, "library/nginx");
        assert!(filtered.tags.contains(&"1.20".to_string()));
        assert!(!filtered.tags.contains(&"1.21".to_string()));
        assert!(filtered.tags.contains(&"1.22".to_string()));
        assert!(filtered.tags.contains(&"latest".to_string()));
    }

    // Test 14: filter_metadata trait method implementation
    #[test]
    fn test_filter_metadata() {
        let plugin = DockerPlugin::new();
        let tag_list = TagList {
            name: "nginx".to_string(),
            tags: vec!["1.0".to_string(), "1.1".to_string()],
        };
        let json = serde_json::to_vec(&tag_list).unwrap();

        let blocked = vec![BlockedVersion::new("1.1", "test")];
        let result = plugin.filter_metadata(&json, &blocked).unwrap();
        let filtered: TagList = serde_json::from_slice(&result).unwrap();

        assert!(filtered.tags.contains(&"1.0".to_string()));
        assert!(!filtered.tags.contains(&"1.1".to_string()));
    }

    // Test 15: Cache key generation with normalization
    #[test]
    fn test_cache_key_generation() {
        let plugin = DockerPlugin::new();

        assert_eq!(
            plugin.cache_key("nginx", Some("latest")),
            "docker:library/nginx:latest"
        );
        assert_eq!(
            plugin.cache_key("library/nginx", None),
            "docker:library/nginx:tags"
        );
    }

    // Test 16: Default configuration values
    #[test]
    fn test_config_defaults() {
        let config = DockerConfig::default();
        assert_eq!(config.upstream, "https://registry-1.docker.io");
        assert_eq!(config.auth_service, "https://auth.docker.io");
        assert_eq!(config.path_prefix, "/v2");
    }

    // Test 17: TagList JSON serialization roundtrip
    #[test]
    fn test_tag_list_serialization() {
        let tag_list = TagList {
            name: "library/nginx".to_string(),
            tags: vec!["latest".to_string(), "1.20".to_string()],
        };

        let json = serde_json::to_string(&tag_list).unwrap();
        assert!(json.contains("library/nginx"));
        assert!(json.contains("latest"));

        let parsed: TagList = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "library/nginx");
        assert_eq!(parsed.tags.len(), 2);
    }
}
