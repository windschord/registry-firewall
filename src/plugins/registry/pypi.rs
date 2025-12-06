//! PyPI registry plugin
//!
//! This module implements the PyPI Simple API proxy.

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{FilterError, ParseError, ProxyError};
use crate::models::block::BlockedVersion;
use crate::models::package::PackageRequest;

use super::traits::{RegistryPlugin, RegistryResponse, RequestContext};

/// Configuration for PyPI plugin
#[derive(Debug, Clone)]
pub struct PyPIConfig {
    /// Upstream PyPI URL (default: https://pypi.org)
    pub upstream: String,

    /// Path prefix for this plugin (default: /pypi)
    pub path_prefix: String,

    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for PyPIConfig {
    fn default() -> Self {
        Self {
            upstream: "https://pypi.org".to_string(),
            path_prefix: "/pypi".to_string(),
            cache_ttl_secs: 86400,
        }
    }
}

/// PyPI Simple API proxy plugin
pub struct PyPIPlugin {
    config: PyPIConfig,
    client: Client,
    /// Cache for ETag/Last-Modified headers (reserved for future use)
    #[allow(dead_code)]
    cache_state: Arc<RwLock<std::collections::HashMap<String, CacheState>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CacheState {
    etag: Option<String>,
    last_modified: Option<String>,
}

impl PyPIPlugin {
    /// Create a new PyPI plugin with default configuration
    pub fn new() -> Self {
        Self::with_config(PyPIConfig::default())
    }

    /// Create a new PyPI plugin with custom configuration
    pub fn with_config(config: PyPIConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            cache_state: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Parse a Simple API request path
    fn parse_simple_api_path(&self, path: &str) -> Result<String, ParseError> {
        // Remove the prefix
        let path = path.strip_prefix(&self.config.path_prefix).unwrap_or(path);

        // Simple API path: /simple/{package}/ or /simple/{package}
        if let Some(rest) = path.strip_prefix("/simple/") {
            let package = rest.trim_end_matches('/');
            if package.is_empty() {
                return Err(ParseError::MissingParameter("package name".to_string()));
            }
            // Normalize package name (PEP 503)
            let normalized = Self::normalize_package_name(package);
            Ok(normalized)
        } else {
            Err(ParseError::InvalidPath(format!(
                "Expected /simple/{{package}}, got {}",
                path
            )))
        }
    }

    /// Parse a package file download path
    fn parse_packages_path(&self, path: &str) -> Result<(String, String, String), ParseError> {
        // Remove the prefix
        let path = path.strip_prefix(&self.config.path_prefix).unwrap_or(path);

        // Packages path: /packages/{hash_prefix}/{hash}/{filename}
        // or /packages/source/{first_letter}/{package}/{filename}
        if let Some(rest) = path.strip_prefix("/packages/") {
            // For simplicity, extract package name and version from filename
            let parts: Vec<&str> = rest.rsplitn(2, '/').collect();
            if parts.is_empty() {
                return Err(ParseError::InvalidPath("Empty packages path".to_string()));
            }

            let filename = parts[0];
            // Parse filename like: requests-2.31.0.tar.gz or requests-2.31.0-py3-none-any.whl
            if let Some((package, version)) = Self::parse_package_filename(filename) {
                return Ok((package, version, filename.to_string()));
            }

            Err(ParseError::InvalidPath(format!(
                "Cannot parse package filename: {}",
                filename
            )))
        } else {
            Err(ParseError::InvalidPath(format!(
                "Expected /packages/..., got {}",
                path
            )))
        }
    }

    /// Normalize package name according to PEP 503
    pub fn normalize_package_name(name: &str) -> String {
        name.to_lowercase().replace(['-', '.', '_'], "-")
    }

    /// Parse package name and version from a filename
    pub fn parse_package_filename(filename: &str) -> Option<(String, String)> {
        // Handle .tar.gz files
        let filename = if filename.ends_with(".tar.gz") {
            filename.strip_suffix(".tar.gz")?
        } else if filename.ends_with(".zip") {
            filename.strip_suffix(".zip")?
        } else if filename.ends_with(".whl") {
            // Wheel format: {distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl
            let base = filename.strip_suffix(".whl")?;
            let parts: Vec<&str> = base.split('-').collect();
            if parts.len() >= 2 {
                return Some((parts[0].to_string(), parts[1].to_string()));
            }
            return None;
        } else {
            return None;
        };

        // Find the last hyphen followed by a version number
        let parts: Vec<&str> = filename.rsplitn(2, '-').collect();
        if parts.len() == 2 {
            let version = parts[0];
            let package = parts[1];
            // Basic version validation (starts with digit)
            if version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return Some((package.to_string(), version.to_string()));
            }
        }

        None
    }

    /// Filter HTML metadata to remove blocked versions
    pub fn filter_html(&self, html: &str, blocked: &[BlockedVersion]) -> String {
        let mut result = String::new();

        for line in html.lines() {
            let trimmed = line.trim();

            // Check if this line contains an <a> tag with href
            if trimmed.contains("<a ") && trimmed.contains("href=") {
                // Check if any blocked version is in this line
                let should_block = blocked.iter().any(|bv| {
                    // Check for version patterns in href or link text
                    // Patterns: -VERSION.ext, -VERSION-tag, -VERSION)
                    trimmed.contains(&format!("-{}.tar", bv.version))
                        || trimmed.contains(&format!("-{}.whl", bv.version))
                        || trimmed.contains(&format!("-{}.zip", bv.version))
                        || trimmed.contains(&format!("-{}-", bv.version))
                        || trimmed.contains(&format!(
                            ">{}-{}",
                            trimmed
                                .split('>')
                                .nth(1)
                                .unwrap_or("")
                                .split('-')
                                .next()
                                .unwrap_or(""),
                            bv.version
                        ))
                });

                if should_block {
                    // Skip this line entirely
                    continue;
                }
            }

            result.push_str(line);
            result.push('\n');
        }

        result
    }
}

impl Default for PyPIPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryPlugin for PyPIPlugin {
    fn name(&self) -> &str {
        "pypi"
    }

    fn path_prefix(&self) -> &str {
        &self.config.path_prefix
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }

    fn parse_request(&self, path: &str, _method: &str) -> Result<PackageRequest, ParseError> {
        // Try to parse as Simple API request first
        if path.contains("/simple/") {
            let package = self.parse_simple_api_path(path)?;
            return Ok(PackageRequest::metadata("pypi", package, path));
        }

        // Try to parse as packages download
        if path.contains("/packages/") {
            let (package, version, _filename) = self.parse_packages_path(path)?;
            return Ok(PackageRequest::download("pypi", package, version, path));
        }

        Err(ParseError::InvalidPath(format!(
            "Unknown PyPI path format: {}",
            path
        )))
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
                    if pkg.package == pkg_req.name {
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
            .unwrap_or("text/html")
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
        let html = std::str::from_utf8(metadata)
            .map_err(|e| FilterError::InvalidFormat(format!("Invalid UTF-8: {}", e)))?;

        let filtered = self.filter_html(html, blocked);
        Ok(filtered.into_bytes())
    }

    fn cache_key(&self, package: &str, version: Option<&str>) -> String {
        let normalized = Self::normalize_package_name(package);
        match version {
            Some(v) => format!("pypi:{}:{}", normalized, v),
            None => format!("pypi:{}:metadata", normalized),
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

    #[test]
    fn test_pypi_plugin_name() {
        let plugin = PyPIPlugin::new();
        assert_eq!(plugin.name(), "pypi");
        assert_eq!(plugin.ecosystem(), "pypi");
        assert_eq!(plugin.path_prefix(), "/pypi");
    }

    #[test]
    fn test_normalize_package_name() {
        assert_eq!(PyPIPlugin::normalize_package_name("Requests"), "requests");
        assert_eq!(
            PyPIPlugin::normalize_package_name("Flask-RESTful"),
            "flask-restful"
        );
        assert_eq!(
            PyPIPlugin::normalize_package_name("typing_extensions"),
            "typing-extensions"
        );
        assert_eq!(
            PyPIPlugin::normalize_package_name("zope.interface"),
            "zope-interface"
        );
    }

    #[test]
    fn test_parse_simple_api_request() {
        let plugin = PyPIPlugin::new();

        let req = plugin
            .parse_request("/pypi/simple/requests/", "GET")
            .unwrap();
        assert_eq!(req.ecosystem, "pypi");
        assert_eq!(req.name, "requests");
        assert_eq!(req.request_type, RequestType::Metadata);
        assert!(req.is_metadata());

        let req = plugin
            .parse_request("/pypi/simple/Flask-RESTful/", "GET")
            .unwrap();
        assert_eq!(req.name, "flask-restful");
    }

    #[test]
    fn test_parse_packages_request() {
        let plugin = PyPIPlugin::new();

        // Test tar.gz file
        let req = plugin
            .parse_request("/pypi/packages/ab/cd/requests-2.31.0.tar.gz", "GET")
            .unwrap();
        assert_eq!(req.ecosystem, "pypi");
        assert_eq!(req.name, "requests");
        assert_eq!(req.version, Some("2.31.0".to_string()));
        assert_eq!(req.request_type, RequestType::Download);
        assert!(req.is_download());
    }

    #[test]
    fn test_parse_wheel_filename() {
        let result = PyPIPlugin::parse_package_filename("requests-2.31.0-py3-none-any.whl");
        assert!(result.is_some());
        let (pkg, ver) = result.unwrap();
        assert_eq!(pkg, "requests");
        assert_eq!(ver, "2.31.0");
    }

    #[test]
    fn test_parse_tarball_filename() {
        let result = PyPIPlugin::parse_package_filename("requests-2.31.0.tar.gz");
        assert!(result.is_some());
        let (pkg, ver) = result.unwrap();
        assert_eq!(pkg, "requests");
        assert_eq!(ver, "2.31.0");
    }

    #[test]
    fn test_parse_invalid_path() {
        let plugin = PyPIPlugin::new();

        let err = plugin.parse_request("/invalid/path", "GET");
        assert!(err.is_err());
    }

    #[test]
    fn test_filter_html_removes_blocked_versions() {
        let plugin = PyPIPlugin::new();
        let html = r#"
<!DOCTYPE html>
<html>
<body>
<a href="requests-2.30.0.tar.gz">requests-2.30.0.tar.gz</a>
<a href="requests-2.31.0.tar.gz">requests-2.31.0.tar.gz</a>
<a href="requests-2.32.0.tar.gz">requests-2.32.0.tar.gz</a>
</body>
</html>
"#;

        let blocked = vec![BlockedVersion::new("2.31.0", "vulnerability")];
        let filtered = plugin.filter_html(html, &blocked);

        assert!(filtered.contains("2.30.0"));
        assert!(!filtered.contains("2.31.0"));
        assert!(filtered.contains("2.32.0"));
    }

    #[test]
    fn test_filter_metadata() {
        let plugin = PyPIPlugin::new();
        let html = r#"<a href="pkg-1.0.0.tar.gz">pkg-1.0.0.tar.gz</a>
<a href="pkg-1.0.1.tar.gz">pkg-1.0.1.tar.gz</a>"#;

        let blocked = vec![BlockedVersion::new("1.0.1", "test block")];
        let result = plugin.filter_metadata(html.as_bytes(), &blocked).unwrap();
        let filtered = String::from_utf8(result).unwrap();

        assert!(filtered.contains("1.0.0"));
        assert!(!filtered.contains("1.0.1"));
    }

    #[test]
    fn test_cache_key_generation() {
        let plugin = PyPIPlugin::new();

        assert_eq!(
            plugin.cache_key("requests", Some("2.31.0")),
            "pypi:requests:2.31.0"
        );
        assert_eq!(
            plugin.cache_key("Flask-RESTful", None),
            "pypi:flask-restful:metadata"
        );
    }

    #[test]
    fn test_config_defaults() {
        let config = PyPIConfig::default();
        assert_eq!(config.upstream, "https://pypi.org");
        assert_eq!(config.path_prefix, "/pypi");
        assert_eq!(config.cache_ttl_secs, 86400);
    }

    #[test]
    fn test_custom_config() {
        let config = PyPIConfig {
            upstream: "https://custom.pypi.org".to_string(),
            path_prefix: "/custom-pypi".to_string(),
            cache_ttl_secs: 3600,
        };
        let plugin = PyPIPlugin::with_config(config);

        assert_eq!(plugin.upstream_url(), "https://custom.pypi.org");
        assert_eq!(plugin.path_prefix(), "/custom-pypi");
    }

    #[test]
    fn test_registry_response_blocked() {
        let resp = RegistryResponse::blocked("malware detected");
        assert_eq!(resp.status, 403);
        assert!(String::from_utf8_lossy(&resp.body).contains("malware detected"));
    }
}
