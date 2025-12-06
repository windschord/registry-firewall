//! Registry plugin trait definition
//!
//! This module defines the `RegistryPlugin` trait that all registry plugins must implement.

use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;

use crate::error::{FilterError, ParseError, ProxyError};
use crate::models::block::BlockedVersion;
use crate::models::package::PackageRequest;
use crate::plugins::cache::traits::CachePlugin;
use crate::plugins::security::traits::SecuritySourcePlugin;

/// Context for handling registry requests
#[derive(Clone)]
pub struct RequestContext {
    /// Client identifier (from token)
    pub client_id: Option<String>,

    /// Client IP address
    pub client_ip: Option<String>,

    /// Security plugins to check against
    pub security_plugins: Vec<Arc<dyn SecuritySourcePlugin>>,

    /// Cache plugin for caching responses
    pub cache_plugin: Option<Arc<dyn CachePlugin>>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new() -> Self {
        Self {
            client_id: None,
            client_ip: None,
            security_plugins: Vec::new(),
            cache_plugin: None,
        }
    }

    /// Set the client ID
    pub fn with_client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// Set the client IP
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set the security plugins
    pub fn with_security_plugins(mut self, plugins: Vec<Arc<dyn SecuritySourcePlugin>>) -> Self {
        self.security_plugins = plugins;
        self
    }

    /// Set the cache plugin
    pub fn with_cache_plugin(mut self, plugin: Arc<dyn CachePlugin>) -> Self {
        self.cache_plugin = Some(plugin);
        self
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContext")
            .field("client_id", &self.client_id)
            .field("client_ip", &self.client_ip)
            .field("security_plugins_count", &self.security_plugins.len())
            .field("has_cache_plugin", &self.cache_plugin.is_some())
            .finish()
    }
}

/// Response from a registry plugin
#[derive(Debug, Clone)]
pub struct RegistryResponse {
    /// HTTP status code
    pub status: u16,

    /// Response headers
    pub headers: Vec<(String, String)>,

    /// Response body
    pub body: Bytes,

    /// Content type
    pub content_type: String,
}

impl RegistryResponse {
    /// Create a new response
    pub fn new(status: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
            content_type: "application/octet-stream".to_string(),
        }
    }

    /// Create a successful response
    pub fn ok(body: impl Into<Bytes>) -> Self {
        Self::new(200, body)
    }

    /// Create a not found response
    pub fn not_found() -> Self {
        Self::new(404, Bytes::from_static(b"Not Found"))
    }

    /// Create a blocked response
    pub fn blocked(reason: &str) -> Self {
        Self {
            status: 403,
            headers: Vec::new(),
            body: Bytes::from(format!("Blocked: {}", reason)),
            content_type: "text/plain".to_string(),
        }
    }

    /// Set the content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }

    /// Add a header
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Trait for registry plugins
///
/// Registry plugins handle requests for specific package registries like PyPI, Go modules,
/// Cargo crates, and Docker images.
#[async_trait]
pub trait RegistryPlugin: Send + Sync {
    /// Returns the plugin name
    fn name(&self) -> &str;

    /// Returns the URL path prefix for this plugin
    fn path_prefix(&self) -> &str;

    /// Returns the ecosystem name (e.g., "pypi", "go", "cargo", "docker")
    fn ecosystem(&self) -> &str;

    /// Parse an incoming request to extract package information
    fn parse_request(&self, path: &str, method: &str) -> Result<PackageRequest, ParseError>;

    /// Handle a request and return a response
    ///
    /// This method should:
    /// 1. Parse the request
    /// 2. Check with security plugins for blocked packages
    /// 3. Check the cache for a cached response
    /// 4. Forward to upstream if needed
    /// 5. Filter metadata to remove blocked versions
    /// 6. Cache the response
    /// 7. Return the response
    async fn handle_request(
        &self,
        ctx: &RequestContext,
        path: &str,
        method: &str,
        headers: &[(String, String)],
    ) -> Result<RegistryResponse, ProxyError>;

    /// Filter metadata to remove blocked versions
    fn filter_metadata(
        &self,
        metadata: &[u8],
        blocked: &[BlockedVersion],
    ) -> Result<Vec<u8>, FilterError>;

    /// Generate a cache key for a package
    fn cache_key(&self, package: &str, version: Option<&str>) -> String;

    /// Get the upstream URL for this registry
    fn upstream_url(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: RequestContext creation with default values
    #[test]
    fn test_request_context_new() {
        let ctx = RequestContext::new();
        assert!(ctx.client_id.is_none());
        assert!(ctx.client_ip.is_none());
        assert!(ctx.security_plugins.is_empty());
        assert!(ctx.cache_plugin.is_none());
    }

    // Test 2: RequestContext Default trait implementation
    #[test]
    fn test_request_context_default() {
        let ctx = RequestContext::default();
        assert!(ctx.client_id.is_none());
        assert!(ctx.client_ip.is_none());
    }

    // Test 3: RequestContext builder pattern for setting fields
    #[test]
    fn test_request_context_builder() {
        let ctx = RequestContext::new()
            .with_client_id("client-123")
            .with_client_ip("192.168.1.100");

        assert_eq!(ctx.client_id, Some("client-123".to_string()));
        assert_eq!(ctx.client_ip, Some("192.168.1.100".to_string()));
    }

    // Test 4: RequestContext Debug trait formatting
    #[test]
    fn test_request_context_debug() {
        let ctx = RequestContext::new()
            .with_client_id("test")
            .with_client_ip("127.0.0.1");

        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("client_id"));
        assert!(debug_str.contains("client_ip"));
    }

    // Test 5: RegistryResponse creation with status and body
    #[test]
    fn test_registry_response_new() {
        let resp = RegistryResponse::new(200, "Hello");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Bytes::from("Hello"));
        assert_eq!(resp.content_type, "application/octet-stream");
    }

    // Test 6: RegistryResponse::ok helper for 200 responses
    #[test]
    fn test_registry_response_ok() {
        let resp = RegistryResponse::ok("Success");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, Bytes::from("Success"));
    }

    // Test 7: RegistryResponse::not_found helper for 404 responses
    #[test]
    fn test_registry_response_not_found() {
        let resp = RegistryResponse::not_found();
        assert_eq!(resp.status, 404);
    }

    // Test 8: RegistryResponse::blocked helper for 403 responses
    #[test]
    fn test_registry_response_blocked() {
        let resp = RegistryResponse::blocked("malware detected");
        assert_eq!(resp.status, 403);
        assert!(String::from_utf8_lossy(&resp.body).contains("malware detected"));
    }

    // Test 9: RegistryResponse content-type customization
    #[test]
    fn test_registry_response_with_content_type() {
        let resp = RegistryResponse::ok("{}").with_content_type("application/json");
        assert_eq!(resp.content_type, "application/json");
    }

    // Test 10: RegistryResponse custom header chaining
    #[test]
    fn test_registry_response_with_header() {
        let resp = RegistryResponse::ok("test")
            .with_header("X-Custom", "value")
            .with_header("Cache-Control", "no-cache");

        assert_eq!(resp.headers.len(), 2);
        assert_eq!(
            resp.headers[0],
            ("X-Custom".to_string(), "value".to_string())
        );
        assert_eq!(
            resp.headers[1],
            ("Cache-Control".to_string(), "no-cache".to_string())
        );
    }

    // Test 11: RegistryPlugin trait is object-safe
    #[test]
    fn test_registry_plugin_is_object_safe() {
        fn _takes_plugin(_: &dyn RegistryPlugin) {}
    }
}
