//! Rate-limited HTTP client for external API calls
//!
//! This module provides an HTTP client with built-in rate limiting,
//! request interval control, and support for conditional requests
//! using ETag and Last-Modified headers.

use crate::config::RateLimitConfig;
use crate::error::SyncError;
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};
use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, warn};

/// Response from a conditional GET request
#[derive(Debug)]
pub enum ConditionalResponse {
    /// 304 Not Modified - content unchanged since last fetch
    NotModified,
    /// 200 OK with new data
    Modified {
        /// Response body
        body: Bytes,
        /// ETag header value if present
        etag: Option<String>,
        /// Last-Modified header value if present
        last_modified: Option<String>,
    },
}

/// HTTP client with rate limiting capabilities
///
/// Features:
/// - Per-domain request interval enforcement
/// - Global concurrent request limiting via semaphore
/// - ETag/If-Modified-Since support for conditional requests
/// - HTTP 429 handling with Retry-After support
#[derive(Debug)]
pub struct HttpClientWithRateLimit {
    client: Client,
    semaphore: Arc<Semaphore>,
    last_request: Arc<Mutex<HashMap<String, Instant>>>,
    config: RateLimitConfig,
}

impl HttpClientWithRateLimit {
    /// Create a new rate-limited HTTP client
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
            last_request: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Create a rate-limited HTTP client with a custom reqwest Client
    pub fn with_client(client: Client, config: RateLimitConfig) -> Self {
        Self {
            client,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
            last_request: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Perform a GET request
    pub async fn get(&self, url: &str) -> Result<Bytes, SyncError> {
        match self.get_with_cache_headers(url, None, None).await? {
            ConditionalResponse::Modified { body, .. } => Ok(body),
            ConditionalResponse::NotModified => {
                // This shouldn't happen without cache headers, but handle it
                Err(SyncError::InvalidData(
                    "Unexpected 304 without cache headers".to_string(),
                ))
            }
        }
    }

    /// Perform a GET request with ETag/If-Modified-Since support
    ///
    /// # Arguments
    ///
    /// * `url` - The URL to fetch
    /// * `etag` - Previous ETag value for conditional request
    /// * `last_modified` - Previous Last-Modified value for conditional request
    ///
    /// # Returns
    ///
    /// `ConditionalResponse::NotModified` if server returns 304,
    /// `ConditionalResponse::Modified` with body and headers if content changed
    pub async fn get_with_cache_headers(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<ConditionalResponse, SyncError> {
        // Acquire semaphore permit to limit concurrent requests
        let _permit = self
            .semaphore
            .acquire()
            .await
            .expect("Semaphore closed unexpectedly");

        // Wait for rate limit interval if needed
        self.wait_for_rate_limit(url).await;

        // Build request with conditional headers
        let mut headers = HeaderMap::new();
        if let Some(etag_value) = etag {
            if let Ok(value) = HeaderValue::from_str(etag_value) {
                headers.insert(IF_NONE_MATCH, value);
            }
        }
        if let Some(lm_value) = last_modified {
            if let Ok(value) = HeaderValue::from_str(lm_value) {
                headers.insert(IF_MODIFIED_SINCE, value);
            }
        }

        debug!(url = url, "Sending HTTP GET request");

        let response = self
            .client
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    SyncError::NetworkTimeout
                } else if e.is_connect() {
                    SyncError::ConnectionRefused
                } else {
                    SyncError::Network(e.to_string())
                }
            })?;

        match response.status() {
            StatusCode::NOT_MODIFIED => {
                debug!(url = url, "Resource not modified (304)");
                Ok(ConditionalResponse::NotModified)
            }
            StatusCode::OK => {
                let etag = response
                    .headers()
                    .get("ETag")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let last_modified = response
                    .headers()
                    .get("Last-Modified")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                let body = response
                    .bytes()
                    .await
                    .map_err(|e| SyncError::Network(e.to_string()))?;

                debug!(
                    url = url,
                    body_size = body.len(),
                    has_etag = etag.is_some(),
                    "Received response"
                );

                Ok(ConditionalResponse::Modified {
                    body,
                    etag,
                    last_modified,
                })
            }
            StatusCode::TOO_MANY_REQUESTS => {
                // Handle rate limiting with Retry-After header
                let wait = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(self.config.rate_limit_wait_secs);

                warn!(url = url, retry_after = wait, "Rate limited by upstream");
                Err(SyncError::RateLimited(wait))
            }
            StatusCode::NOT_FOUND => {
                debug!(url = url, "Resource not found (404)");
                Err(SyncError::NotFound)
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                warn!(url = url, status = ?response.status(), "Unauthorized");
                Err(SyncError::Unauthorized)
            }
            status if status.is_server_error() => {
                warn!(url = url, status = status.as_u16(), "Server error");
                Err(SyncError::ServerError(status.as_u16()))
            }
            status => {
                warn!(url = url, status = status.as_u16(), "Unexpected status");
                Err(SyncError::ServerError(status.as_u16()))
            }
        }
    }

    /// Wait for the rate limit interval to pass for the given URL's domain
    async fn wait_for_rate_limit(&self, url: &str) {
        let domain = extract_domain(url);
        let min_interval = Duration::from_millis(self.config.min_interval_ms);

        let mut last_requests = self.last_request.lock().await;

        if let Some(last) = last_requests.get(&domain) {
            let elapsed = last.elapsed();
            if elapsed < min_interval {
                let wait_time = min_interval - elapsed;
                debug!(
                    domain = domain,
                    wait_ms = wait_time.as_millis(),
                    "Waiting for rate limit"
                );
                drop(last_requests); // Release lock while waiting
                tokio::time::sleep(wait_time).await;
                last_requests = self.last_request.lock().await;
            }
        }

        last_requests.insert(domain, Instant::now());
    }

    /// Get current configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Get number of available permits (concurrent request slots)
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Extract domain from URL for rate limiting purposes
fn extract_domain(url: &str) -> String {
    url.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or(url)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Test 1: Basic GET request returns body
    #[tokio::test]
    async fn test_basic_get_request() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Hello, World!"))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client.get(&format!("{}/test", mock_server.uri())).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from("Hello, World!"));
    }

    // Test 2: ETag conditional request - returns Not Modified
    #[tokio::test]
    async fn test_etag_not_modified() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/resource"))
            .and(header("If-None-Match", "\"abc123\""))
            .respond_with(ResponseTemplate::new(304))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client
            .get_with_cache_headers(
                &format!("{}/resource", mock_server.uri()),
                Some("\"abc123\""),
                None,
            )
            .await;

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ConditionalResponse::NotModified));
    }

    // Test 3: If-Modified-Since conditional request - verifies 304 response handling
    #[tokio::test]
    async fn test_if_modified_since() {
        let mock_server = MockServer::start().await;
        // Return 304 for any GET request to /resource with any If-Modified-Since header
        Mock::given(method("GET"))
            .and(path("/resource"))
            .and(header_exists("if-modified-since"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client
            .get_with_cache_headers(
                &format!("{}/resource", mock_server.uri()),
                None,
                Some("Wed, 21 Oct 2023 07:28:00 GMT"),
            )
            .await;

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), ConditionalResponse::NotModified));
    }

    // Test 4: Response includes ETag and Last-Modified headers
    #[tokio::test]
    async fn test_response_includes_cache_headers() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/resource"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("content")
                    .insert_header("ETag", "\"xyz789\"")
                    .insert_header("Last-Modified", "Thu, 22 Oct 2023 10:00:00 GMT"),
            )
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client
            .get_with_cache_headers(&format!("{}/resource", mock_server.uri()), None, None)
            .await;

        assert!(result.is_ok());
        match result.unwrap() {
            ConditionalResponse::Modified {
                body,
                etag,
                last_modified,
            } => {
                assert_eq!(body, Bytes::from("content"));
                assert_eq!(etag, Some("\"xyz789\"".to_string()));
                assert_eq!(
                    last_modified,
                    Some("Thu, 22 Oct 2023 10:00:00 GMT".to_string())
                );
            }
            _ => panic!("Expected Modified response"),
        }
    }

    // Test 5: HTTP 429 returns RateLimited error
    #[tokio::test]
    async fn test_429_rate_limited() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "120"))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client.get(&format!("{}/limited", mock_server.uri())).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::RateLimited(secs) => assert_eq!(secs, 120),
            err => panic!("Expected RateLimited error, got {:?}", err),
        }
    }

    // Test 6: HTTP 429 without Retry-After uses default
    #[tokio::test]
    async fn test_429_uses_default_wait() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 30,
        });

        let result = client.get(&format!("{}/limited", mock_server.uri())).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::RateLimited(secs) => assert_eq!(secs, 30),
            err => panic!("Expected RateLimited error, got {:?}", err),
        }
    }

    // Test 7: HTTP 404 returns NotFound error
    #[tokio::test]
    async fn test_404_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client.get(&format!("{}/missing", mock_server.uri())).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncError::NotFound));
    }

    // Test 8: HTTP 5xx returns ServerError
    #[tokio::test]
    async fn test_5xx_server_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/error"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client.get(&format!("{}/error", mock_server.uri())).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::ServerError(code) => assert_eq!(code, 503),
            err => panic!("Expected ServerError, got {:?}", err),
        }
    }

    // Test 9: Concurrent request limiting
    #[tokio::test]
    async fn test_concurrent_request_limiting() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(100)))
            .expect(3)
            .mount(&mock_server)
            .await;

        let client = Arc::new(HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        }));

        // Start 3 concurrent requests with max_concurrent = 2
        let url = format!("{}/slow", mock_server.uri());

        let start = Instant::now();
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let c = client.clone();
                let u = url.clone();
                tokio::spawn(async move { c.get(&u).await })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        let elapsed = start.elapsed();

        // With max_concurrent=2, 3 requests of 100ms each should take ~200ms
        // (first 2 parallel, then 1 more)
        assert!(
            elapsed >= Duration::from_millis(150),
            "Requests should be limited: {:?}",
            elapsed
        );
    }

    // Test 10: Domain rate limiting enforces minimum interval
    #[tokio::test]
    async fn test_domain_rate_limiting() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fast"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(2)
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 100, // 100ms between requests
            max_concurrent: 10,
            rate_limit_wait_secs: 60,
        });

        let url = format!("{}/fast", mock_server.uri());

        let start = Instant::now();
        client.get(&url).await.unwrap();
        client.get(&url).await.unwrap();
        let elapsed = start.elapsed();

        // Second request should wait at least 100ms
        assert!(
            elapsed >= Duration::from_millis(90), // Allow some timing slack
            "Rate limiting should enforce minimum interval: {:?}",
            elapsed
        );
    }

    // Test 11: Domain extraction from URL
    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(
            extract_domain("http://api.example.com:8080/resource"),
            "api.example.com:8080"
        );
        assert_eq!(extract_domain("https://localhost/test"), "localhost");
        assert_eq!(extract_domain("invalid"), "invalid");
    }

    // Test 12: HTTP 401 returns Unauthorized error
    #[tokio::test]
    async fn test_401_unauthorized() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protected"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 2,
            rate_limit_wait_secs: 60,
        });

        let result = client
            .get(&format!("{}/protected", mock_server.uri()))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SyncError::Unauthorized));
    }

    // Test 13: Available permits reflects concurrent limit
    #[tokio::test]
    async fn test_available_permits() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(200)))
            .mount(&mock_server)
            .await;

        let client = Arc::new(HttpClientWithRateLimit::new(RateLimitConfig {
            min_interval_ms: 0,
            max_concurrent: 3,
            rate_limit_wait_secs: 60,
        }));

        assert_eq!(client.available_permits(), 3);

        // Start a request (will acquire permit)
        let url = format!("{}/slow", mock_server.uri());
        let c = client.clone();
        let handle = tokio::spawn(async move { c.get(&url).await });

        // Give time for permit to be acquired
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(client.available_permits(), 2);

        handle.await.unwrap().unwrap();
        assert_eq!(client.available_permits(), 3);
    }

    // Test 14: Default configuration values
    #[test]
    fn test_default_configuration() {
        let config = RateLimitConfig::default();

        assert_eq!(config.min_interval_ms, 1000);
        assert_eq!(config.max_concurrent, 2);
        assert_eq!(config.rate_limit_wait_secs, 60);
    }
}
