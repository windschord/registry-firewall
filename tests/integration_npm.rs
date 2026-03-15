//! npm registry proxy integration tests
//!
//! Tests the npm registry proxy functionality including:
//! - Request routing for simple and scoped packages
//! - Tarball download routing
//! - Security check integration (blocked package returns 403)
//! - Metadata filtering (blocked versions removed from JSON)

mod common;

use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use registry_firewall::error::SyncError;
use registry_firewall::models::{BlockReason, BlockedPackage, Severity, SyncResult, SyncStatus};
use registry_firewall::plugins::registry::npm::{NpmConfig, NpmPlugin};
use registry_firewall::plugins::registry::RegistryPlugin;
use registry_firewall::plugins::security::traits::SecuritySourcePlugin;

use common::{create_test_state_with_plugins, run_test_server};

/// Test security plugin that blocks specific packages
struct TestSecurityPlugin {
    blocked_packages: Vec<BlockedPackage>,
    ecosystems: Vec<String>,
}

impl TestSecurityPlugin {
    fn new(blocked_packages: Vec<BlockedPackage>) -> Self {
        let ecosystems: Vec<String> = blocked_packages
            .iter()
            .map(|p| p.ecosystem.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        Self {
            blocked_packages,
            ecosystems,
        }
    }
}

#[async_trait::async_trait]
impl SecuritySourcePlugin for TestSecurityPlugin {
    fn name(&self) -> &str {
        "test-security"
    }

    fn supported_ecosystems(&self) -> &[String] {
        &self.ecosystems
    }

    async fn sync(&self) -> Result<SyncResult, SyncError> {
        Ok(SyncResult::success(self.blocked_packages.len() as u64))
    }

    fn sync_interval(&self) -> Duration {
        Duration::from_secs(3600)
    }

    fn sync_status(&self) -> SyncStatus {
        SyncStatus::new("test-security").success(self.blocked_packages.len() as u64)
    }

    async fn check_package(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Option<BlockReason> {
        self.blocked_packages
            .iter()
            .find(|p| p.ecosystem == ecosystem && p.package == package && p.version == version)
            .map(|p| {
                BlockReason::new("test-security", p.reason.clone().unwrap_or_default())
                    .with_severity(p.severity.unwrap_or(Severity::High))
            })
    }

    async fn get_blocked_packages(&self, ecosystem: &str) -> Vec<BlockedPackage> {
        self.blocked_packages
            .iter()
            .filter(|p| p.ecosystem == ecosystem)
            .cloned()
            .collect()
    }
}

fn create_npm_plugin(upstream_uri: &str) -> Arc<dyn RegistryPlugin> {
    let config = NpmConfig {
        upstream: upstream_uri.to_string(),
        path_prefix: "/npm".to_string(),
        cache_ttl_secs: 3600,
    };
    Arc::new(NpmPlugin::with_config(config))
}

// =============================================================================
// Route existence tests
// =============================================================================

/// Test 1: npm package metadata route returns 404 without plugin
#[tokio::test]
async fn test_npm_metadata_route_returns_404_without_plugin() {
    let state = common::create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/lodash", addr))
        .send()
        .await
        .expect("Failed to send request");

    // Returns NOT_FOUND when no matching plugin is registered
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test 2: npm scoped package route returns 404 without plugin
#[tokio::test]
async fn test_npm_scoped_package_route_returns_404_without_plugin() {
    let state = common::create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/@types/node", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Test 3: npm tarball download route exists
#[tokio::test]
async fn test_npm_tarball_route_exists() {
    let state = common::create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/lodash/-/lodash-4.17.21.tgz", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// =============================================================================
// Proxy functionality tests
// =============================================================================

/// Test 4: npm metadata request proxies to upstream
#[tokio::test]
async fn test_npm_metadata_proxied_to_upstream() {
    let mock_server = MockServer::start().await;

    let upstream_json = r#"{
        "name": "express",
        "dist-tags": {"latest": "4.18.2"},
        "versions": {
            "4.18.2": {"name": "express", "version": "4.18.2"}
        }
    }"#;

    Mock::given(method("GET"))
        .and(path("/express"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(upstream_json)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/express", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "express");
    assert!(body["versions"]["4.18.2"].is_object());
}

/// Test 5: npm tarball download proxies to upstream
#[tokio::test]
async fn test_npm_tarball_proxied_to_upstream() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/express/-/express-4.18.2.tgz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes("fake-tarball-content")
                .insert_header("content-type", "application/gzip"),
        )
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/express/-/express-4.18.2.tgz", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.bytes().await.expect("Failed to read body");
    assert_eq!(body.as_ref(), b"fake-tarball-content");
}

/// Test 5b: upstream 500 error returns error status to client
#[tokio::test]
async fn test_npm_upstream_server_error_returns_error_status() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/broken-pkg"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/broken-pkg", addr))
        .send()
        .await
        .expect("Failed to send request");

    // Proxy should return a server error status for upstream 500
    assert!(
        response.status().is_server_error(),
        "Expected server error status for upstream 500, got {}",
        response.status()
    );
}

// =============================================================================
// Security filtering tests
// =============================================================================

/// Test 6: blocked npm package tarball returns 403
#[tokio::test]
async fn test_npm_blocked_tarball_returns_403() {
    let mock_server = MockServer::start().await;

    // Upstream mock should never be called for blocked packages
    Mock::given(method("GET"))
        .and(path_regex("/event-stream/-/.*"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());

    let security_plugin: Arc<dyn SecuritySourcePlugin> =
        Arc::new(TestSecurityPlugin::new(vec![BlockedPackage::new(
            "npm",
            "event-stream",
            "3.3.6",
            "test-security",
        )
        .with_reason("Malicious package - cryptocurrency theft")
        .with_severity(Severity::Critical)]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/npm/event-stream/-/event-stream-3.3.6.tgz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response.text().await.expect("Failed to read body");
    assert!(
        body.contains("blocked") || body.contains("Blocked"),
        "Response should indicate package is blocked: {}",
        body
    );
}

/// Test 7: non-blocked version of same package passes through
#[tokio::test]
async fn test_npm_non_blocked_version_passes_through() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/event-stream/-/event-stream-4.0.1.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("safe-tarball-content"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());

    let security_plugin: Arc<dyn SecuritySourcePlugin> =
        Arc::new(TestSecurityPlugin::new(vec![BlockedPackage::new(
            "npm",
            "event-stream",
            "3.3.6",
            "test-security",
        )
        .with_reason("Malicious package")]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/npm/event-stream/-/event-stream-4.0.1.tgz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.bytes().await.expect("Failed to read body");
    assert_eq!(body.as_ref(), b"safe-tarball-content");
}

/// Test 8: metadata filtering removes blocked versions from JSON
#[tokio::test]
async fn test_npm_metadata_filters_blocked_versions() {
    let mock_server = MockServer::start().await;

    let upstream_json = r#"{
        "name": "ua-parser-js",
        "dist-tags": {"latest": "0.7.31"},
        "versions": {
            "0.7.28": {"name": "ua-parser-js", "version": "0.7.28"},
            "0.7.29": {"name": "ua-parser-js", "version": "0.7.29"},
            "0.7.31": {"name": "ua-parser-js", "version": "0.7.31"}
        },
        "time": {
            "0.7.28": "2021-10-20T00:00:00.000Z",
            "0.7.29": "2021-10-22T00:00:00.000Z",
            "0.7.31": "2022-01-10T00:00:00.000Z"
        }
    }"#;

    Mock::given(method("GET"))
        .and(path("/ua-parser-js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(upstream_json)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());

    let security_plugin: Arc<dyn SecuritySourcePlugin> =
        Arc::new(TestSecurityPlugin::new(vec![BlockedPackage::new(
            "npm",
            "ua-parser-js",
            "0.7.29",
            "test-security",
        )
        .with_reason("Supply chain attack - cryptominer injection")]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/ua-parser-js", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");

    // Blocked version should be removed from versions
    assert!(
        body["versions"].get("0.7.29").is_none(),
        "Blocked version 0.7.29 should be removed from versions"
    );

    // Blocked version should be removed from time
    assert!(
        body["time"].get("0.7.29").is_none(),
        "Blocked version 0.7.29 should be removed from time"
    );

    // Non-blocked versions should remain
    assert!(
        body["versions"]["0.7.28"].is_object(),
        "Non-blocked version 0.7.28 should remain"
    );
    assert!(
        body["versions"]["0.7.31"].is_object(),
        "Non-blocked version 0.7.31 should remain"
    );
}

// =============================================================================
// Scoped package tests
// =============================================================================

/// Test 9: scoped package metadata is proxied correctly
#[tokio::test]
async fn test_npm_scoped_package_metadata() {
    let mock_server = MockServer::start().await;

    let upstream_json = r#"{
        "name": "@types/node",
        "dist-tags": {"latest": "18.19.0"},
        "versions": {
            "18.19.0": {"name": "@types/node", "version": "18.19.0"}
        }
    }"#;

    // Use path_regex to accept both unencoded and percent-encoded scoped paths
    Mock::given(method("GET"))
        .and(path_regex(r"^/@types(?:/|%2F)node$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(upstream_json)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/@types/node", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["name"], "@types/node");
}

/// Test 10: scoped package tarball download works
#[tokio::test]
async fn test_npm_scoped_package_tarball() {
    let mock_server = MockServer::start().await;

    // Use path_regex to accept both unencoded and percent-encoded scoped paths
    Mock::given(method("GET"))
        .and(path_regex(r"^/@types(?:/|%2F)node/-/node-18\.19\.0\.tgz$"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("scoped-tarball-content"))
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/npm/@types/node/-/node-18.19.0.tgz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.bytes().await.expect("Failed to read body");
    assert_eq!(body.as_ref(), b"scoped-tarball-content");
}

/// Test 11: blocked scoped package returns 403
#[tokio::test]
async fn test_npm_blocked_scoped_package_returns_403() {
    let mock_server = MockServer::start().await;

    // Upstream should never be called for blocked packages
    Mock::given(method("GET"))
        .and(path_regex(r"^/@malicious(?:/|%2F).*"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());

    let security_plugin: Arc<dyn SecuritySourcePlugin> =
        Arc::new(TestSecurityPlugin::new(vec![BlockedPackage::new(
            "npm",
            "@malicious/package",
            "1.0.0",
            "test-security",
        )
        .with_reason("Malicious scoped package")
        .with_severity(Severity::Critical)]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/npm/@malicious/package/-/package-1.0.0.tgz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// =============================================================================
// dist-tags update tests
// =============================================================================

/// Test 12: dist-tags updated when latest version is blocked
#[tokio::test]
async fn test_npm_dist_tags_updated_when_latest_blocked() {
    let mock_server = MockServer::start().await;

    let upstream_json = r#"{
        "name": "colors",
        "dist-tags": {"latest": "1.4.1"},
        "versions": {
            "1.4.0": {"name": "colors", "version": "1.4.0"},
            "1.4.1": {"name": "colors", "version": "1.4.1"}
        },
        "time": {
            "1.4.0": "2021-01-01T00:00:00.000Z",
            "1.4.1": "2022-01-08T00:00:00.000Z"
        }
    }"#;

    Mock::given(method("GET"))
        .and(path("/colors"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(upstream_json)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let npm_plugin = create_npm_plugin(&mock_server.uri());

    let security_plugin: Arc<dyn SecuritySourcePlugin> =
        Arc::new(TestSecurityPlugin::new(vec![BlockedPackage::new(
            "npm",
            "colors",
            "1.4.1",
            "test-security",
        )
        .with_reason("Sabotaged version - infinite loop")]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/colors", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");

    // Blocked version should be removed
    assert!(body["versions"].get("1.4.1").is_none());

    // dist-tags.latest should be updated to the highest remaining version
    assert_eq!(
        body["dist-tags"]["latest"], "1.4.0",
        "dist-tags.latest should be updated to 1.4.0 after blocking 1.4.1"
    );
}
