//! Integration tests for registry filtering
//!
//! Tests that each package manager's requests are correctly received and filtered.
//! Verifies that blocked packages return 403 and safe packages are proxied correctly.

mod common;

use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use registry_firewall::auth::{AuthConfig, AuthManager};
use registry_firewall::database::SqliteDatabase;
use registry_firewall::error::SyncError;
use registry_firewall::models::{BlockReason, BlockedPackage, Severity, SyncResult, SyncStatus};
use registry_firewall::plugins::registry::cargo::{CargoConfig, CargoPlugin};
use registry_firewall::plugins::registry::docker::{DockerConfig, DockerPlugin};
use registry_firewall::plugins::registry::golang::{GoModuleConfig, GoModulePlugin};
use registry_firewall::plugins::registry::npm::{NpmConfig, NpmPlugin};
use registry_firewall::plugins::registry::pypi::{PyPIConfig, PyPIPlugin};
use registry_firewall::plugins::registry::RegistryPlugin;
use registry_firewall::plugins::security::traits::SecuritySourcePlugin;
use registry_firewall::server::AppState;

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
            .find(|p| {
                p.ecosystem == ecosystem && p.package == package && p.version == version
            })
            .map(|p| {
                BlockReason::new("test-security", p.reason.clone().unwrap_or_default())
                    .with_severity(p.severity.clone().unwrap_or(Severity::High))
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

/// Create test app state with plugins
async fn create_test_state_with_plugins(
    registry_plugins: Vec<Arc<dyn RegistryPlugin>>,
    security_plugins: Vec<Arc<dyn SecuritySourcePlugin>>,
) -> AppState<SqliteDatabase> {
    let db = Arc::new(
        SqliteDatabase::new(":memory:")
            .await
            .expect("Failed to create test database"),
    );

    let auth_config = AuthConfig {
        enabled: false,
        ..Default::default()
    };
    let auth_manager = Arc::new(AuthManager::new(Arc::clone(&db), auth_config));

    AppState {
        auth_manager,
        database: db,
        registry_plugins,
        security_plugins,
        cache_plugin: None,
    }
}

/// Run test server with custom state
async fn run_test_server_with_state(
    state: AppState<SqliteDatabase>,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test server");
    let addr = listener.local_addr().expect("Failed to get local address");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let app = registry_firewall::server::build_router(state);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("Server error");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    (addr, shutdown_tx)
}

// =============================================================================
// PyPI Tests - pip install
// =============================================================================

/// Test: pip requests for blocked package version returns 403
#[tokio::test]
async fn test_pypi_blocked_package_download_returns_403() {
    let mock_server = MockServer::start().await;

    // Set up mock upstream (not needed because we should block before reaching upstream)
    Mock::given(method("GET"))
        .and(path_regex("/packages/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("package content"))
        .mount(&mock_server)
        .await;

    // Create PyPI plugin pointing to mock server
    let pypi_config = PyPIConfig {
        upstream: mock_server.uri(),
        path_prefix: "/pypi".to_string(),
        cache_ttl_secs: 3600,
    };
    let pypi_plugin: Arc<dyn RegistryPlugin> = Arc::new(PyPIPlugin::with_config(pypi_config));

    // Create security plugin that blocks requests-2.31.0
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("pypi", "requests", "2.31.0", "test-security")
            .with_reason("Known malware")
            .with_severity(Severity::Critical),
    ]));

    let state = create_test_state_with_plugins(vec![pypi_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    // Simulate pip download request
    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/pypi/packages/ab/cd/requests-2.31.0.tar.gz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Blocked package should return 403"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Known malware") || body.contains("blocked"));
}

/// Test: pip requests for safe package version is proxied correctly
#[tokio::test]
async fn test_pypi_safe_package_download_succeeds() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/packages/ab/cd/requests-2.32.0.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("safe package content"))
        .mount(&mock_server)
        .await;

    let pypi_config = PyPIConfig {
        upstream: mock_server.uri(),
        path_prefix: "/pypi".to_string(),
        cache_ttl_secs: 3600,
    };
    let pypi_plugin: Arc<dyn RegistryPlugin> = Arc::new(PyPIPlugin::with_config(pypi_config));

    // Block only version 2.31.0, not 2.32.0
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("pypi", "requests", "2.31.0", "test-security")
            .with_reason("Known malware"),
    ]));

    let state = create_test_state_with_plugins(vec![pypi_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/pypi/packages/ab/cd/requests-2.32.0.tar.gz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Safe package should be proxied"
    );
}

/// Test: pip metadata request filters blocked versions from HTML
#[tokio::test]
async fn test_pypi_metadata_filters_blocked_versions() {
    let mock_server = MockServer::start().await;

    // Upstream returns HTML with multiple versions
    let upstream_html = r#"
<!DOCTYPE html>
<html>
<body>
<a href="requests-2.30.0.tar.gz">requests-2.30.0.tar.gz</a>
<a href="requests-2.31.0.tar.gz">requests-2.31.0.tar.gz</a>
<a href="requests-2.32.0.tar.gz">requests-2.32.0.tar.gz</a>
</body>
</html>
"#;

    Mock::given(method("GET"))
        .and(path("/simple/requests/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(upstream_html))
        .mount(&mock_server)
        .await;

    let pypi_config = PyPIConfig {
        upstream: mock_server.uri(),
        path_prefix: "/pypi".to_string(),
        cache_ttl_secs: 3600,
    };
    let pypi_plugin: Arc<dyn RegistryPlugin> = Arc::new(PyPIPlugin::with_config(pypi_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("pypi", "requests", "2.31.0", "test-security")
            .with_reason("Known malware"),
    ]));

    let state = create_test_state_with_plugins(vec![pypi_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/pypi/simple/requests/", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();

    // Version 2.31.0 should be filtered out
    assert!(body.contains("2.30.0"), "Safe version 2.30.0 should remain");
    assert!(
        !body.contains("2.31.0"),
        "Blocked version 2.31.0 should be filtered"
    );
    assert!(body.contains("2.32.0"), "Safe version 2.32.0 should remain");
}

// =============================================================================
// Go Tests - go get
// =============================================================================

/// Test: go get for blocked module version returns 403
#[tokio::test]
async fn test_go_blocked_module_download_returns_403() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/github.com/test/pkg/@v/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("module content"))
        .mount(&mock_server)
        .await;

    let go_config = GoModuleConfig {
        upstream: mock_server.uri(),
        path_prefix: "/go".to_string(),
        cache_ttl_secs: 3600,
    };
    let go_plugin: Arc<dyn RegistryPlugin> = Arc::new(GoModulePlugin::with_config(go_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("go", "github.com/test/pkg", "v1.0.0", "test-security")
            .with_reason("Known vulnerability")
            .with_severity(Severity::High),
    ]));

    let state = create_test_state_with_plugins(vec![go_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/go/github.com/test/pkg/@v/v1.0.0.zip",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Blocked module should return 403"
    );
}

/// Test: go list filters blocked versions from version list
#[tokio::test]
async fn test_go_version_list_filters_blocked_versions() {
    let mock_server = MockServer::start().await;

    // Upstream returns version list
    let upstream_list = "v1.0.0\nv1.1.0\nv1.2.0\n";

    Mock::given(method("GET"))
        .and(path("/github.com/test/pkg/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(upstream_list))
        .mount(&mock_server)
        .await;

    let go_config = GoModuleConfig {
        upstream: mock_server.uri(),
        path_prefix: "/go".to_string(),
        cache_ttl_secs: 3600,
    };
    let go_plugin: Arc<dyn RegistryPlugin> = Arc::new(GoModulePlugin::with_config(go_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("go", "github.com/test/pkg", "v1.1.0", "test-security")
            .with_reason("Known vulnerability"),
    ]));

    let state = create_test_state_with_plugins(vec![go_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/go/github.com/test/pkg/@v/list",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();

    assert!(body.contains("v1.0.0"), "Safe version v1.0.0 should remain");
    assert!(
        !body.contains("v1.1.0"),
        "Blocked version v1.1.0 should be filtered"
    );
    assert!(body.contains("v1.2.0"), "Safe version v1.2.0 should remain");
}

// =============================================================================
// Cargo Tests - cargo install
// =============================================================================

/// Test: cargo install blocked crate version returns 403
#[tokio::test]
async fn test_cargo_blocked_crate_download_returns_403() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/crates/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("crate content"))
        .mount(&mock_server)
        .await;

    let cargo_config = CargoConfig {
        index_upstream: mock_server.uri(),
        download_upstream: mock_server.uri(),
        path_prefix: "/cargo".to_string(),
        cache_ttl_secs: 3600,
    };
    let cargo_plugin: Arc<dyn RegistryPlugin> = Arc::new(CargoPlugin::with_config(cargo_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("cargo", "serde", "1.0.0", "test-security")
            .with_reason("Known vulnerability")
            .with_severity(Severity::High),
    ]));

    let state = create_test_state_with_plugins(vec![cargo_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/cargo/crates/serde/serde-1.0.0.crate",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Blocked crate should return 403"
    );
}

/// Test: cargo index request filters blocked versions from JSON lines
#[tokio::test]
async fn test_cargo_index_filters_blocked_versions() {
    let mock_server = MockServer::start().await;

    // Upstream returns JSON lines index
    let upstream_index = r#"{"name":"serde","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}
{"name":"serde","vers":"1.0.1","deps":[],"cksum":"def","features":{},"yanked":false}
{"name":"serde","vers":"1.0.2","deps":[],"cksum":"ghi","features":{},"yanked":false}
"#;

    Mock::given(method("GET"))
        .and(path("/se/rd/serde"))
        .respond_with(ResponseTemplate::new(200).set_body_string(upstream_index))
        .mount(&mock_server)
        .await;

    let cargo_config = CargoConfig {
        index_upstream: mock_server.uri(),
        download_upstream: mock_server.uri(),
        path_prefix: "/cargo".to_string(),
        cache_ttl_secs: 3600,
    };
    let cargo_plugin: Arc<dyn RegistryPlugin> = Arc::new(CargoPlugin::with_config(cargo_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("cargo", "serde", "1.0.1", "test-security")
            .with_reason("Known vulnerability"),
    ]));

    let state = create_test_state_with_plugins(vec![cargo_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/cargo/se/rd/serde", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();

    assert!(body.contains("1.0.0"), "Safe version 1.0.0 should remain");
    assert!(
        !body.contains("1.0.1"),
        "Blocked version 1.0.1 should be filtered"
    );
    assert!(body.contains("1.0.2"), "Safe version 1.0.2 should remain");
}

// =============================================================================
// npm Tests - npm install
// =============================================================================

/// Test: npm install blocked package version returns 403
#[tokio::test]
async fn test_npm_blocked_package_download_returns_403() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/lodash/-/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("package content"))
        .mount(&mock_server)
        .await;

    let npm_config = NpmConfig {
        upstream: mock_server.uri(),
        path_prefix: "/npm".to_string(),
        cache_ttl_secs: 3600,
    };
    let npm_plugin: Arc<dyn RegistryPlugin> = Arc::new(NpmPlugin::with_config(npm_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("npm", "lodash", "4.17.20", "test-security")
            .with_reason("Prototype pollution vulnerability")
            .with_severity(Severity::Critical),
    ]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/npm/lodash/-/lodash-4.17.20.tgz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Blocked package should return 403"
    );
}

/// Test: npm metadata request filters blocked versions from JSON
#[tokio::test]
async fn test_npm_metadata_filters_blocked_versions() {
    let mock_server = MockServer::start().await;

    // Upstream returns npm package metadata JSON
    let upstream_json = r#"{
        "name": "lodash",
        "dist-tags": {
            "latest": "4.17.21"
        },
        "versions": {
            "4.17.19": {"name": "lodash", "version": "4.17.19"},
            "4.17.20": {"name": "lodash", "version": "4.17.20"},
            "4.17.21": {"name": "lodash", "version": "4.17.21"}
        },
        "time": {
            "4.17.19": "2020-01-01T00:00:00.000Z",
            "4.17.20": "2020-06-01T00:00:00.000Z",
            "4.17.21": "2020-12-01T00:00:00.000Z"
        }
    }"#;

    Mock::given(method("GET"))
        .and(path("/lodash"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(upstream_json)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let npm_config = NpmConfig {
        upstream: mock_server.uri(),
        path_prefix: "/npm".to_string(),
        cache_ttl_secs: 3600,
    };
    let npm_plugin: Arc<dyn RegistryPlugin> = Arc::new(NpmPlugin::with_config(npm_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("npm", "lodash", "4.17.20", "test-security")
            .with_reason("Prototype pollution"),
    ]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/npm/lodash", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // Check versions object
    let versions = json["versions"].as_object().unwrap();
    assert!(versions.contains_key("4.17.19"), "Safe version should remain");
    assert!(
        !versions.contains_key("4.17.20"),
        "Blocked version should be filtered"
    );
    assert!(versions.contains_key("4.17.21"), "Safe version should remain");
}

/// Test: npm scoped package (@scope/package) is correctly parsed
#[tokio::test]
async fn test_npm_scoped_package_download() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/@types/node/-/node-18.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("package content"))
        .mount(&mock_server)
        .await;

    let npm_config = NpmConfig {
        upstream: mock_server.uri(),
        path_prefix: "/npm".to_string(),
        cache_ttl_secs: 3600,
    };
    let npm_plugin: Arc<dyn RegistryPlugin> = Arc::new(NpmPlugin::with_config(npm_config));

    // No blocked packages
    let security_plugin: Arc<dyn SecuritySourcePlugin> =
        Arc::new(TestSecurityPlugin::new(vec![]));

    let state = create_test_state_with_plugins(vec![npm_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/npm/@types/node/-/node-18.0.0.tgz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Scoped package request should be proxied"
    );
}

// =============================================================================
// Docker Tests - docker pull
// =============================================================================

/// Test: docker pull blocked image tag returns 403
#[tokio::test]
async fn test_docker_blocked_image_manifest_returns_403() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/v2/library/alpine/manifests/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("manifest content"))
        .mount(&mock_server)
        .await;

    let docker_config = DockerConfig {
        upstream: mock_server.uri(),
        auth_service: String::new(),
        path_prefix: "/v2".to_string(),
        cache_ttl_secs: 3600,
    };
    let docker_plugin: Arc<dyn RegistryPlugin> = Arc::new(DockerPlugin::with_config(docker_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("docker", "library/alpine", "3.14", "test-security")
            .with_reason("Known CVE")
            .with_severity(Severity::High),
    ]));

    let state = create_test_state_with_plugins(vec![docker_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/v2/library/alpine/manifests/3.14",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Blocked image tag should return 403"
    );
}

/// Test: docker tag list filters blocked tags
#[tokio::test]
async fn test_docker_tag_list_filters_blocked_tags() {
    let mock_server = MockServer::start().await;

    // Upstream returns tag list JSON
    let upstream_tags = r#"{"name":"library/alpine","tags":["3.13","3.14","3.15","latest"]}"#;

    Mock::given(method("GET"))
        .and(path("/v2/library/alpine/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(upstream_tags)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let docker_config = DockerConfig {
        upstream: mock_server.uri(),
        auth_service: String::new(),
        path_prefix: "/v2".to_string(),
        cache_ttl_secs: 3600,
    };
    let docker_plugin: Arc<dyn RegistryPlugin> = Arc::new(DockerPlugin::with_config(docker_config));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("docker", "library/alpine", "3.14", "test-security")
            .with_reason("Known CVE"),
    ]));

    let state = create_test_state_with_plugins(vec![docker_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/v2/library/alpine/tags/list", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    let tags = json["tags"].as_array().unwrap();
    let tag_strings: Vec<&str> = tags.iter().map(|t| t.as_str().unwrap()).collect();

    assert!(tag_strings.contains(&"3.13"), "Safe tag 3.13 should remain");
    assert!(
        !tag_strings.contains(&"3.14"),
        "Blocked tag 3.14 should be filtered"
    );
    assert!(tag_strings.contains(&"3.15"), "Safe tag 3.15 should remain");
}

/// Test: docker pull by digest is allowed (digests can't be filtered)
#[tokio::test]
async fn test_docker_digest_pull_is_allowed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/v2/library/alpine/manifests/sha256:.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("manifest content"))
        .mount(&mock_server)
        .await;

    let docker_config = DockerConfig {
        upstream: mock_server.uri(),
        auth_service: String::new(),
        path_prefix: "/v2".to_string(),
        cache_ttl_secs: 3600,
    };
    let docker_plugin: Arc<dyn RegistryPlugin> = Arc::new(DockerPlugin::with_config(docker_config));

    // Even with blocking, digest pulls should work
    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("docker", "library/alpine", "3.14", "test-security")
            .with_reason("Known CVE"),
    ]));

    let state = create_test_state_with_plugins(vec![docker_plugin], vec![security_plugin]).await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/v2/library/alpine/manifests/sha256:abc123def456",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    // Digest pulls should be allowed (not filtered by version)
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Digest pulls should be allowed"
    );
}

// =============================================================================
// Multiple Registries Test
// =============================================================================

/// Test: Multiple registry plugins can be registered simultaneously
#[tokio::test]
async fn test_multiple_registries_with_filtering() {
    let mock_pypi = MockServer::start().await;
    let mock_npm = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/packages/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("pypi content"))
        .mount(&mock_pypi)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("/lodash/-/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes("npm content"))
        .mount(&mock_npm)
        .await;

    let pypi_plugin: Arc<dyn RegistryPlugin> = Arc::new(PyPIPlugin::with_config(PyPIConfig {
        upstream: mock_pypi.uri(),
        path_prefix: "/pypi".to_string(),
        cache_ttl_secs: 3600,
    }));

    let npm_plugin: Arc<dyn RegistryPlugin> = Arc::new(NpmPlugin::with_config(NpmConfig {
        upstream: mock_npm.uri(),
        path_prefix: "/npm".to_string(),
        cache_ttl_secs: 3600,
    }));

    let security_plugin: Arc<dyn SecuritySourcePlugin> = Arc::new(TestSecurityPlugin::new(vec![
        BlockedPackage::new("pypi", "requests", "2.31.0", "test-security")
            .with_reason("PyPI malware"),
        BlockedPackage::new("npm", "lodash", "4.17.20", "test-security")
            .with_reason("npm vulnerability"),
    ]));

    let state = create_test_state_with_plugins(
        vec![pypi_plugin, npm_plugin],
        vec![security_plugin],
    )
    .await;
    let (addr, _shutdown) = run_test_server_with_state(state).await;

    let client = reqwest::Client::new();

    // PyPI blocked request
    let response = client
        .get(format!(
            "http://{}/pypi/packages/ab/cd/requests-2.31.0.tar.gz",
            addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // npm blocked request
    let response = client
        .get(format!(
            "http://{}/npm/lodash/-/lodash-4.17.20.tgz",
            addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // PyPI safe request
    let response = client
        .get(format!(
            "http://{}/pypi/packages/ab/cd/requests-2.32.0.tar.gz",
            addr
        ))
        .send()
        .await
        .unwrap();
    // May return 404 from mock, but not 403
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}
