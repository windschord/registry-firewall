//! PyPI proxy integration tests
//!
//! Tests the PyPI registry proxy functionality including:
//! - Request routing
//! - Security check integration
//! - Response handling

mod common;

use common::*;
use reqwest::StatusCode;

/// Test 1: Health check endpoint returns healthy status
#[tokio::test]
async fn test_health_endpoint() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/health", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "healthy");
}

/// Test 2: Metrics endpoint returns metrics
#[tokio::test]
async fn test_metrics_endpoint() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/metrics", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body.get("requests_total").is_some());
}

/// Test 3: PyPI simple API route exists (returns NOT_IMPLEMENTED for now)
#[tokio::test]
async fn test_pypi_simple_route() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/pypi/simple/requests/", addr))
        .send()
        .await
        .expect("Failed to send request");

    // Currently returns NOT_IMPLEMENTED as proxy is not fully implemented
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

/// Test 4: PyPI packages route exists
#[tokio::test]
async fn test_pypi_packages_route() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!(
            "http://{}/pypi/packages/requests/2.31.0/requests-2.31.0.tar.gz",
            addr
        ))
        .send()
        .await
        .expect("Failed to send request");

    // Currently returns NOT_IMPLEMENTED as proxy is not fully implemented
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

/// Test 5: Dashboard API returns stats
#[tokio::test]
async fn test_dashboard_api() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/dashboard", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test 6: Blocks API returns empty list initially
#[tokio::test]
async fn test_blocks_api() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/blocks", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body.get("logs").is_some());
    assert_eq!(body["total"], 0);
}

/// Test 7: Security sources API returns list
#[tokio::test]
async fn test_security_sources_api() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/security-sources", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body.get("sources").is_some());
}

/// Test 8: Unknown route returns 404
#[tokio::test]
async fn test_unknown_route() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/unknown/route", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
