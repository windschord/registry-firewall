//! Authentication flow integration tests
//!
//! Tests the authentication system including:
//! - Token creation and validation
//! - Basic authentication
//! - Rate limiting

mod common;

use std::sync::Arc;

use common::*;
use registry_firewall::auth::{hash_token, AuthConfig, AuthManager, RateLimitConfig};
use registry_firewall::models::CreateTokenRequest;
use reqwest::StatusCode;

/// Test 1: Token creation through AuthManager
#[tokio::test]
async fn test_create_token() {
    let database = create_test_database().await;
    let auth_config = AuthConfig {
        enabled: true,
        admin_password_hash: None,
        rate_limit: RateLimitConfig::default(),
    };
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    let request = CreateTokenRequest::new("test-token");
    let response = auth_manager.create_token(request).await;

    assert!(response.is_ok());
    let token_response = response.unwrap();
    assert!(token_response.token.starts_with("rf_"));
    assert_eq!(token_response.name, "test-token");
}

/// Test 2: Token validation succeeds with valid token
#[tokio::test]
async fn test_validate_valid_token() {
    let database = create_test_database().await;
    let auth_config = AuthConfig {
        enabled: true,
        admin_password_hash: None,
        rate_limit: RateLimitConfig::default(),
    };
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    // Create a token
    let request = CreateTokenRequest::new("test-token");
    let token_response = auth_manager.create_token(request).await.unwrap();

    // Validate the token
    let result = auth_manager
        .validate_token(&token_response.token, None)
        .await;
    assert!(result.is_ok());
    let client = result.unwrap();
    assert_eq!(client.name, "test-token");
}

/// Test 3: Token validation fails with invalid token
#[tokio::test]
async fn test_validate_invalid_token() {
    let database = create_test_database().await;
    let auth_config = AuthConfig {
        enabled: true,
        admin_password_hash: None,
        rate_limit: RateLimitConfig::default(),
    };
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    // Use a valid format but non-existent token
    let result = auth_manager
        .validate_token("rf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None)
        .await;
    assert!(result.is_err());
}

/// Test 4: Basic auth with correct credentials
#[tokio::test]
async fn test_basic_auth_valid() {
    let database = create_test_database().await;
    let password_hash = hash_token("admin_password").expect("Failed to hash password");
    let auth_config = AuthConfig {
        enabled: true,
        admin_password_hash: Some(password_hash),
        rate_limit: RateLimitConfig::default(),
    };
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    let result = auth_manager
        .validate_basic_auth("admin", "admin_password", None)
        .await;
    assert!(result.is_ok());
    let client = result.unwrap();
    assert_eq!(client.id, "admin");
}

/// Test 5: Basic auth with wrong credentials
#[tokio::test]
async fn test_basic_auth_invalid() {
    let database = create_test_database().await;
    let password_hash = hash_token("admin_password").expect("Failed to hash password");
    let auth_config = AuthConfig {
        enabled: true,
        admin_password_hash: Some(password_hash),
        rate_limit: RateLimitConfig::default(),
    };
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    let result = auth_manager
        .validate_basic_auth("admin", "wrong_password", None)
        .await;
    assert!(result.is_err());
}

/// Test 6: Token revocation
#[tokio::test]
async fn test_revoke_token() {
    let database = create_test_database().await;
    let auth_config = AuthConfig {
        enabled: true,
        admin_password_hash: None,
        rate_limit: RateLimitConfig::default(),
    };
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    // Create a token
    let request = CreateTokenRequest::new("test-token");
    let token_response = auth_manager.create_token(request).await.unwrap();

    // Revoke the token
    let revoke_result = auth_manager.revoke_token(&token_response.id).await;
    assert!(revoke_result.is_ok());

    // Verify token is no longer valid
    let validate_result = auth_manager
        .validate_token(&token_response.token, None)
        .await;
    assert!(validate_result.is_err());
}

/// Test 7: Tokens API endpoint returns empty list initially
#[tokio::test]
async fn test_tokens_api_empty() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/tokens", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body.get("tokens").is_some());
    assert_eq!(body["tokens"].as_array().unwrap().len(), 0);
}

/// Test 8: Create token through API
#[tokio::test]
async fn test_create_token_api() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/api/tokens", addr))
        .json(&serde_json::json!({
            "name": "api-test-token"
        }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body.get("token").is_some());
    assert!(body["token"].as_str().unwrap().starts_with("rf_"));
}

/// Test 9: Ecosystem access check
#[tokio::test]
async fn test_ecosystem_access() {
    let database = create_test_database().await;
    let auth_config = AuthConfig::default();
    let auth_manager = AuthManager::new(Arc::clone(&database), auth_config);

    // Create a token with specific ecosystems
    let request = CreateTokenRequest::new("pypi-only").with_ecosystems(vec!["pypi".to_string()]);
    let token_response = auth_manager.create_token(request).await.unwrap();

    // Validate and check access
    let client = auth_manager
        .validate_token(&token_response.token, None)
        .await
        .unwrap();

    assert!(auth_manager.check_ecosystem_access(&client, "pypi"));
    assert!(!auth_manager.check_ecosystem_access(&client, "cargo"));
}
