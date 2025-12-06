//! HTTP router for registry-firewall
//!
//! This module defines the axum router that handles all HTTP requests.
//! It provides routes for:
//! - Health checks and metrics
//! - Registry proxies (PyPI, Go, Cargo, Docker)
//! - Web UI and API endpoints

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{any, delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::AuthManager;
use crate::database::Database;
use crate::plugins::cache::traits::CachePlugin;
use crate::plugins::registry::RegistryPlugin;
use crate::plugins::security::traits::SecuritySourcePlugin;

/// Shared application state
pub struct AppState<D: Database> {
    /// Authentication manager
    pub auth_manager: Arc<AuthManager<D>>,

    /// Database
    pub database: Arc<D>,

    /// Registry plugins by name
    pub registry_plugins: Vec<Arc<dyn RegistryPlugin>>,

    /// Security plugins
    pub security_plugins: Vec<Arc<dyn SecuritySourcePlugin>>,

    /// Cache plugin
    pub cache_plugin: Option<Arc<dyn CachePlugin>>,
}

impl<D: Database> Clone for AppState<D> {
    fn clone(&self) -> Self {
        Self {
            auth_manager: Arc::clone(&self.auth_manager),
            database: Arc::clone(&self.database),
            registry_plugins: self.registry_plugins.clone(),
            security_plugins: self.security_plugins.clone(),
            cache_plugin: self.cache_plugin.clone(),
        }
    }
}

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Metrics response (Prometheus format placeholder)
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub requests_total: u64,
    pub blocked_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

/// Build the main application router
///
/// # Arguments
///
/// * `state` - Application state containing plugins and managers
///
/// # Returns
///
/// An axum Router configured with all endpoints
pub fn build_router<D: Database + 'static>(state: AppState<D>) -> Router {
    Router::new()
        // Health and metrics endpoints (no auth required)
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        // Registry proxy routes
        .route("/pypi/*path", any(registry_proxy_handler::<D>))
        .route("/go/*path", any(registry_proxy_handler::<D>))
        .route("/cargo/*path", any(registry_proxy_handler::<D>))
        .route("/v2/*path", any(registry_proxy_handler::<D>))
        // API routes
        .route("/api/dashboard", get(api_dashboard_handler::<D>))
        .route("/api/blocks", get(api_blocks_handler::<D>))
        .route(
            "/api/security-sources",
            get(api_security_sources_handler::<D>),
        )
        .route(
            "/api/security-sources/:name/sync",
            post(api_trigger_sync_handler::<D>),
        )
        .route("/api/cache/stats", get(api_cache_stats_handler::<D>))
        .route("/api/cache", delete(api_cache_clear_handler::<D>))
        .route("/api/rules", get(api_list_rules_handler::<D>))
        .route("/api/rules", post(api_create_rule_handler::<D>))
        .route("/api/rules/:id", get(api_get_rule_handler::<D>))
        .route("/api/rules/:id", put(api_update_rule_handler::<D>))
        .route("/api/rules/:id", delete(api_delete_rule_handler::<D>))
        .route("/api/tokens", get(api_list_tokens_handler::<D>))
        .route("/api/tokens", post(api_create_token_handler::<D>))
        .route("/api/tokens/:id", delete(api_delete_token_handler::<D>))
        // Web UI routes
        .route("/ui", get(webui_index_handler))
        .route("/ui/*path", get(webui_static_handler))
        .with_state(state)
}

// =============================================================================
// Health and Metrics Handlers
// =============================================================================

/// Health check endpoint handler
async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Metrics endpoint handler (Prometheus format placeholder)
async fn metrics_handler() -> impl IntoResponse {
    // TODO: Implement proper Prometheus metrics
    let metrics = MetricsResponse {
        requests_total: 0,
        blocked_total: 0,
        cache_hits: 0,
        cache_misses: 0,
    };
    Json(metrics)
}

// =============================================================================
// Registry Proxy Handlers
// =============================================================================

/// Generic registry proxy handler
async fn registry_proxy_handler<D: Database + 'static>(
    State(_state): State<AppState<D>>,
    Path(_path): Path<String>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    // Get the full path from the request
    let full_path = req.uri().path();

    // Find the matching registry plugin
    // The proxy handler implementation will be completed in a future phase
    // For now, return a placeholder response
    tracing::debug!(path = %full_path, "Registry proxy request received");
    (
        StatusCode::NOT_IMPLEMENTED,
        "Registry proxy not yet implemented".to_string(),
    )
}

// =============================================================================
// API Handlers
// =============================================================================

/// Dashboard API handler
async fn api_dashboard_handler<D: Database + 'static>(
    State(_state): State<AppState<D>>,
) -> impl IntoResponse {
    // TODO: Implement proper dashboard stats
    Json(serde_json::json!({
        "total_requests": 0,
        "blocked_requests": 0,
        "cache_hit_rate": 0.0,
        "security_sources": []
    }))
}

/// Block logs API handler
async fn api_blocks_handler<D: Database + 'static>(
    State(_state): State<AppState<D>>,
) -> impl IntoResponse {
    // TODO: Implement proper block logs retrieval
    Json(serde_json::json!({
        "logs": [],
        "total": 0
    }))
}

/// Security sources status API handler
async fn api_security_sources_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
) -> impl IntoResponse {
    let sources: Vec<serde_json::Value> = state
        .security_plugins
        .iter()
        .map(|p| {
            let status = p.sync_status();
            serde_json::json!({
                "name": p.name(),
                "ecosystems": p.supported_ecosystems(),
                "last_sync": status.last_sync_at,
                "status": format!("{:?}", status.status),
                "records_count": status.records_count
            })
        })
        .collect();

    Json(serde_json::json!({ "sources": sources }))
}

/// Trigger sync for a security source
async fn api_trigger_sync_handler<D: Database + 'static>(
    State(_state): State<AppState<D>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    // TODO: Implement manual sync trigger
    Json(serde_json::json!({
        "message": format!("Sync triggered for {}", name)
    }))
}

/// Cache stats API handler
async fn api_cache_stats_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
) -> impl IntoResponse {
    if let Some(cache) = &state.cache_plugin {
        let stats = cache.stats().await;
        Json(serde_json::json!({
            "plugin": cache.name(),
            "hits": stats.hits,
            "misses": stats.misses,
            "total_size_bytes": stats.total_size_bytes,
            "entries": stats.entries
        }))
    } else {
        Json(serde_json::json!({
            "plugin": "none",
            "hits": 0,
            "misses": 0,
            "total_size_bytes": 0,
            "entries": 0
        }))
    }
}

/// Cache clear API handler
async fn api_cache_clear_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
) -> impl IntoResponse {
    if let Some(cache) = &state.cache_plugin {
        match cache.purge().await {
            Ok(_) => (
                StatusCode::OK,
                Json(serde_json::json!({ "message": "Cache cleared" })),
            ),
            Err(e) => {
                tracing::error!(error = %e, "Failed to clear cache");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "Failed to clear cache" })),
                )
            }
        }
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "message": "No cache configured" })),
        )
    }
}

/// List custom rules handler
async fn api_list_rules_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
) -> impl IntoResponse {
    match state.database.list_rules().await {
        Ok(rules) => (StatusCode::OK, Json(serde_json::json!({ "rules": rules }))),
        Err(e) => {
            tracing::error!(error = %e, "Failed to list rules");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to list rules" })),
            )
        }
    }
}

/// Create custom rule handler
async fn api_create_rule_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
    Json(rule): Json<crate::models::CustomRule>,
) -> impl IntoResponse {
    match state.database.insert_rule(&rule).await {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "id": id, "message": "Rule created" })),
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to create rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to create rule" })),
            )
        }
    }
}

/// Get custom rule by ID handler
async fn api_get_rule_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.database.get_rule(id).await {
        Ok(Some(rule)) => (StatusCode::OK, Json(serde_json::json!({ "rule": rule }))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Rule not found" })),
        ),
        Err(e) => {
            tracing::error!(error = %e, rule_id = id, "Failed to get rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to get rule" })),
            )
        }
    }
}

/// Update custom rule handler
async fn api_update_rule_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
    Path(id): Path<i64>,
    Json(mut rule): Json<crate::models::CustomRule>,
) -> impl IntoResponse {
    rule.id = Some(id);
    match state.database.update_rule(&rule).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "message": "Rule updated" })),
        ),
        Err(e) => {
            tracing::error!(error = %e, rule_id = id, "Failed to update rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to update rule" })),
            )
        }
    }
}

/// Delete custom rule handler
async fn api_delete_rule_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.database.delete_rule(id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "message": "Rule deleted" })),
        ),
        Err(e) => {
            tracing::error!(error = %e, rule_id = id, "Failed to delete rule");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to delete rule" })),
            )
        }
    }
}

/// List tokens handler
async fn api_list_tokens_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
) -> impl IntoResponse {
    match state.auth_manager.list_tokens().await {
        Ok(tokens) => {
            // Don't expose token hashes
            let safe_tokens: Vec<serde_json::Value> = tokens
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "id": t.id,
                        "name": t.name,
                        "created_at": t.created_at,
                        "expires_at": t.expires_at,
                        "last_used_at": t.last_used_at,
                        "allowed_ecosystems": t.allowed_ecosystems
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "tokens": safe_tokens })),
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list tokens");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to list tokens" })),
            )
        }
    }
}

/// Create token request
#[derive(Debug, Deserialize)]
pub struct CreateTokenApiRequest {
    pub name: String,
    pub allowed_ecosystems: Option<Vec<String>>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Create token handler
async fn api_create_token_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
    Json(req): Json<CreateTokenApiRequest>,
) -> impl IntoResponse {
    let create_req = crate::models::CreateTokenRequest::new(&req.name)
        .with_ecosystems(req.allowed_ecosystems.unwrap_or_default());

    let create_req = if let Some(expires_at) = req.expires_at {
        create_req.with_expires_at(expires_at)
    } else {
        create_req
    };

    match state.auth_manager.create_token(create_req).await {
        Ok(response) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "id": response.id,
                "name": response.name,
                "token": response.token,
                "created_at": response.created_at,
                "expires_at": response.expires_at
            })),
        ),
        Err(e) => {
            tracing::error!(error = %e, "Failed to create token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to create token" })),
            )
        }
    }
}

/// Delete token handler
async fn api_delete_token_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.auth_manager.revoke_token(&id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "message": "Token revoked" })),
        ),
        Err(e) => {
            tracing::error!(error = %e, token_id = %id, "Failed to revoke token");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Failed to revoke token" })),
            )
        }
    }
}

// =============================================================================
// Web UI Handlers
// =============================================================================

/// Web UI index handler
async fn webui_index_handler() -> impl IntoResponse {
    // TODO: Serve embedded index.html
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        "<html><body><h1>Registry Firewall Web UI</h1><p>Coming soon...</p></body></html>",
    )
}

/// Web UI static file handler
async fn webui_static_handler(Path(path): Path<String>) -> impl IntoResponse {
    // TODO: Serve embedded static files
    (
        StatusCode::NOT_FOUND,
        format!("Static file not found: {}", path),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, AuthManager};
    use crate::database::MockDatabase;
    use axum_test::TestServer;

    fn create_test_state() -> AppState<MockDatabase> {
        let mut mock_db = MockDatabase::new();
        // Set up default expectations
        mock_db.expect_list_tokens().returning(|| Ok(vec![]));
        mock_db.expect_list_rules().returning(|| Ok(vec![]));

        let db = Arc::new(mock_db);
        let auth_config = AuthConfig::default();
        let auth_manager = Arc::new(AuthManager::new(Arc::clone(&db), auth_config));

        AppState {
            auth_manager,
            database: db,
            registry_plugins: vec![],
            security_plugins: vec![],
            cache_plugin: None,
        }
    }

    // Test 1: Health endpoint returns OK
    #[tokio::test]
    async fn test_health_endpoint_returns_ok() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        response.assert_status_ok();

        let body: HealthResponse = response.json();
        assert_eq!(body.status, "healthy");
        assert!(!body.version.is_empty());
    }

    // Test 2: Metrics endpoint returns OK
    #[tokio::test]
    async fn test_metrics_endpoint_returns_ok() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/metrics").await;
        response.assert_status_ok();

        let body: MetricsResponse = response.json();
        assert_eq!(body.requests_total, 0);
    }

    // Test 3: PyPI proxy route is routed
    #[tokio::test]
    async fn test_pypi_route_exists() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/pypi/simple/requests/").await;
        // Should not be 404 (route exists but returns NOT_IMPLEMENTED for now)
        response.assert_status(StatusCode::NOT_IMPLEMENTED);
    }

    // Test 4: Go proxy route is routed
    #[tokio::test]
    async fn test_go_route_exists() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/go/github.com/test/pkg/@v/list").await;
        response.assert_status(StatusCode::NOT_IMPLEMENTED);
    }

    // Test 5: Cargo proxy route is routed
    #[tokio::test]
    async fn test_cargo_route_exists() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/cargo/se/rd/serde").await;
        response.assert_status(StatusCode::NOT_IMPLEMENTED);
    }

    // Test 6: Docker v2 proxy route is routed
    #[tokio::test]
    async fn test_docker_route_exists() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/v2/library/alpine/manifests/latest").await;
        response.assert_status(StatusCode::NOT_IMPLEMENTED);
    }

    // Test 7: API dashboard endpoint
    #[tokio::test]
    async fn test_api_dashboard_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/dashboard").await;
        response.assert_status_ok();
    }

    // Test 8: API blocks endpoint
    #[tokio::test]
    async fn test_api_blocks_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/blocks").await;
        response.assert_status_ok();
    }

    // Test 9: API security-sources endpoint
    #[tokio::test]
    async fn test_api_security_sources_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/security-sources").await;
        response.assert_status_ok();
    }

    // Test 10: API cache stats endpoint
    #[tokio::test]
    async fn test_api_cache_stats_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/cache/stats").await;
        response.assert_status_ok();
    }

    // Test 11: API rules list endpoint
    #[tokio::test]
    async fn test_api_rules_list_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/rules").await;
        response.assert_status_ok();
    }

    // Test 12: API tokens list endpoint
    #[tokio::test]
    async fn test_api_tokens_list_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/tokens").await;
        response.assert_status_ok();
    }

    // Test 13: Web UI index endpoint
    #[tokio::test]
    async fn test_webui_index_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/ui").await;
        response.assert_status_ok();
    }

    // Test 14: Web UI static files endpoint
    #[tokio::test]
    async fn test_webui_static_endpoint() {
        let state = create_test_state();
        let app = build_router(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/ui/app.js").await;
        // Returns 404 for non-existent static files
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
