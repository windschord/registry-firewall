//! HTTP middleware for registry-firewall
//!
//! This module provides middleware layers for:
//! - Authentication (token and basic auth)
//! - Request/response logging
//! - OpenTelemetry tracing

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::auth::AuthManager;
use crate::database::Database;
use crate::error::AuthError;
use crate::models::Client;

/// Paths that should skip authentication
const AUTH_SKIP_PATHS: &[&str] = &["/health", "/metrics"];

/// Authentication middleware layer
pub struct AuthLayer<D: Database> {
    auth_manager: Arc<AuthManager<D>>,
    skip_paths: Vec<String>,
}

impl<D: Database> AuthLayer<D> {
    /// Create a new authentication layer
    pub fn new(auth_manager: Arc<AuthManager<D>>) -> Self {
        Self {
            auth_manager,
            skip_paths: AUTH_SKIP_PATHS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Add a path that should skip authentication
    pub fn skip_path(mut self, path: impl Into<String>) -> Self {
        self.skip_paths.push(path.into());
        self
    }
}

impl<D: Database> Clone for AuthLayer<D> {
    fn clone(&self) -> Self {
        Self {
            auth_manager: Arc::clone(&self.auth_manager),
            skip_paths: self.skip_paths.clone(),
        }
    }
}

/// Authenticated client extension for requests
#[derive(Clone, Debug)]
pub struct AuthenticatedClient(pub Client);

/// Authentication middleware function
///
/// This middleware:
/// 1. Checks if the path should skip authentication
/// 2. Extracts the Authorization header
/// 3. Validates the token or basic auth credentials
/// 4. Adds the authenticated client to the request extensions
pub async fn auth_middleware<D: Database + 'static>(
    State(auth_manager): State<Arc<AuthManager<D>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthResponse> {
    let path = request.uri().path();

    // Skip authentication for specific paths
    if AUTH_SKIP_PATHS.iter().any(|p| path.starts_with(p)) {
        return Ok(next.run(request).await);
    }

    // Check if auth is enabled
    if !auth_manager.is_enabled() {
        return Ok(next.run(request).await);
    }

    // Get client IP for rate limiting
    let client_ip = Some(addr.ip());

    // Get authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let client = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = header.trim_start_matches("Bearer ");
            auth_manager
                .validate_token(token, client_ip)
                .await
                .map_err(AuthResponse::from_error)?
        }
        Some(header) if header.starts_with("Basic ") => {
            let credentials = header.trim_start_matches("Basic ");
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, credentials)
                    .map_err(|_| AuthResponse::invalid_credentials())?;
            let decoded_str =
                String::from_utf8(decoded).map_err(|_| AuthResponse::invalid_credentials())?;
            let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(AuthResponse::invalid_credentials());
            }
            auth_manager
                .validate_basic_auth(parts[0], parts[1], client_ip)
                .await
                .map_err(AuthResponse::from_error)?
        }
        Some(_) => {
            return Err(AuthResponse::unsupported_scheme());
        }
        None => {
            return Err(AuthResponse::missing_auth());
        }
    };

    // Add authenticated client to request extensions
    request.extensions_mut().insert(AuthenticatedClient(client));

    Ok(next.run(request).await)
}

/// Authentication error response
pub struct AuthResponse {
    status: StatusCode,
    message: String,
}

impl AuthResponse {
    fn from_error(error: AuthError) -> Self {
        match error {
            AuthError::InvalidToken | AuthError::TokenNotFound => Self {
                status: StatusCode::UNAUTHORIZED,
                message: "Invalid token".to_string(),
            },
            AuthError::InvalidCredentials => Self {
                status: StatusCode::UNAUTHORIZED,
                message: "Invalid credentials".to_string(),
            },
            AuthError::RateLimited => Self {
                status: StatusCode::TOO_MANY_REQUESTS,
                message: "Too many failed attempts. Please try again later.".to_string(),
            },
            AuthError::MissingAuth => Self {
                status: StatusCode::UNAUTHORIZED,
                message: "Missing authorization header".to_string(),
            },
        }
    }

    fn missing_auth() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing authorization header".to_string(),
        }
    }

    fn invalid_credentials() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "Invalid credentials".to_string(),
        }
    }

    fn unsupported_scheme() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "Unsupported authentication scheme".to_string(),
        }
    }
}

impl IntoResponse for AuthResponse {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.message
        });
        (
            self.status,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::to_string(&body).unwrap(),
        )
            .into_response()
    }
}

/// Logging middleware layer
#[derive(Clone)]
pub struct LoggingLayer;

impl LoggingLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LoggingLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Logging middleware function
///
/// Logs request and response details including:
/// - Method and path
/// - Status code
/// - Response time
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let response = next.run(request).await;

    let elapsed = start.elapsed();
    let status = response.status();

    tracing::info!(
        method = %method,
        path = %uri.path(),
        status = %status.as_u16(),
        duration_ms = %elapsed.as_millis(),
        "Request completed"
    );

    response
}

/// Tracing middleware layer for OpenTelemetry
#[derive(Clone)]
pub struct TracingLayer;

impl TracingLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TracingLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracing middleware function
///
/// Creates OpenTelemetry spans for requests.
/// Uses the Instrument trait to properly span the entire request lifecycle,
/// including async operations.
pub async fn tracing_middleware(request: Request, next: Next) -> Response {
    use tracing::Instrument;

    let method = request.method().clone();
    let uri = request.uri().clone();

    // Create a span for the request
    let span = tracing::info_span!(
        "http_request",
        http.method = %method,
        http.url = %uri,
        http.status_code = tracing::field::Empty,
    );

    // Use instrument to properly cover the entire request lifecycle
    async move {
        let response = next.run(request).await;

        // Record status code within the span
        tracing::Span::current().record("http.status_code", response.status().as_u16());

        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{hash_token, AuthConfig, AuthManager};
    use crate::database::MockDatabase;
    use crate::models::Token;
    use axum::{middleware, routing::get, Router};

    fn create_test_auth_manager() -> (Arc<AuthManager<MockDatabase>>, String) {
        let (raw_token, _) = crate::auth::generate_token();
        let token_hash = hash_token(&raw_token).unwrap();
        let stored_token = Token::new("id1", "test-token", &token_hash);

        let mut mock_db = MockDatabase::new();
        mock_db
            .expect_list_tokens()
            .returning(move || Ok(vec![stored_token.clone()]));
        mock_db
            .expect_update_token_last_used()
            .returning(|_| Ok(()));

        let db = Arc::new(mock_db);
        let auth_config = AuthConfig {
            enabled: true,
            admin_password_hash: Some(hash_token("admin_password").unwrap()),
            ..Default::default()
        };
        let auth_manager = Arc::new(AuthManager::new(db, auth_config));

        (auth_manager, raw_token)
    }

    async fn test_handler() -> &'static str {
        "OK"
    }

    // Test 1: Auth middleware allows health endpoint without auth
    #[tokio::test]
    async fn test_auth_middleware_skips_health() {
        let (auth_manager, _) = create_test_auth_manager();

        let app = Router::new()
            .route("/health", get(test_handler))
            .layer(middleware::from_fn_with_state(
                auth_manager.clone(),
                auth_middleware::<MockDatabase>,
            ))
            .with_state(auth_manager)
            .into_make_service_with_connect_info::<SocketAddr>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/health", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    // Test 2: Auth middleware rejects request without auth header
    #[tokio::test]
    async fn test_auth_middleware_rejects_no_auth() {
        let (auth_manager, _) = create_test_auth_manager();

        let app = Router::new()
            .route("/api/test", get(test_handler))
            .layer(middleware::from_fn_with_state(
                auth_manager.clone(),
                auth_middleware::<MockDatabase>,
            ))
            .with_state(auth_manager)
            .into_make_service_with_connect_info::<SocketAddr>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/api/test", addr))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
    }

    // Test 3: Auth middleware accepts valid bearer token
    #[tokio::test]
    async fn test_auth_middleware_accepts_valid_token() {
        let (auth_manager, raw_token) = create_test_auth_manager();

        let app = Router::new()
            .route("/api/test", get(test_handler))
            .layer(middleware::from_fn_with_state(
                auth_manager.clone(),
                auth_middleware::<MockDatabase>,
            ))
            .with_state(auth_manager)
            .into_make_service_with_connect_info::<SocketAddr>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/api/test", addr))
            .header("Authorization", format!("Bearer {}", raw_token))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    // Test 4: Auth middleware accepts valid basic auth
    #[tokio::test]
    async fn test_auth_middleware_accepts_basic_auth() {
        let (auth_manager, _) = create_test_auth_manager();

        let app = Router::new()
            .route("/api/test", get(test_handler))
            .layer(middleware::from_fn_with_state(
                auth_manager.clone(),
                auth_middleware::<MockDatabase>,
            ))
            .with_state(auth_manager)
            .into_make_service_with_connect_info::<SocketAddr>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let credentials = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "admin:admin_password",
        );
        let response = client
            .get(format!("http://{}/api/test", addr))
            .header("Authorization", format!("Basic {}", credentials))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    // Test 5: Auth middleware rejects invalid token
    #[tokio::test]
    async fn test_auth_middleware_rejects_invalid_token() {
        let (auth_manager, _) = create_test_auth_manager();

        let app = Router::new()
            .route("/api/test", get(test_handler))
            .layer(middleware::from_fn_with_state(
                auth_manager.clone(),
                auth_middleware::<MockDatabase>,
            ))
            .with_state(auth_manager)
            .into_make_service_with_connect_info::<SocketAddr>();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/api/test", addr))
            .header("Authorization", "Bearer rf_invalid_token_here_xxxxx")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 401);
    }

    // Test 6: AuthResponse from_error creates correct responses
    #[test]
    fn test_auth_response_from_error() {
        let resp = AuthResponse::from_error(AuthError::InvalidToken);
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        assert!(resp.message.contains("Invalid token"));

        let resp = AuthResponse::from_error(AuthError::RateLimited);
        assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.message.contains("Too many"));
    }

    // Test 7: LoggingLayer can be created
    #[test]
    fn test_logging_layer_new() {
        let _layer = LoggingLayer::new();
        let _layer2 = LoggingLayer::default();
        // Just verify they can be created
    }

    // Test 8: TracingLayer can be created
    #[test]
    fn test_tracing_layer_new() {
        let _layer = TracingLayer::new();
        let _layer2 = TracingLayer::default();
        // Just verify they can be created
    }

    // Test 9: Auth skip paths work correctly
    #[test]
    fn test_auth_skip_paths() {
        assert!(AUTH_SKIP_PATHS.contains(&"/health"));
        assert!(AUTH_SKIP_PATHS.contains(&"/metrics"));
    }

    // Test 10: AuthLayer skip_path method
    #[test]
    fn test_auth_layer_skip_path() {
        let mock_db = MockDatabase::new();
        let db = Arc::new(mock_db);
        let auth_config = AuthConfig::default();
        let auth_manager = Arc::new(AuthManager::new(db, auth_config));

        let layer = AuthLayer::new(auth_manager).skip_path("/custom/path");
        assert!(layer.skip_paths.contains(&"/custom/path".to_string()));
    }
}
