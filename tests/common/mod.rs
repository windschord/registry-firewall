//! Common test utilities and helpers for integration tests

#![allow(dead_code)]

use std::sync::Arc;

use registry_firewall::auth::{AuthConfig, AuthManager, RateLimitConfig};
use registry_firewall::config::ServerConfig;
use registry_firewall::database::{Database, SqliteDatabase};
use registry_firewall::server::{AppState, Server};

/// Create an in-memory database for testing
pub async fn create_test_database() -> Arc<SqliteDatabase> {
    Arc::new(
        SqliteDatabase::new(":memory:")
            .await
            .expect("Failed to create test database"),
    )
}

/// Create a test authentication manager with disabled auth
pub fn create_test_auth_manager<D: Database>(db: Arc<D>) -> Arc<AuthManager<D>> {
    let config = AuthConfig {
        enabled: false,
        admin_password_hash: None,
        rate_limit: RateLimitConfig::default(),
    };
    Arc::new(AuthManager::new(db, config))
}

/// Create a test authentication manager with enabled auth and admin password
pub fn create_test_auth_manager_with_auth<D: Database>(
    db: Arc<D>,
    admin_password_hash: &str,
) -> Arc<AuthManager<D>> {
    let config = AuthConfig {
        enabled: true,
        admin_password_hash: Some(admin_password_hash.to_string()),
        rate_limit: RateLimitConfig::default(),
    };
    Arc::new(AuthManager::new(db, config))
}

/// Create a test application state
pub async fn create_test_state() -> AppState<SqliteDatabase> {
    let database = create_test_database().await;
    let auth_manager = create_test_auth_manager(Arc::clone(&database));

    AppState {
        auth_manager,
        database,
        registry_plugins: vec![],
        security_plugins: vec![],
        cache_plugin: None,
    }
}

/// Create a test server configuration with a random port
pub fn create_test_server_config() -> ServerConfig {
    ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 0, // Let OS assign a free port
        ..Default::default()
    }
}

/// Create a test server
pub async fn create_test_server() -> (Server<SqliteDatabase>, AppState<SqliteDatabase>) {
    let state = create_test_state().await;
    let config = create_test_server_config();
    let server = Server::new(config, state.clone());
    (server, state)
}

/// Run a test server in the background and return the address
/// The server will be shut down when the returned shutdown sender is dropped or sent
pub async fn run_test_server(
    state: AppState<SqliteDatabase>,
) -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test server");
    let addr = listener.local_addr().expect("Failed to get local address");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let app = registry_firewall::server::build_router(state)
        .layer(tower_http::trace::TraceLayer::new_for_http());

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("Server error");
    });

    // Give the server a moment to start (100ms is sufficient for slow CI systems)
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (addr, shutdown_tx)
}
