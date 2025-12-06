//! HTTP server components for registry-firewall
//!
//! This module provides the HTTP server infrastructure including:
//! - Router configuration and route handlers
//! - Authentication and logging middleware
//! - Server lifecycle management

pub mod middleware;
pub mod router;

pub use middleware::{AuthLayer, LoggingLayer, TracingLayer};
pub use router::{build_router, AppState, HealthResponse, MetricsResponse};

use std::future::Future;
use std::net::SocketAddr;

use tokio::net::TcpListener;

use crate::config::ServerConfig;
use crate::database::Database;

/// HTTP Server for registry-firewall
///
/// Manages the axum server lifecycle, including:
/// - Binding to configured address
/// - Applying middleware layers
/// - Graceful shutdown handling
pub struct Server<D: Database + 'static> {
    config: ServerConfig,
    state: AppState<D>,
}

impl<D: Database + 'static> Server<D> {
    /// Create a new server instance
    pub fn new(config: ServerConfig, state: AppState<D>) -> Self {
        Self { config, state }
    }

    /// Get the configured bind address
    pub fn bind_addr(&self) -> SocketAddr {
        SocketAddr::new(
            self.config.host.parse().unwrap_or([0, 0, 0, 0].into()),
            self.config.port,
        )
    }

    /// Run the server until shutdown signal is received
    ///
    /// # Arguments
    ///
    /// * `shutdown` - Future that resolves when the server should shut down
    ///
    /// # Returns
    ///
    /// Ok(()) if server shuts down gracefully, Err if there was an error
    pub async fn run(
        self,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ServerError> {
        let addr = self.bind_addr();
        let app = build_router(self.state);

        // Apply middleware layers
        let app = app
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .layer(tower_http::compression::CompressionLayer::new());

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        tracing::info!("Server listening on {}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(|e| ServerError::Serve(e.to_string()))?;

        tracing::info!("Server shutdown complete");
        Ok(())
    }
}

/// Server error types
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Failed to bind to address
    #[error("Failed to bind to address: {0}")]
    Bind(String),

    /// Failed to serve requests
    #[error("Server error: {0}")]
    Serve(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthConfig, AuthManager};
    use crate::database::MockDatabase;
    use std::sync::Arc;
    use std::time::Duration;

    fn create_test_state() -> AppState<MockDatabase> {
        let mut mock_db = MockDatabase::new();
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

    // Test 1: Server can be created with config
    #[test]
    fn test_server_new() {
        let config = ServerConfig::default();
        let state = create_test_state();
        let server = Server::new(config, state);
        assert_eq!(server.bind_addr().port(), 8080);
    }

    // Test 2: Server bind address calculation
    #[test]
    fn test_server_bind_addr() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 9090,
            ..Default::default()
        };
        let state = create_test_state();
        let server = Server::new(config, state);
        assert_eq!(server.bind_addr().to_string(), "127.0.0.1:9090");
    }

    // Test 3: Server graceful shutdown
    #[tokio::test]
    async fn test_server_graceful_shutdown() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0, // Let OS assign a port
            ..Default::default()
        };
        let state = create_test_state();
        let server = Server::new(config, state);

        // Create a shutdown signal that triggers immediately
        let shutdown = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        // Start server in background
        let handle = tokio::spawn(async move { server.run(shutdown).await });

        // Wait for the server to complete
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    // Test 4: ServerError display messages
    #[test]
    fn test_server_error_display() {
        let bind_err = ServerError::Bind("address in use".to_string());
        assert_eq!(
            bind_err.to_string(),
            "Failed to bind to address: address in use"
        );

        let serve_err = ServerError::Serve("connection reset".to_string());
        assert_eq!(serve_err.to_string(), "Server error: connection reset");

        let config_err = ServerError::Config("missing field".to_string());
        assert_eq!(config_err.to_string(), "Configuration error: missing field");
    }
}
