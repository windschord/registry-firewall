//! registry-firewall - A unified registry proxy for software supply chain security
//!
//! This is the main entry point for the registry-firewall application.

use std::sync::Arc;

use clap::Parser;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info};

use registry_firewall::auth::{AuthConfig, AuthManager, RateLimitConfig};
use registry_firewall::config::Config;
use registry_firewall::database::SqliteDatabase;
use registry_firewall::otel::{init_tracing, OtelProvider};
use registry_firewall::server::{AppState, Server};

/// registry-firewall - A unified registry proxy for software supply chain security
#[derive(Parser, Debug)]
#[command(name = "registry-firewall")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, env = "REGISTRY_FIREWALL_CONFIG")]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Load configuration
    let config = load_config(&args)?;

    // Initialize OpenTelemetry provider
    let otel_provider = OtelProvider::new(&config.otel)?;

    // Initialize tracing/logging
    init_tracing(&otel_provider, &config.logging.level)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting registry-firewall"
    );

    // Initialize database
    let database = SqliteDatabase::new(&config.database.path).await?;
    let database = Arc::new(database);
    info!(path = %config.database.path, "Database initialized");

    // Initialize authentication manager
    let auth_config = AuthConfig {
        enabled: config.auth.enabled,
        admin_password_hash: config.auth.admin_password.clone(),
        rate_limit: RateLimitConfig {
            max_failures: config.auth.rate_limit.max_failures,
            block_duration: std::time::Duration::from_secs(
                config.auth.rate_limit.block_duration_secs,
            ),
            window_duration: std::time::Duration::from_secs(
                config.auth.rate_limit.block_duration_secs * 2,
            ),
        },
    };
    let auth_manager = Arc::new(AuthManager::new(Arc::clone(&database), auth_config));
    info!(
        auth_enabled = config.auth.enabled,
        "Authentication manager initialized"
    );

    // Create shutdown broadcast channel
    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

    // Create application state
    let state = AppState {
        auth_manager,
        database,
        registry_plugins: vec![],
        security_plugins: vec![],
        cache_plugin: None,
    };

    // Create and start the HTTP server
    let server = Server::new(config.server.clone(), state);
    let shutdown_signal = shutdown_signal();

    info!(
        host = %config.server.host,
        port = %config.server.port,
        "Starting HTTP server"
    );

    // Run the server
    let result = server.run(shutdown_signal).await;

    // Signal shutdown to all background tasks
    let _ = shutdown_tx.send(());

    // Shutdown OpenTelemetry
    if let Err(e) = otel_provider.shutdown() {
        error!(error = %e, "Failed to shutdown OpenTelemetry");
    }

    info!("registry-firewall shutdown complete");

    result.map_err(Into::into)
}

/// Load configuration from file or environment
fn load_config(args: &Args) -> anyhow::Result<Config> {
    match &args.config {
        Some(path) => {
            info!(path = %path, "Loading configuration from file");
            Config::from_file(path).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))
        }
        None => {
            info!("Loading configuration from environment variables");
            Config::from_env().map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))
        }
    }
}

/// Create a future that resolves when a shutdown signal is received
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
