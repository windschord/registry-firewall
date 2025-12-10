//! registry-firewall - A unified registry proxy for software supply chain security
//!
//! This is the main entry point for the registry-firewall application.

use std::sync::Arc;

use clap::Parser;
use tokio::signal;
use tracing::{error, info};

use registry_firewall::auth::{AuthConfig, AuthManager, RateLimitConfig};
use registry_firewall::config::Config;
use registry_firewall::database::SqliteDatabase;
use registry_firewall::otel::{init_tracing, OtelProvider};
use registry_firewall::plugins::registry::npm::{NpmConfig, NpmPlugin};
use registry_firewall::plugins::registry::pypi::{PyPIConfig, PyPIPlugin};
use registry_firewall::plugins::registry::RegistryPlugin;
use registry_firewall::plugins::security::custom::{CustomBlocklistConfig, CustomBlocklistPlugin};
use registry_firewall::plugins::security::SecuritySourcePlugin;
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
                config.auth.rate_limit.window_duration_secs,
            ),
        },
    };
    let auth_manager = Arc::new(AuthManager::new(Arc::clone(&database), auth_config));
    info!(
        auth_enabled = config.auth.enabled,
        "Authentication manager initialized"
    );

    // Initialize registry plugins
    let mut registry_plugins: Vec<Arc<dyn RegistryPlugin>> = vec![];

    if let Some(pypi_cfg) = config.registry_plugins.get("pypi") {
        if pypi_cfg.enabled {
            let pypi_config = PyPIConfig {
                upstream: pypi_cfg.upstream.clone(),
                path_prefix: pypi_cfg.path_prefix.clone(),
                cache_ttl_secs: pypi_cfg.cache_ttl_secs,
            };
            registry_plugins.push(Arc::new(PyPIPlugin::with_config(pypi_config)));
            info!(
                upstream = %pypi_cfg.upstream,
                path_prefix = %pypi_cfg.path_prefix,
                "PyPI registry plugin enabled"
            );
        }
    }

    if let Some(npm_cfg) = config.registry_plugins.get("npm") {
        if npm_cfg.enabled {
            let npm_config = NpmConfig {
                upstream: npm_cfg.upstream.clone(),
                path_prefix: npm_cfg.path_prefix.clone(),
                cache_ttl_secs: npm_cfg.cache_ttl_secs,
            };
            registry_plugins.push(Arc::new(NpmPlugin::with_config(npm_config)));
            info!(
                upstream = %npm_cfg.upstream,
                path_prefix = %npm_cfg.path_prefix,
                "npm registry plugin enabled"
            );
        }
    }

    // Initialize security plugins
    let mut security_plugins: Vec<Arc<dyn SecuritySourcePlugin>> = vec![];

    if let Some(custom_cfg) = config.security_plugins.get("custom") {
        if custom_cfg.enabled {
            // Get blocklist_path from options
            if let Some(blocklist_path) = custom_cfg.options.get("blocklist_path") {
                let custom_config = CustomBlocklistConfig {
                    file_path: std::path::PathBuf::from(blocklist_path),
                    ..Default::default()
                };
                let plugin = CustomBlocklistPlugin::new(custom_config);
                // Load the blocklist rules
                match plugin.sync().await {
                    Ok(result) => {
                        info!(
                            blocklist_path = %blocklist_path,
                            rules = result.records_updated,
                            "Custom blocklist plugin enabled"
                        );
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to load custom blocklist");
                    }
                }
                security_plugins.push(Arc::new(plugin));
            }
        }
    }

    // Create application state
    let state = AppState {
        auth_manager,
        database,
        registry_plugins,
        security_plugins,
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
            // Use eprintln! since tracing is not yet initialized
            eprintln!("Loading configuration from file: {}", path);
            Config::from_file(path).map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))
        }
        None => {
            // Use eprintln! since tracing is not yet initialized
            eprintln!("Loading configuration from environment variables");
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
