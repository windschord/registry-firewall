//! Security source plugins for vulnerability and malware detection
//!
//! This module contains plugins that provide security data from various sources:
//!
//! - [`traits`]: The `SecuritySourcePlugin` trait that all plugins must implement
//! - [`osv`]: OSV (Open Source Vulnerabilities) database integration
//! - [`openssf`]: OpenSSF Malicious Packages repository integration
//! - [`custom`]: Custom blocklist support (YAML-based)
//! - [`minage`]: Minimum package age filter
//!
//! # Example
//!
//! ```ignore
//! use registry_firewall::plugins::security::SecuritySourcePlugin;
//!
//! async fn check_security(plugins: &[Arc<dyn SecuritySourcePlugin>]) {
//!     for plugin in plugins {
//!         if let Some(reason) = plugin.check_package("pypi", "requests", "2.31.0").await {
//!             println!("Package blocked by {}: {}", plugin.name(), reason.reason);
//!         }
//!     }
//! }
//! ```

pub mod custom;
pub mod minage;
pub mod openssf;
pub mod osv;
pub mod traits;

// Re-export main types
pub use traits::SecuritySourcePlugin;

#[cfg(test)]
pub use traits::MockSecuritySourcePlugin;
