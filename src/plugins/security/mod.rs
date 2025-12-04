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

/// Normalize ecosystem name for consistent comparison across all plugins.
///
/// This function maps various ecosystem name variants to a canonical form:
/// - PyPI, PYPI, pypi -> "pypi"
/// - crates.io, Cargo, cargo -> "crates.io"
/// - Go, go -> "go"
/// - npm, NPM -> "npm"
/// - Docker, docker -> "docker"
///
/// # Example
///
/// ```ignore
/// use registry_firewall::plugins::security::normalize_ecosystem;
///
/// assert_eq!(normalize_ecosystem("PyPI"), "pypi");
/// assert_eq!(normalize_ecosystem("cargo"), "crates.io");
/// ```
pub fn normalize_ecosystem(ecosystem: &str) -> String {
    match ecosystem.to_lowercase().as_str() {
        "pypi" => "pypi".to_string(),
        "crates.io" | "cargo" => "crates.io".to_string(),
        "go" => "go".to_string(),
        "npm" => "npm".to_string(),
        "docker" => "docker".to_string(),
        other => other.to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_ecosystem() {
        assert_eq!(normalize_ecosystem("PyPI"), "pypi");
        assert_eq!(normalize_ecosystem("PYPI"), "pypi");
        assert_eq!(normalize_ecosystem("pypi"), "pypi");
        assert_eq!(normalize_ecosystem("crates.io"), "crates.io");
        assert_eq!(normalize_ecosystem("Cargo"), "crates.io");
        assert_eq!(normalize_ecosystem("cargo"), "crates.io");
        assert_eq!(normalize_ecosystem("Go"), "go");
        assert_eq!(normalize_ecosystem("npm"), "npm");
        assert_eq!(normalize_ecosystem("NPM"), "npm");
        assert_eq!(normalize_ecosystem("docker"), "docker");
        assert_eq!(normalize_ecosystem("Docker"), "docker");
        assert_eq!(normalize_ecosystem("unknown"), "unknown");
    }
}
