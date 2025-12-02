//! registry-firewall - A unified registry proxy for software supply chain security
//!
//! This crate provides a proxy server that filters malicious packages and versions
//! from package registries like PyPI, Go modules, Cargo, and Docker.

pub mod auth;
pub mod config;
pub mod database;
pub mod error;
pub mod models;
pub mod otel;
pub mod plugins;
pub mod server;
pub mod sync;
pub mod webui;
