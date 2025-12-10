//! Registry plugins for different package ecosystems
//!
//! This module contains plugins for proxying requests to package registries:
//! - PyPI (Python Package Index)
//! - Go Module Proxy
//! - Cargo (Rust crates)
//! - npm (Node Package Manager)
//! - Docker Registry

pub mod traits;

// Registry plugin implementations
pub mod cargo;
pub mod docker;
pub mod golang;
pub mod npm;
pub mod pypi;

pub use traits::{RegistryPlugin, RegistryResponse, RequestContext};
