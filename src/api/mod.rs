//! REST API types and handlers
//!
//! This module contains API type definitions and business logic
//! that are independent of the webui feature flag.

pub mod handlers;
#[cfg(feature = "swagger-gen")]
pub mod openapi;
pub mod types;

pub use handlers::*;
pub use types::*;
