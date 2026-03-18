//! REST API types and handlers
//!
//! This module contains API type definitions and business logic
//! that are independent of the webui feature flag.

pub mod types;
pub mod handlers;
#[cfg(feature = "swagger-gen")]
pub mod openapi;

pub use types::*;
pub use handlers::*;
