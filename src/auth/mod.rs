//! Authentication system for registry-firewall
//!
//! This module provides authentication and authorization functionality:
//! - Token generation and verification
//! - Basic authentication
//! - Rate limiting for failed attempts
//! - Ecosystem-based access control

pub mod manager;
pub mod ratelimit;
pub mod token;

pub use manager::{AuthConfig, AuthManager};
pub use ratelimit::{RateLimitConfig, RateLimiter};
pub use token::{
    generate_token, hash_token, is_valid_token_format, verify_token, HashError, TOKEN_PREFIX,
};
