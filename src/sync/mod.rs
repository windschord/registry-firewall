//! Data synchronization infrastructure
//!
//! This module provides infrastructure for synchronizing security data from
//! external sources with automatic retry, rate limiting, and scheduling capabilities.
//!
//! # Components
//!
//! - [`retry`]: Retry manager with exponential backoff for handling transient failures
//! - [`http_client`]: Rate-limited HTTP client for external API calls
//! - [`scheduler`]: Automatic sync scheduler with jitter support
//!
//! # Example
//!
//! ```ignore
//! use registry_firewall::sync::{RetryManager, HttpClientWithRateLimit};
//! use registry_firewall::config::{RetryConfig, RateLimitConfig};
//! use registry_firewall::error::SyncError;
//!
//! async fn example() -> Result<(), SyncError> {
//!     // Create a retry manager
//!     let retry = RetryManager::new(RetryConfig::default());
//!
//!     // Create a rate-limited HTTP client (returns Result)
//!     let client = HttpClientWithRateLimit::new(RateLimitConfig::default())?;
//!
//!     // Use retry manager to execute operations
//!     let result = retry.execute(|| async {
//!         client.get("https://example.com/api").await
//!     }).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod http_client;
pub mod retry;
pub mod scheduler;

// Re-export main types for convenience
pub use http_client::{ConditionalResponse, HttpClientWithRateLimit};
pub use retry::RetryManager;
pub use scheduler::{
    ManualSyncHandle, SchedulerConfig, SyncResult, SyncScheduler, SyncStatus, Syncable,
};
