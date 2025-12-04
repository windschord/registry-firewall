//! Cache plugins for registry-firewall
//!
//! This module contains cache implementations for storing package data.
//! The default implementation uses the filesystem, with an optional Redis backend.

pub mod traits;

mod filesystem;
mod redis;

pub use traits::{CacheEntry, CacheMeta, CachePlugin, CacheStats};

#[cfg(test)]
pub use traits::MockCachePlugin;

pub use filesystem::{FilesystemCache, FilesystemCacheConfig};
pub use redis::{RedisCache, RedisCacheConfig};
