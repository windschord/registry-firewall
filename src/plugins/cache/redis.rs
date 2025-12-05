//! Redis-based cache implementation (optional)
//!
//! This module implements caching using Redis as the backend.
//! It's suitable for distributed caching in multi-instance deployments.
//!
//! Note: This is a placeholder implementation. To enable Redis support,
//! add the `redis` crate to Cargo.toml and implement the actual Redis operations.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::RwLock;

use crate::error::CacheError;

use super::traits::{CacheEntry, CacheMeta, CachePlugin, CacheStats};

/// Configuration for the Redis cache
#[derive(Debug, Clone)]
pub struct RedisCacheConfig {
    /// Redis connection URL
    pub url: String,
    /// Key prefix for all cache entries
    pub prefix: String,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Default TTL in seconds (if not specified in metadata)
    pub default_ttl_secs: u64,
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".to_string(),
            prefix: "registry-firewall:cache:".to_string(),
            connection_timeout_secs: 5,
            default_ttl_secs: 86400, // 24 hours
        }
    }
}

/// Internal state for tracking cache statistics
#[derive(Default)]
struct CacheState {
    /// In-memory storage (placeholder for actual Redis)
    storage: HashMap<String, CacheEntry>,
    /// Cache hit count
    hits: u64,
    /// Cache miss count
    misses: u64,
    /// Eviction count
    evictions: u64,
}

/// Redis-based cache implementation
///
/// This is a placeholder implementation that uses in-memory storage.
/// In production, this would use the `redis` crate for actual Redis operations.
pub struct RedisCache {
    config: RedisCacheConfig,
    state: Arc<RwLock<CacheState>>,
}

impl RedisCache {
    /// Creates a new RedisCache with the given configuration
    pub fn new(config: RedisCacheConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CacheState::default())),
        }
    }

    /// Returns the configured Redis URL
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Returns the key prefix
    pub fn prefix(&self) -> &str {
        &self.config.prefix
    }

    /// Generates a prefixed key for Redis storage
    fn make_key(&self, key: &str) -> String {
        format!("{}{}", self.config.prefix, key)
    }
}

#[async_trait]
impl CachePlugin for RedisCache {
    fn name(&self) -> &str {
        "redis"
    }

    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        let prefixed_key = self.make_key(key);
        let mut state = self.state.write().await;

        // First check if entry exists and get necessary info
        let entry_info = state.storage.get(&prefixed_key).map(|e| {
            (e.meta.is_expired(), e.clone())
        });

        match entry_info {
            Some((is_expired, entry)) => {
                if is_expired {
                    state.storage.remove(&prefixed_key);
                    state.misses += 1;
                    Ok(None)
                } else {
                    state.hits += 1;
                    Ok(Some(entry))
                }
            }
            None => {
                state.misses += 1;
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, data: Bytes, meta: CacheMeta) -> Result<(), CacheError> {
        let prefixed_key = self.make_key(key);
        let mut state = self.state.write().await;

        state.storage.insert(
            prefixed_key,
            CacheEntry {
                data,
                meta,
            },
        );

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let prefixed_key = self.make_key(key);
        let mut state = self.state.write().await;
        state.storage.remove(&prefixed_key);
        Ok(())
    }

    async fn stats(&self) -> CacheStats {
        let state = self.state.read().await;
        let total_size: u64 = state.storage.values().map(|e| e.meta.size).sum();

        CacheStats {
            entries: state.storage.len() as u64,
            total_size_bytes: total_size,
            hits: state.hits,
            misses: state.misses,
            evictions: state.evictions,
        }
    }

    async fn purge(&self) -> Result<(), CacheError> {
        let mut state = self.state.write().await;
        state.storage.clear();
        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, CacheError> {
        let mut state = self.state.write().await;
        let initial_count = state.storage.len();

        state.storage.retain(|_, entry| !entry.meta.is_expired());

        let deleted = initial_count - state.storage.len();
        // Note: We don't increment evictions here because expiration is not
        // the same as eviction (which refers to size-based removal).

        Ok(deleted as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_cache() -> RedisCache {
        RedisCache::new(RedisCacheConfig::default())
    }

    // Test 1: Cache name
    #[tokio::test]
    async fn test_cache_name() {
        let cache = create_test_cache();
        assert_eq!(cache.name(), "redis");
    }

    // Test 2: Config defaults
    #[test]
    fn test_config_defaults() {
        let config = RedisCacheConfig::default();
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.prefix, "registry-firewall:cache:");
        assert_eq!(config.connection_timeout_secs, 5);
        assert_eq!(config.default_ttl_secs, 86400);
    }

    // Test 3: Set and get entry
    #[tokio::test]
    async fn test_set_and_get_entry() {
        let cache = create_test_cache();

        let data = Bytes::from("Test data");
        let meta = CacheMeta::new(9, Duration::from_secs(3600), "text/plain".to_string());

        cache.set("test_key", data.clone(), meta).await.unwrap();

        let entry = cache.get("test_key").await.unwrap().unwrap();
        assert_eq!(entry.data, data);
        assert_eq!(entry.meta.content_type, "text/plain");
    }

    // Test 4: Get non-existent key returns None
    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let cache = create_test_cache();
        let result = cache.get("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    // Test 5: Delete entry
    #[tokio::test]
    async fn test_delete_entry() {
        let cache = create_test_cache();

        let data = Bytes::from("Data");
        let meta = CacheMeta::new(4, Duration::from_secs(3600), "text/plain".to_string());

        cache.set("delete_me", data, meta).await.unwrap();
        assert!(cache.get("delete_me").await.unwrap().is_some());

        cache.delete("delete_me").await.unwrap();
        assert!(cache.get("delete_me").await.unwrap().is_none());
    }

    // Test 6: TTL expiration
    #[tokio::test]
    async fn test_ttl_expiration() {
        let cache = create_test_cache();

        let data = Bytes::from("Expiring data");
        let mut meta = CacheMeta::new(13, Duration::from_secs(0), "text/plain".to_string());
        meta.created_at = chrono::Utc::now() - chrono::Duration::seconds(10);

        cache.set("expired", data, meta).await.unwrap();

        // Entry should be treated as expired
        let result = cache.get("expired").await.unwrap();
        assert!(result.is_none());
    }

    // Test 7: Stats tracking
    #[tokio::test]
    async fn test_stats_tracking() {
        let cache = create_test_cache();

        let data = Bytes::from("Data");
        let meta = CacheMeta::new(4, Duration::from_secs(3600), "text/plain".to_string());
        cache.set("key1", data.clone(), meta.clone()).await.unwrap();
        cache.set("key2", data, meta).await.unwrap();

        // Hit
        cache.get("key1").await.unwrap();
        // Miss
        cache.get("nonexistent").await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.total_size_bytes, 8);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    // Test 8: Purge all entries
    #[tokio::test]
    async fn test_purge() {
        let cache = create_test_cache();

        for i in 0..5 {
            let data = Bytes::from(format!("Data {}", i));
            let meta = CacheMeta::new(data.len() as u64, Duration::from_secs(3600), "text/plain".to_string());
            cache.set(&format!("key{}", i), data, meta).await.unwrap();
        }

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 5);

        cache.purge().await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 0);
    }

    // Test 9: Purge expired entries
    #[tokio::test]
    async fn test_purge_expired() {
        let cache = create_test_cache();

        // Add valid entry
        let data1 = Bytes::from("Valid");
        let meta1 = CacheMeta::new(5, Duration::from_secs(3600), "text/plain".to_string());
        cache.set("valid", data1, meta1).await.unwrap();

        // Add expired entry
        let data2 = Bytes::from("Expired");
        let mut meta2 = CacheMeta::new(7, Duration::from_secs(0), "text/plain".to_string());
        meta2.created_at = chrono::Utc::now() - chrono::Duration::seconds(10);
        cache.set("expired", data2, meta2).await.unwrap();

        let deleted = cache.purge_expired().await.unwrap();
        assert_eq!(deleted, 1);

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 1);
    }

    // Test 10: Key prefixing
    #[test]
    fn test_key_prefixing() {
        let config = RedisCacheConfig {
            prefix: "myapp:".to_string(),
            ..Default::default()
        };
        let cache = RedisCache::new(config);

        assert_eq!(cache.make_key("test"), "myapp:test");
        assert_eq!(cache.make_key("foo/bar"), "myapp:foo/bar");
    }

    // Test 11: URL accessor
    #[test]
    fn test_url_accessor() {
        let config = RedisCacheConfig {
            url: "redis://custom:6379".to_string(),
            ..Default::default()
        };
        let cache = RedisCache::new(config);

        assert_eq!(cache.url(), "redis://custom:6379");
    }
}
