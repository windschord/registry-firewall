//! Cache plugin trait and related types
//!
//! This module defines the CachePlugin trait that all cache implementations must implement,
//! as well as the associated types like CacheEntry, CacheMeta, and CacheStats.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::CacheError;

/// A cached entry containing data and metadata
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached data
    pub data: Bytes,
    /// Metadata about the cached entry
    pub meta: CacheMeta,
}

/// Metadata associated with a cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    /// Size of the cached data in bytes
    pub size: u64,
    /// Time-to-live duration
    #[serde(with = "duration_serde")]
    pub ttl: Duration,
    /// When the entry was created
    pub created_at: DateTime<Utc>,
    /// ETag from the upstream response
    pub etag: Option<String>,
    /// Content-Type of the cached data
    pub content_type: String,
}

/// Serde helper for Duration
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

impl CacheMeta {
    /// Creates a new CacheMeta with the given parameters
    pub fn new(size: u64, ttl: Duration, content_type: String) -> Self {
        Self {
            size,
            ttl,
            created_at: Utc::now(),
            etag: None,
            content_type,
        }
    }

    /// Creates a new CacheMeta with an ETag
    pub fn with_etag(size: u64, ttl: Duration, content_type: String, etag: String) -> Self {
        Self {
            size,
            ttl,
            created_at: Utc::now(),
            etag: Some(etag),
            content_type,
        }
    }

    /// Checks if the cache entry has expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now();
        let expires_at = self.created_at + chrono::Duration::from_std(self.ttl).unwrap_or_default();
        now > expires_at
    }
}

/// Statistics about cache usage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total number of cached entries
    pub entries: u64,
    /// Total size of all cached data in bytes
    pub total_size_bytes: u64,
    /// Number of cache hits
    pub hits: u64,
    /// Number of cache misses
    pub misses: u64,
    /// Number of evictions due to size limits
    pub evictions: u64,
}

impl CacheStats {
    /// Creates new empty cache statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculates the hit rate as a percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// Trait for cache plugins
///
/// Cache plugins are responsible for storing and retrieving cached data.
/// Implementations can use various storage backends like filesystem or Redis.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CachePlugin: Send + Sync {
    /// Returns the name of this cache plugin
    fn name(&self) -> &str;

    /// Retrieves a cached entry by key
    ///
    /// Returns `Ok(Some(entry))` if found, `Ok(None)` if not found,
    /// or an error if the operation failed.
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError>;

    /// Stores data in the cache with the given key and metadata
    ///
    /// If an entry with the same key exists, it will be overwritten.
    async fn set(&self, key: &str, data: Bytes, meta: CacheMeta) -> Result<(), CacheError>;

    /// Deletes a cached entry by key
    ///
    /// Returns `Ok(())` even if the entry doesn't exist.
    async fn delete(&self, key: &str) -> Result<(), CacheError>;

    /// Returns statistics about cache usage
    async fn stats(&self) -> CacheStats;

    /// Deletes all cached entries
    async fn purge(&self) -> Result<(), CacheError>;

    /// Deletes all expired entries and returns the count of deleted entries
    async fn purge_expired(&self) -> Result<u64, CacheError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: CacheMeta creation
    #[test]
    fn test_cache_meta_new() {
        let meta = CacheMeta::new(1024, Duration::from_secs(3600), "application/json".to_string());

        assert_eq!(meta.size, 1024);
        assert_eq!(meta.ttl, Duration::from_secs(3600));
        assert_eq!(meta.content_type, "application/json");
        assert!(meta.etag.is_none());
    }

    // Test 2: CacheMeta with ETag
    #[test]
    fn test_cache_meta_with_etag() {
        let meta = CacheMeta::with_etag(
            2048,
            Duration::from_secs(7200),
            "text/html".to_string(),
            "abc123".to_string(),
        );

        assert_eq!(meta.size, 2048);
        assert_eq!(meta.ttl, Duration::from_secs(7200));
        assert_eq!(meta.content_type, "text/html");
        assert_eq!(meta.etag, Some("abc123".to_string()));
    }

    // Test 3: CacheMeta expiration check - not expired
    #[test]
    fn test_cache_meta_not_expired() {
        let meta = CacheMeta::new(1024, Duration::from_secs(3600), "text/plain".to_string());
        assert!(!meta.is_expired());
    }

    // Test 4: CacheMeta expiration check - expired
    #[test]
    fn test_cache_meta_expired() {
        let mut meta = CacheMeta::new(1024, Duration::from_secs(0), "text/plain".to_string());
        // Set created_at to the past
        meta.created_at = Utc::now() - chrono::Duration::seconds(10);
        assert!(meta.is_expired());
    }

    // Test 5: CacheStats defaults
    #[test]
    fn test_cache_stats_default() {
        let stats = CacheStats::default();

        assert_eq!(stats.entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
    }

    // Test 6: CacheStats hit rate with no requests
    #[test]
    fn test_cache_stats_hit_rate_zero() {
        let stats = CacheStats::new();
        assert_eq!(stats.hit_rate(), 0.0);
    }

    // Test 7: CacheStats hit rate calculation
    #[test]
    fn test_cache_stats_hit_rate() {
        let stats = CacheStats {
            entries: 10,
            total_size_bytes: 10240,
            hits: 75,
            misses: 25,
            evictions: 0,
        };
        assert_eq!(stats.hit_rate(), 75.0);
    }

    // Test 8: CacheEntry creation
    #[test]
    fn test_cache_entry() {
        let data = Bytes::from("test data");
        let meta = CacheMeta::new(9, Duration::from_secs(3600), "text/plain".to_string());
        let entry = CacheEntry {
            data: data.clone(),
            meta,
        };

        assert_eq!(entry.data, data);
        assert_eq!(entry.meta.size, 9);
    }

    // Test 9: CacheMeta serialization
    #[test]
    fn test_cache_meta_serialization() {
        let meta = CacheMeta::new(1024, Duration::from_secs(3600), "application/json".to_string());
        let json = serde_json::to_string(&meta).expect("Serialization should succeed");

        assert!(json.contains("\"size\":1024"));
        assert!(json.contains("\"ttl\":3600"));
        assert!(json.contains("\"content_type\":\"application/json\""));
    }

    // Test 10: CacheMeta deserialization
    #[test]
    fn test_cache_meta_deserialization() {
        let json = r#"{
            "size": 2048,
            "ttl": 7200,
            "created_at": "2025-01-01T00:00:00Z",
            "etag": "xyz789",
            "content_type": "text/html"
        }"#;

        let meta: CacheMeta = serde_json::from_str(json).expect("Deserialization should succeed");

        assert_eq!(meta.size, 2048);
        assert_eq!(meta.ttl, Duration::from_secs(7200));
        assert_eq!(meta.etag, Some("xyz789".to_string()));
        assert_eq!(meta.content_type, "text/html");
    }

    // Test 11: MockCachePlugin can be created and used
    #[tokio::test]
    async fn test_mock_cache_plugin() {
        let mut mock = MockCachePlugin::new();

        mock.expect_name().return_const("mock_cache".to_string());
        mock.expect_get()
            .with(mockall::predicate::eq("test_key"))
            .returning(|_| Ok(None));

        assert_eq!(mock.name(), "mock_cache");
        let result = mock.get("test_key").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // Test 12: MockCachePlugin set and get
    #[tokio::test]
    async fn test_mock_cache_plugin_set_get() {
        let mut mock = MockCachePlugin::new();
        let test_data = Bytes::from("cached data");
        let test_data_clone = test_data.clone();

        mock.expect_set().returning(|_, _, _| Ok(()));
        mock.expect_get().returning(move |_| {
            Ok(Some(CacheEntry {
                data: test_data_clone.clone(),
                meta: CacheMeta::new(11, Duration::from_secs(3600), "text/plain".to_string()),
            }))
        });

        let meta = CacheMeta::new(11, Duration::from_secs(3600), "text/plain".to_string());
        assert!(mock.set("key", test_data, meta).await.is_ok());

        let entry = mock.get("key").await.unwrap().unwrap();
        assert_eq!(entry.data.as_ref(), b"cached data");
    }

    // Test 13: CacheStats serialization
    #[test]
    fn test_cache_stats_serialization() {
        let stats = CacheStats {
            entries: 100,
            total_size_bytes: 1024000,
            hits: 500,
            misses: 100,
            evictions: 5,
        };

        let json = serde_json::to_string(&stats).expect("Serialization should succeed");
        let deserialized: CacheStats =
            serde_json::from_str(&json).expect("Deserialization should succeed");

        assert_eq!(deserialized.entries, stats.entries);
        assert_eq!(deserialized.hits, stats.hits);
        assert_eq!(deserialized.misses, stats.misses);
    }
}
