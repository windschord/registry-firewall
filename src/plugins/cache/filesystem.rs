//! Filesystem-based cache implementation
//!
//! This module implements caching using the local filesystem.
//! Each cache entry is stored as a file with an accompanying .meta.json file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::sync::RwLock;

use crate::error::CacheError;

use super::traits::{CacheEntry, CacheMeta, CachePlugin, CacheStats};

/// Configuration for the filesystem cache
#[derive(Debug, Clone)]
pub struct FilesystemCacheConfig {
    /// Base path for cache storage
    pub base_path: PathBuf,
    /// Maximum cache size in bytes
    pub max_size_bytes: u64,
}

impl Default for FilesystemCacheConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("/data/cache"),
            max_size_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
        }
    }
}

/// Extended metadata stored in .meta.json files
/// Includes the original key to support recovery during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMeta {
    /// The original cache key (for recovery during scan)
    original_key: String,
    /// The actual cache metadata
    #[serde(flatten)]
    meta: CacheMeta,
}

/// Metadata about an LRU entry
#[derive(Debug, Clone)]
struct LruEntry {
    /// Size of the cached data in bytes
    size: u64,
    /// Last access timestamp (for LRU eviction)
    last_accessed: chrono::DateTime<chrono::Utc>,
}

/// Internal state for the cache
#[derive(Default)]
struct CacheState {
    /// Total size of all cached entries
    total_size: u64,
    /// Cache hit count
    hits: u64,
    /// Cache miss count
    misses: u64,
    /// Eviction count
    evictions: u64,
    /// LRU tracking: original_key -> (size, last_accessed)
    lru_map: HashMap<String, LruEntry>,
}

/// Filesystem-based cache implementation
pub struct FilesystemCache {
    config: FilesystemCacheConfig,
    state: Arc<RwLock<CacheState>>,
}

impl FilesystemCache {
    /// Creates a new FilesystemCache with the given configuration
    pub fn new(config: FilesystemCacheConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CacheState::default())),
        }
    }

    /// Creates a new FilesystemCache and initializes the base directory
    pub async fn new_with_init(config: FilesystemCacheConfig) -> Result<Self, CacheError> {
        // Create base directory if it doesn't exist
        fs::create_dir_all(&config.base_path).await?;

        let cache = Self::new(config);
        // Scan existing entries to populate state
        cache.scan_existing_entries().await?;
        Ok(cache)
    }

    /// Returns the base path for cache storage
    pub fn base_path(&self) -> &PathBuf {
        &self.config.base_path
    }

    /// Returns the maximum cache size in bytes
    pub fn max_size_bytes(&self) -> u64 {
        self.config.max_size_bytes
    }

    /// Encodes a key to a safe filename using URL-safe base64
    /// This prevents collisions between keys with different special characters
    fn encode_key(key: &str) -> String {
        URL_SAFE_NO_PAD.encode(key.as_bytes())
    }

    /// Gets the file path for a cache key
    fn key_to_path(&self, key: &str) -> PathBuf {
        let encoded = Self::encode_key(key);
        self.config.base_path.join(&encoded)
    }

    /// Gets the metadata file path for a cache key
    fn key_to_meta_path(&self, key: &str) -> PathBuf {
        let encoded = Self::encode_key(key);
        self.config.base_path.join(format!("{}.meta.json", encoded))
    }

    /// Scans existing entries to populate the internal state
    ///
    /// Reads all .meta.json files to recover original keys and populate the LRU map.
    async fn scan_existing_entries(&self) -> Result<(), CacheError> {
        let base_path = &self.config.base_path;
        if !base_path.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(base_path).await?;
        let mut state = self.state.write().await;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            // Only process .meta.json files to recover original keys
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();

            if !file_name.ends_with(".meta.json") {
                continue;
            }

            // Read the meta file to get the original key
            if let Ok(meta_content) = fs::read_to_string(&path).await {
                if let Ok(stored_meta) = serde_json::from_str::<StoredMeta>(&meta_content) {
                    // Extract the encoded base name by removing ".meta.json" suffix
                    let encoded_base = file_name.strip_suffix(".meta.json").unwrap_or(file_name);
                    let data_path = base_path.join(encoded_base);

                    if let Ok(file_meta) = fs::metadata(&data_path).await {
                        let size = file_meta.len();
                        state.total_size += size;
                        state.lru_map.insert(
                            stored_meta.original_key,
                            LruEntry {
                                size,
                                last_accessed: chrono::Utc::now(),
                            },
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Evicts entries using LRU until enough space is available
    async fn evict_lru(&self, required_space: u64) -> Result<(), CacheError> {
        let max_size = self.config.max_size_bytes;

        loop {
            // Collect eviction targets while holding the lock
            let eviction_target = {
                let mut state = self.state.write().await;

                if state.total_size + required_space <= max_size || state.lru_map.is_empty() {
                    break;
                }

                // Find the least recently used entry
                let lru_key = state
                    .lru_map
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_accessed)
                    .map(|(k, _)| k.clone());

                if let Some(key) = lru_key {
                    let entry_size = state.lru_map.get(&key).map(|e| e.size).unwrap_or(0);

                    // Remove from LRU map and update stats
                    state.lru_map.remove(&key);
                    state.total_size = state.total_size.saturating_sub(entry_size);
                    state.evictions += 1;

                    Some(key)
                } else {
                    None
                }
            };

            // Delete files outside of lock
            if let Some(key) = eviction_target {
                let data_path = self.key_to_path(&key);
                let meta_path = self.key_to_meta_path(&key);
                let _ = fs::remove_file(&data_path).await;
                let _ = fs::remove_file(&meta_path).await;
            } else {
                break;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl CachePlugin for FilesystemCache {
    fn name(&self) -> &str {
        "filesystem"
    }

    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        let data_path = self.key_to_path(key);
        let meta_path = self.key_to_meta_path(key);

        // Read metadata first
        let meta_content = match fs::read_to_string(&meta_path).await {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut state = self.state.write().await;
                state.misses += 1;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        let stored_meta: StoredMeta = serde_json::from_str(&meta_content)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;

        // Check if expired
        if stored_meta.meta.is_expired() {
            // Clean up expired entry
            let _ = fs::remove_file(&data_path).await;
            let _ = fs::remove_file(&meta_path).await;

            let mut state = self.state.write().await;
            if let Some(lru_entry) = state.lru_map.remove(key) {
                state.total_size = state.total_size.saturating_sub(lru_entry.size);
            }
            state.misses += 1;
            return Ok(None);
        }

        // Read data file
        let data = match fs::read(&data_path).await {
            Ok(data) => Bytes::from(data),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Meta exists but data doesn't - clean up
                let _ = fs::remove_file(&meta_path).await;
                let mut state = self.state.write().await;
                state.lru_map.remove(key);
                state.misses += 1;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };

        // Update LRU access time and hit count
        let mut state = self.state.write().await;
        state.hits += 1;
        if let Some(lru_entry) = state.lru_map.get_mut(key) {
            lru_entry.last_accessed = chrono::Utc::now();
        }

        Ok(Some(CacheEntry {
            data,
            meta: stored_meta.meta,
        }))
    }

    async fn set(&self, key: &str, data: Bytes, meta: CacheMeta) -> Result<(), CacheError> {
        let data_len = data.len() as u64;

        // Check if we need to evict entries
        {
            let state = self.state.read().await;
            if state.total_size + data_len > self.config.max_size_bytes {
                drop(state);
                self.evict_lru(data_len).await?;
            }
        }

        let data_path = self.key_to_path(key);
        let meta_path = self.key_to_meta_path(key);

        // Ensure parent directory exists
        if let Some(parent) = data_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Write data file
        fs::write(&data_path, &data).await?;

        // Write metadata file with original key
        let stored_meta = StoredMeta {
            original_key: key.to_string(),
            meta,
        };
        let meta_json = serde_json::to_string_pretty(&stored_meta)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;
        fs::write(&meta_path, meta_json).await?;

        // Update state
        let mut state = self.state.write().await;

        // If key already exists, subtract old size
        if let Some(old_entry) = state.lru_map.get(key) {
            state.total_size = state.total_size.saturating_sub(old_entry.size);
        }

        state.total_size += data_len;
        state.lru_map.insert(
            key.to_string(),
            LruEntry {
                size: data_len,
                last_accessed: chrono::Utc::now(),
            },
        );

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CacheError> {
        let data_path = self.key_to_path(key);
        let meta_path = self.key_to_meta_path(key);

        // Update state and delete files atomically (state update first)
        {
            let mut state = self.state.write().await;
            if let Some(lru_entry) = state.lru_map.remove(key) {
                state.total_size = state.total_size.saturating_sub(lru_entry.size);
            }
        }

        // Delete files (ignore errors if files don't exist)
        let _ = fs::remove_file(&data_path).await;
        let _ = fs::remove_file(&meta_path).await;

        Ok(())
    }

    async fn stats(&self) -> CacheStats {
        let state = self.state.read().await;
        CacheStats {
            entries: state.lru_map.len() as u64,
            total_size_bytes: state.total_size,
            hits: state.hits,
            misses: state.misses,
            evictions: state.evictions,
        }
    }

    async fn purge(&self) -> Result<(), CacheError> {
        // Collect keys and clear state atomically
        let keys: Vec<String> = {
            let mut state = self.state.write().await;
            let keys: Vec<String> = state.lru_map.keys().cloned().collect();
            state.lru_map.clear();
            state.total_size = 0;
            keys
        };

        // Delete all files
        for key in keys {
            let data_path = self.key_to_path(&key);
            let meta_path = self.key_to_meta_path(&key);
            let _ = fs::remove_file(&data_path).await;
            let _ = fs::remove_file(&meta_path).await;
        }

        Ok(())
    }

    async fn purge_expired(&self) -> Result<u64, CacheError> {
        // Get keys to check
        let keys: Vec<String> = {
            let state = self.state.read().await;
            state.lru_map.keys().cloned().collect()
        };

        let mut deleted_count = 0u64;

        for key in keys {
            let meta_path = self.key_to_meta_path(&key);

            // Read and check metadata
            if let Ok(meta_content) = fs::read_to_string(&meta_path).await {
                if let Ok(stored_meta) = serde_json::from_str::<StoredMeta>(&meta_content) {
                    if stored_meta.meta.is_expired() {
                        // Re-verify key still exists before deleting
                        let should_delete = {
                            let state = self.state.read().await;
                            state.lru_map.contains_key(&key)
                        };
                        if should_delete {
                            self.delete(&key).await?;
                            deleted_count += 1;
                        }
                    }
                }
            }
        }

        Ok(deleted_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    async fn create_test_cache() -> (FilesystemCache, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = FilesystemCacheConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_size_bytes: 1024 * 1024, // 1 MB
        };
        let cache = FilesystemCache::new_with_init(config)
            .await
            .expect("Failed to create cache");
        (cache, temp_dir)
    }

    // Test 1: Cache name
    #[tokio::test]
    async fn test_cache_name() {
        let (cache, _temp) = create_test_cache().await;
        assert_eq!(cache.name(), "filesystem");
    }

    // Test 2: Set and get basic entry
    #[tokio::test]
    async fn test_set_and_get_entry() {
        let (cache, _temp) = create_test_cache().await;

        let data = Bytes::from("Hello, World!");
        let meta = CacheMeta::new(13, Duration::from_secs(3600), "text/plain".to_string());

        cache
            .set("test_key", data.clone(), meta)
            .await
            .expect("Set should succeed");

        let entry = cache
            .get("test_key")
            .await
            .expect("Get should succeed")
            .expect("Entry should exist");

        assert_eq!(entry.data, data);
        assert_eq!(entry.meta.content_type, "text/plain");
    }

    // Test 3: Get non-existent key returns None
    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let (cache, _temp) = create_test_cache().await;

        let result = cache
            .get("nonexistent")
            .await
            .expect("Get should not error");
        assert!(result.is_none());
    }

    // Test 4: Delete entry
    #[tokio::test]
    async fn test_delete_entry() {
        let (cache, _temp) = create_test_cache().await;

        let data = Bytes::from("Test data");
        let meta = CacheMeta::new(9, Duration::from_secs(3600), "text/plain".to_string());

        cache.set("delete_me", data, meta).await.unwrap();
        assert!(cache.get("delete_me").await.unwrap().is_some());

        cache.delete("delete_me").await.unwrap();
        assert!(cache.get("delete_me").await.unwrap().is_none());
    }

    // Test 5: Delete non-existent key is ok
    #[tokio::test]
    async fn test_delete_nonexistent_key() {
        let (cache, _temp) = create_test_cache().await;
        // Should not return error
        cache.delete("nonexistent").await.unwrap();
    }

    // Test 6: TTL expiration
    #[tokio::test]
    async fn test_ttl_expiration() {
        let (cache, _temp) = create_test_cache().await;

        let data = Bytes::from("Expiring data");
        let mut meta = CacheMeta::new(13, Duration::from_secs(0), "text/plain".to_string());
        // Set created_at to the past
        meta.created_at = chrono::Utc::now() - chrono::Duration::seconds(10);

        cache.set("expired_key", data, meta).await.unwrap();

        // The entry should be treated as expired on get
        let result = cache.get("expired_key").await.unwrap();
        assert!(result.is_none());
    }

    // Test 7: Stats tracking - entries and size
    #[tokio::test]
    async fn test_stats_entries_and_size() {
        let (cache, _temp) = create_test_cache().await;

        let data1 = Bytes::from("First entry");
        let meta1 = CacheMeta::new(11, Duration::from_secs(3600), "text/plain".to_string());

        let data2 = Bytes::from("Second entry data");
        let meta2 = CacheMeta::new(17, Duration::from_secs(3600), "text/plain".to_string());

        cache.set("key1", data1, meta1).await.unwrap();
        cache.set("key2", data2, meta2).await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.total_size_bytes, 28); // 11 + 17
    }

    // Test 8: Stats tracking - hits and misses
    #[tokio::test]
    async fn test_stats_hits_and_misses() {
        let (cache, _temp) = create_test_cache().await;

        let data = Bytes::from("Data");
        let meta = CacheMeta::new(4, Duration::from_secs(3600), "text/plain".to_string());
        cache.set("existing", data, meta).await.unwrap();

        // Hit
        cache.get("existing").await.unwrap();
        // Miss
        cache.get("nonexistent").await.unwrap();
        // Another hit
        cache.get("existing").await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
    }

    // Test 9: Purge all entries
    #[tokio::test]
    async fn test_purge() {
        let (cache, _temp) = create_test_cache().await;

        for i in 0..5 {
            let data = Bytes::from(format!("Data {}", i));
            let meta = CacheMeta::new(
                data.len() as u64,
                Duration::from_secs(3600),
                "text/plain".to_string(),
            );
            cache.set(&format!("key{}", i), data, meta).await.unwrap();
        }

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 5);

        cache.purge().await.unwrap();

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.total_size_bytes, 0);
    }

    // Test 10: Purge expired entries
    #[tokio::test]
    async fn test_purge_expired() {
        let (cache, _temp) = create_test_cache().await;

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

    // Test 11: LRU eviction
    #[tokio::test]
    async fn test_lru_eviction() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let config = FilesystemCacheConfig {
            base_path: temp_dir.path().to_path_buf(),
            max_size_bytes: 100, // Very small limit
        };
        let cache = FilesystemCache::new_with_init(config)
            .await
            .expect("Failed to create cache");

        // Add first entry (50 bytes)
        let data1 = Bytes::from(vec![0u8; 50]);
        let meta1 = CacheMeta::new(
            50,
            Duration::from_secs(3600),
            "application/octet-stream".to_string(),
        );
        cache.set("key1", data1, meta1).await.unwrap();

        // Small delay to ensure different access times
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add second entry (50 bytes) - should still fit
        let data2 = Bytes::from(vec![1u8; 50]);
        let meta2 = CacheMeta::new(
            50,
            Duration::from_secs(3600),
            "application/octet-stream".to_string(),
        );
        cache.set("key2", data2, meta2).await.unwrap();

        // Add third entry (50 bytes) - should trigger eviction of key1
        let data3 = Bytes::from(vec![2u8; 50]);
        let meta3 = CacheMeta::new(
            50,
            Duration::from_secs(3600),
            "application/octet-stream".to_string(),
        );
        cache.set("key3", data3, meta3).await.unwrap();

        let stats = cache.stats().await;
        assert!(stats.evictions >= 1, "Should have at least 1 eviction");

        // key1 should be evicted (oldest)
        assert!(cache.get("key1").await.unwrap().is_none());
    }

    // Test 12: Overwrite existing entry
    #[tokio::test]
    async fn test_overwrite_entry() {
        let (cache, _temp) = create_test_cache().await;

        let data1 = Bytes::from("Original");
        let meta1 = CacheMeta::new(8, Duration::from_secs(3600), "text/plain".to_string());
        cache.set("key", data1, meta1).await.unwrap();

        let data2 = Bytes::from("Updated content");
        let meta2 = CacheMeta::new(15, Duration::from_secs(3600), "text/plain".to_string());
        cache.set("key", data2.clone(), meta2).await.unwrap();

        let entry = cache.get("key").await.unwrap().unwrap();
        assert_eq!(entry.data, data2);

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.total_size_bytes, 15);
    }

    // Test 13: Meta file is created with original key
    #[tokio::test]
    async fn test_meta_file_created() {
        let (cache, temp_dir) = create_test_cache().await;

        let data = Bytes::from("Test");
        let meta = CacheMeta::with_etag(
            4,
            Duration::from_secs(3600),
            "text/plain".to_string(),
            "etag123".to_string(),
        );
        cache.set("meta_test", data, meta).await.unwrap();

        // The meta file uses base64-encoded key
        let encoded_key = FilesystemCache::encode_key("meta_test");
        let meta_path = temp_dir.path().join(format!("{}.meta.json", encoded_key));
        assert!(meta_path.exists(), "Meta file should exist");

        let content = std::fs::read_to_string(&meta_path).unwrap();
        assert!(content.contains("etag123"));
        assert!(content.contains("text/plain"));
        assert!(content.contains("meta_test")); // Original key stored
    }

    // Test 14: Key sanitization - no collisions with base64 encoding
    #[tokio::test]
    async fn test_key_no_collisions() {
        let (cache, _temp) = create_test_cache().await;

        // Keys that would collide with simple sanitization
        let data = Bytes::from("Data");
        let meta = CacheMeta::new(4, Duration::from_secs(3600), "text/plain".to_string());

        // These keys would all become "path_with_something" with simple replacement
        cache
            .set("path/with/slashes", data.clone(), meta.clone())
            .await
            .unwrap();
        cache
            .set("path:with:colons", data.clone(), meta.clone())
            .await
            .unwrap();
        cache
            .set("path_with_underscores", data.clone(), meta)
            .await
            .unwrap();

        // All should be retrievable independently (no collisions)
        assert!(cache.get("path/with/slashes").await.unwrap().is_some());
        assert!(cache.get("path:with:colons").await.unwrap().is_some());
        assert!(cache.get("path_with_underscores").await.unwrap().is_some());

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 3, "All three entries should exist");
    }

    // Test 15: Config defaults
    #[test]
    fn test_config_defaults() {
        let config = FilesystemCacheConfig::default();
        assert_eq!(config.base_path, PathBuf::from("/data/cache"));
        assert_eq!(config.max_size_bytes, 50 * 1024 * 1024 * 1024);
    }

    // Test 16: Base64 encoding produces unique filenames
    #[test]
    fn test_key_encoding_uniqueness() {
        let key1 = "path/with/slashes";
        let key2 = "path:with:colons";
        let key3 = "path_with_underscores";

        let encoded1 = FilesystemCache::encode_key(key1);
        let encoded2 = FilesystemCache::encode_key(key2);
        let encoded3 = FilesystemCache::encode_key(key3);

        assert_ne!(encoded1, encoded2);
        assert_ne!(encoded1, encoded3);
        assert_ne!(encoded2, encoded3);
    }
}
