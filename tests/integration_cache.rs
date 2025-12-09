//! Cache behavior integration tests
//!
//! Tests the caching system including:
//! - Cache hit/miss behavior
//! - Cache invalidation
//! - Cache statistics

mod common;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use registry_firewall::plugins::cache::{
    CacheMeta, CachePlugin, FilesystemCache, FilesystemCacheConfig,
};
use reqwest::StatusCode;
use tempfile::TempDir;

/// Helper function to create a test cache
async fn create_test_cache(temp_dir: &TempDir) -> FilesystemCache {
    let config = FilesystemCacheConfig {
        base_path: temp_dir.path().to_path_buf(),
        max_size_bytes: 1024 * 1024, // 1MB
    };
    FilesystemCache::new_with_init(config)
        .await
        .expect("Failed to create cache")
}

/// Helper to create test metadata
fn test_meta(size: u64) -> CacheMeta {
    CacheMeta::new(
        size,
        Duration::from_secs(3600),
        "application/octet-stream".to_string(),
    )
}

/// Test 1: Cache stats API returns empty stats when no cache
#[tokio::test]
async fn test_cache_stats_no_cache() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{}/api/cache/stats", addr))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    // API uses total_size_bytes and entries as field names
    assert!(
        body.get("total_size_bytes").is_some(),
        "Expected total_size_bytes field"
    );
    assert!(body.get("entries").is_some(), "Expected entries field");
}

/// Test 2: Filesystem cache stores and retrieves data
#[tokio::test]
async fn test_filesystem_cache_store_retrieve() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = create_test_cache(&temp_dir).await;

    let key = "test-key";
    let data = Bytes::from("test data");

    // Store data
    let store_result = cache
        .set(key, data.clone(), test_meta(data.len() as u64))
        .await;
    assert!(store_result.is_ok());

    // Retrieve data
    let get_result = cache.get(key).await;
    assert!(get_result.is_ok());
    let entry = get_result.unwrap();
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().data, data);
}

/// Test 3: Filesystem cache returns None for missing key
#[tokio::test]
async fn test_filesystem_cache_miss() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = create_test_cache(&temp_dir).await;

    let result = cache.get("nonexistent-key").await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

/// Test 4: Filesystem cache delete
#[tokio::test]
async fn test_filesystem_cache_delete() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = create_test_cache(&temp_dir).await;

    let key = "delete-test";
    let data = Bytes::from("test data");

    // Store data
    cache
        .set(key, data.clone(), test_meta(data.len() as u64))
        .await
        .unwrap();

    // Verify it exists
    assert!(cache.get(key).await.unwrap().is_some());

    // Delete
    let delete_result = cache.delete(key).await;
    assert!(delete_result.is_ok());

    // Verify it's gone
    assert!(cache.get(key).await.unwrap().is_none());
}

/// Test 5: Filesystem cache stats
#[tokio::test]
async fn test_filesystem_cache_stats() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = create_test_cache(&temp_dir).await;

    // Store some data
    let data1 = Bytes::from("data1");
    cache
        .set("key1", data1.clone(), test_meta(data1.len() as u64))
        .await
        .unwrap();
    let data2 = Bytes::from("data2data2");
    cache
        .set("key2", data2.clone(), test_meta(data2.len() as u64))
        .await
        .unwrap();

    let stats = cache.stats().await;
    assert_eq!(stats.entries, 2);
    // Total size should account for both entries
    assert!(stats.total_size_bytes > 0);
}

/// Test 6: Filesystem cache purge
#[tokio::test]
async fn test_filesystem_cache_purge() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = create_test_cache(&temp_dir).await;

    // Store some data
    let data1 = Bytes::from("data1");
    cache
        .set("key1", data1.clone(), test_meta(data1.len() as u64))
        .await
        .unwrap();
    let data2 = Bytes::from("data2");
    cache
        .set("key2", data2.clone(), test_meta(data2.len() as u64))
        .await
        .unwrap();

    // Purge all
    let purge_result = cache.purge().await;
    assert!(purge_result.is_ok());

    // Verify both are gone
    assert!(cache.get("key1").await.unwrap().is_none());
    assert!(cache.get("key2").await.unwrap().is_none());

    // Stats should show empty
    let stats = cache.stats().await;
    assert_eq!(stats.entries, 0);
}

/// Test 7: Cache clear API
#[tokio::test]
async fn test_cache_clear_api_no_cache() {
    let state = create_test_state().await;
    let (addr, _shutdown) = run_test_server(state).await;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("http://{}/api/cache", addr))
        .send()
        .await
        .expect("Failed to send request");

    // Should succeed even with no cache configured (no-op)
    assert_eq!(response.status(), StatusCode::OK);
}

/// Test 8: Cache name returns correct identifier
#[tokio::test]
async fn test_filesystem_cache_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = create_test_cache(&temp_dir).await;

    assert_eq!(cache.name(), "filesystem");
}

/// Test 9: Cache handles concurrent operations
#[tokio::test]
async fn test_filesystem_cache_concurrent() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let cache = Arc::new(create_test_cache(&temp_dir).await);

    // Spawn multiple concurrent writes
    let mut handles = vec![];
    for i in 0..10 {
        let cache_clone = Arc::clone(&cache);
        let handle = tokio::spawn(async move {
            let key = format!("key-{}", i);
            let data = Bytes::from(format!("data-{}", i));
            let meta = CacheMeta::new(
                data.len() as u64,
                Duration::from_secs(3600),
                "application/octet-stream".to_string(),
            );
            cache_clone
                .set(&key, data, meta)
                .await
                .expect("Failed to set cache entry");
        });
        handles.push(handle);
    }

    // Wait for all writes
    for handle in handles {
        handle.await.expect("Task failed");
    }

    // Verify all entries exist
    for i in 0..10 {
        let key = format!("key-{}", i);
        let entry = cache.get(&key).await.unwrap();
        assert!(entry.is_some(), "Missing entry for {}", key);
    }
}
