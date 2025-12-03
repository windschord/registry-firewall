//! Retry manager for handling transient failures with exponential backoff
//!
//! This module provides a retry mechanism with configurable backoff strategy,
//! jitter, and maximum retry limits for handling temporary failures gracefully.

use crate::config::RetryConfig;
use crate::error::RetryableError;
use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tracing::{debug, warn};

/// Retry manager with exponential backoff support
#[derive(Debug, Clone)]
pub struct RetryManager {
    config: RetryConfig,
}

impl RetryManager {
    /// Create a new RetryManager with the given configuration
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Create a RetryManager with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Execute an async operation with retry logic
    ///
    /// The operation will be retried up to `max_retries` times if it returns
    /// a retryable error. Each retry will wait for an exponentially increasing
    /// backoff period with optional jitter.
    ///
    /// # Arguments
    ///
    /// * `operation` - A closure that returns a Future with Result<T, E>
    ///
    /// # Returns
    ///
    /// The result of the operation, or the last error if all retries are exhausted
    pub async fn execute<F, Fut, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: RetryableError + std::fmt::Display,
    {
        let mut attempt = 0u32;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    if !err.is_retryable() || attempt >= self.config.max_retries {
                        if attempt >= self.config.max_retries {
                            warn!(
                                attempts = attempt + 1,
                                max_retries = self.config.max_retries,
                                "Max retries exhausted"
                            );
                        }
                        return Err(err);
                    }

                    let backoff = self.calculate_backoff(attempt);
                    debug!(
                        attempt = attempt + 1,
                        max_retries = self.config.max_retries,
                        backoff_ms = backoff.as_millis(),
                        error = %err,
                        "Retrying after transient error"
                    );

                    tokio::time::sleep(backoff).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Calculate backoff duration for a given attempt number
    ///
    /// Uses exponential backoff: initial_backoff * multiplier^attempt
    /// Capped at max_backoff_secs with optional jitter
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base = self.config.initial_backoff_secs as f64
            * self.config.backoff_multiplier.powi(attempt as i32);
        let capped = base.min(self.config.max_backoff_secs as f64);

        let delay = if self.config.jitter {
            // Add jitter: 50-100% of the calculated backoff
            let jitter = rand::thread_rng().gen_range(0.5..1.0);
            capped * jitter
        } else {
            capped
        };

        Duration::from_secs_f64(delay)
    }

    /// Get the retry configuration
    pub fn config(&self) -> &RetryConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SyncError;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // Test 1: Success on first attempt returns immediately
    #[tokio::test]
    async fn test_success_on_first_attempt() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 3,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let result: Result<&str, SyncError> = manager
            .execute(|| {
                let count = call_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok("success")
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    // Test 2: Retries on transient error and eventually succeeds
    #[tokio::test]
    async fn test_retry_succeeds_after_transient_failure() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 3,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<&str, SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    let current = count.fetch_add(1, Ordering::SeqCst);
                    if current < 2 {
                        Err(SyncError::NetworkTimeout) // First 2 attempts fail
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    // Test 3: Gives up after max retries
    #[tokio::test]
    async fn test_gives_up_after_max_retries() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 2,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<(), SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Err(SyncError::NetworkTimeout)
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SyncError::NetworkTimeout);
        // Initial attempt + max_retries
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    // Test 4: Non-retryable error returns immediately
    #[tokio::test]
    async fn test_non_retryable_error_returns_immediately() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 5,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<(), SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Err(SyncError::NotFound) // Non-retryable
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SyncError::NotFound);
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    // Test 5: Exponential backoff calculation without jitter
    #[test]
    fn test_exponential_backoff_calculation() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 5,
            initial_backoff_secs: 5,
            max_backoff_secs: 300,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        // Attempt 0: 5 * 2^0 = 5
        assert_eq!(manager.calculate_backoff(0), Duration::from_secs(5));

        // Attempt 1: 5 * 2^1 = 10
        assert_eq!(manager.calculate_backoff(1), Duration::from_secs(10));

        // Attempt 2: 5 * 2^2 = 20
        assert_eq!(manager.calculate_backoff(2), Duration::from_secs(20));

        // Attempt 3: 5 * 2^3 = 40
        assert_eq!(manager.calculate_backoff(3), Duration::from_secs(40));
    }

    // Test 6: Backoff is capped at max_backoff
    #[test]
    fn test_backoff_capped_at_max() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 10,
            initial_backoff_secs: 10,
            max_backoff_secs: 60,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        // Attempt 5: 10 * 2^5 = 320, but capped at 60
        assert_eq!(manager.calculate_backoff(5), Duration::from_secs(60));

        // Attempt 10: should still be capped at 60
        assert_eq!(manager.calculate_backoff(10), Duration::from_secs(60));
    }

    // Test 7: Jitter reduces backoff to 50-100% range
    #[test]
    fn test_jitter_within_range() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 3,
            initial_backoff_secs: 10,
            max_backoff_secs: 300,
            backoff_multiplier: 2.0,
            jitter: true,
        });

        // Run multiple times to verify jitter
        for _ in 0..100 {
            let backoff = manager.calculate_backoff(0);
            // Without jitter: 10 seconds
            // With jitter: 5-10 seconds (50-100%)
            assert!(
                backoff >= Duration::from_secs(5) && backoff <= Duration::from_secs(10),
                "Backoff {:?} should be between 5-10 seconds",
                backoff
            );
        }
    }

    // Test 8: Rate limited error is retryable
    #[tokio::test]
    async fn test_rate_limited_error_is_retried() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 2,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<&str, SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    let current = count.fetch_add(1, Ordering::SeqCst);
                    if current < 1 {
                        Err(SyncError::RateLimited(60)) // First attempt fails with rate limit
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    // Test 9: Server 5xx errors are retried
    #[tokio::test]
    async fn test_server_5xx_error_is_retried() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 2,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<&str, SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    let current = count.fetch_add(1, Ordering::SeqCst);
                    if current < 1 {
                        Err(SyncError::ServerError(503)) // First attempt fails
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    // Test 10: Default configuration
    #[test]
    fn test_default_configuration() {
        let manager = RetryManager::with_defaults();
        let config = manager.config();

        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff_secs, 5);
        assert_eq!(config.max_backoff_secs, 300);
        assert!((config.backoff_multiplier - 2.0).abs() < f64::EPSILON);
        assert!(config.jitter);
    }

    // Test 11: Connection refused is retried
    #[tokio::test]
    async fn test_connection_refused_is_retried() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 1,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<&str, SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    let current = count.fetch_add(1, Ordering::SeqCst);
                    if current < 1 {
                        Err(SyncError::ConnectionRefused)
                    } else {
                        Ok("connected")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(attempt_count.load(Ordering::SeqCst), 2);
    }

    // Test 12: Zero max_retries still allows initial attempt
    #[tokio::test]
    async fn test_zero_max_retries() {
        let manager = RetryManager::new(RetryConfig {
            max_retries: 0,
            initial_backoff_secs: 0,
            max_backoff_secs: 0,
            backoff_multiplier: 2.0,
            jitter: false,
        });

        let attempt_count = Arc::new(AtomicU32::new(0));
        let attempt_count_clone = attempt_count.clone();

        let result: Result<(), SyncError> = manager
            .execute(|| {
                let count = attempt_count_clone.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Err(SyncError::NetworkTimeout)
                }
            })
            .await;

        assert!(result.is_err());
        // Only the initial attempt, no retries
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }
}
