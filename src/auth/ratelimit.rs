//! Rate limiter for authentication failures
//!
//! This module provides IP-based rate limiting for authentication failures.
//! After a configurable number of failed attempts, an IP is blocked for a
//! configurable duration.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Configuration for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of failed attempts before blocking
    pub max_failures: u32,

    /// Duration to block an IP after max failures
    pub block_duration: Duration,

    /// Duration after which failure count resets (sliding window)
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_failures: 10,
            block_duration: Duration::from_secs(300), // 5 minutes
            window_duration: Duration::from_secs(600), // 10 minutes
        }
    }
}

/// Entry tracking failures for an IP address
#[derive(Debug, Clone)]
struct FailureEntry {
    /// Number of failures in the current window
    count: u32,

    /// First failure timestamp
    first_failure: Instant,

    /// Block start timestamp (if blocked)
    blocked_at: Option<Instant>,
}

impl FailureEntry {
    fn new() -> Self {
        Self {
            count: 0, // Start at 0, will be incremented by record_failure
            first_failure: Instant::now(),
            blocked_at: None,
        }
    }
}

/// Rate limiter for authentication failures
///
/// Thread-safe rate limiter that tracks failed authentication attempts per IP.
pub struct RateLimiter {
    config: RateLimitConfig,
    entries: RwLock<HashMap<IpAddr, FailureEntry>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new rate limiter with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Record a failed authentication attempt for an IP
    ///
    /// Returns `true` if the IP is now blocked
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        let mut entries = self.entries.write().unwrap();
        let now = Instant::now();

        let entry = entries.entry(ip).or_insert_with(FailureEntry::new);

        // If already blocked, check if block has expired
        if let Some(blocked_at) = entry.blocked_at {
            if now.duration_since(blocked_at) >= self.config.block_duration {
                // Block expired, reset entry
                *entry = FailureEntry::new();
            } else {
                // Still blocked
                return true;
            }
        }

        // Check if window has expired
        if now.duration_since(entry.first_failure) >= self.config.window_duration {
            // Window expired, reset entry
            *entry = FailureEntry::new();
        } else {
            // Increment failure count
            entry.count += 1;
        }

        // Check if should be blocked
        if entry.count >= self.config.max_failures {
            entry.blocked_at = Some(now);
            true
        } else {
            false
        }
    }

    /// Check if an IP is currently blocked
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let entries = self.entries.read().unwrap();
        let now = Instant::now();

        if let Some(entry) = entries.get(&ip) {
            if let Some(blocked_at) = entry.blocked_at {
                // Check if block has expired
                return now.duration_since(blocked_at) < self.config.block_duration;
            }
        }

        false
    }

    /// Reset the failure count for an IP (e.g., after successful login)
    pub fn reset(&self, ip: IpAddr) {
        let mut entries = self.entries.write().unwrap();
        entries.remove(&ip);
    }

    /// Get the number of failures for an IP
    ///
    /// Returns 0 if no failures recorded or window has expired
    pub fn get_failure_count(&self, ip: IpAddr) -> u32 {
        let entries = self.entries.read().unwrap();
        let now = Instant::now();

        if let Some(entry) = entries.get(&ip) {
            // Check if window has expired
            if now.duration_since(entry.first_failure) >= self.config.window_duration {
                return 0;
            }
            return entry.count;
        }

        0
    }

    /// Get remaining block time for an IP
    ///
    /// Returns `None` if not blocked, otherwise returns the remaining duration
    pub fn remaining_block_time(&self, ip: IpAddr) -> Option<Duration> {
        let entries = self.entries.read().unwrap();
        let now = Instant::now();

        if let Some(entry) = entries.get(&ip) {
            if let Some(blocked_at) = entry.blocked_at {
                let elapsed = now.duration_since(blocked_at);
                if elapsed < self.config.block_duration {
                    return Some(self.config.block_duration - elapsed);
                }
            }
        }

        None
    }

    /// Clean up expired entries
    ///
    /// Should be called periodically to free memory
    pub fn cleanup(&self) {
        let mut entries = self.entries.write().unwrap();
        let now = Instant::now();

        entries.retain(|_, entry| {
            // Keep if blocked and block hasn't expired
            if let Some(blocked_at) = entry.blocked_at {
                if now.duration_since(blocked_at) < self.config.block_duration {
                    return true;
                }
            }

            // Keep if window hasn't expired
            now.duration_since(entry.first_failure) < self.config.window_duration
        });
    }

    /// Get current number of tracked IPs
    pub fn tracked_ips_count(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn test_ip2() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
    }

    // Test 1: New rate limiter is empty
    #[test]
    fn test_new_rate_limiter_is_empty() {
        let limiter = RateLimiter::with_defaults();
        assert_eq!(limiter.tracked_ips_count(), 0);
    }

    // Test 2: Recording failure increments count
    #[test]
    fn test_record_failure_increments_count() {
        let limiter = RateLimiter::with_defaults();
        let ip = test_ip();

        // First failure
        limiter.record_failure(ip);
        assert_eq!(limiter.get_failure_count(ip), 1);

        // Second failure
        limiter.record_failure(ip);
        assert_eq!(limiter.get_failure_count(ip), 2);
    }

    // Test 3: IP not blocked until max failures
    #[test]
    fn test_not_blocked_until_max_failures() {
        let config = RateLimitConfig {
            max_failures: 5,
            block_duration: Duration::from_secs(60),
            window_duration: Duration::from_secs(120),
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Record 4 failures (max is 5)
        for _ in 0..4 {
            let blocked = limiter.record_failure(ip);
            assert!(!blocked, "Should not be blocked before max failures");
        }

        assert!(!limiter.is_blocked(ip));
    }

    // Test 4: IP blocked after max failures
    #[test]
    fn test_blocked_after_max_failures() {
        let config = RateLimitConfig {
            max_failures: 3,
            block_duration: Duration::from_secs(60),
            window_duration: Duration::from_secs(120),
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Record failures until blocked
        for i in 0..3 {
            let blocked = limiter.record_failure(ip);
            if i < 2 {
                assert!(!blocked, "Should not be blocked before max failures");
            } else {
                assert!(blocked, "Should be blocked after max failures");
            }
        }

        assert!(limiter.is_blocked(ip));
    }

    // Test 5: Reset clears failure count
    #[test]
    fn test_reset_clears_failures() {
        let limiter = RateLimiter::with_defaults();
        let ip = test_ip();

        // Record some failures
        limiter.record_failure(ip);
        limiter.record_failure(ip);
        assert!(limiter.get_failure_count(ip) > 0);

        // Reset
        limiter.reset(ip);
        assert_eq!(limiter.get_failure_count(ip), 0);
        assert!(!limiter.is_blocked(ip));
    }

    // Test 6: Different IPs are tracked separately
    #[test]
    fn test_different_ips_tracked_separately() {
        let config = RateLimitConfig {
            max_failures: 3,
            block_duration: Duration::from_secs(60),
            window_duration: Duration::from_secs(120),
        };
        let limiter = RateLimiter::new(config);
        let ip1 = test_ip();
        let ip2 = test_ip2();

        // Block ip1
        for _ in 0..3 {
            limiter.record_failure(ip1);
        }

        assert!(limiter.is_blocked(ip1));
        assert!(!limiter.is_blocked(ip2));
    }

    // Test 7: Remaining block time is calculated correctly
    #[test]
    fn test_remaining_block_time() {
        let config = RateLimitConfig {
            max_failures: 1,
            block_duration: Duration::from_secs(60),
            window_duration: Duration::from_secs(120),
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Not blocked yet
        assert!(limiter.remaining_block_time(ip).is_none());

        // Block the IP
        limiter.record_failure(ip);

        // Should have remaining time
        let remaining = limiter.remaining_block_time(ip);
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_secs(60));
    }

    // Test 8: Cleanup removes expired entries
    #[test]
    fn test_cleanup() {
        let config = RateLimitConfig {
            max_failures: 10,
            block_duration: Duration::from_millis(1),
            window_duration: Duration::from_millis(1),
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        limiter.record_failure(ip);
        assert_eq!(limiter.tracked_ips_count(), 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(5));

        limiter.cleanup();
        assert_eq!(limiter.tracked_ips_count(), 0);
    }

    // Test 9: Default config has expected values
    #[test]
    fn test_default_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_failures, 10);
        assert_eq!(config.block_duration, Duration::from_secs(300));
        assert_eq!(config.window_duration, Duration::from_secs(600));
    }

    // Test 10: is_blocked returns false for unknown IP
    #[test]
    fn test_is_blocked_unknown_ip() {
        let limiter = RateLimiter::with_defaults();
        assert!(!limiter.is_blocked(test_ip()));
    }

    // Test 11: Failure count for unknown IP is zero
    #[test]
    fn test_failure_count_unknown_ip() {
        let limiter = RateLimiter::with_defaults();
        assert_eq!(limiter.get_failure_count(test_ip()), 0);
    }

    // Test 12: Record failure on blocked IP keeps it blocked
    #[test]
    fn test_record_failure_on_blocked_ip() {
        let config = RateLimitConfig {
            max_failures: 1,
            block_duration: Duration::from_secs(60),
            window_duration: Duration::from_secs(120),
        };
        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Block the IP
        let blocked = limiter.record_failure(ip);
        assert!(blocked);
        assert!(limiter.is_blocked(ip));

        // Additional failures should keep it blocked
        let still_blocked = limiter.record_failure(ip);
        assert!(still_blocked);
        assert!(limiter.is_blocked(ip));
    }
}
