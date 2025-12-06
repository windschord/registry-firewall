//! Token generation and verification
//!
//! This module provides functions for generating, hashing, and verifying API tokens.
//! Tokens use the `rf_` prefix followed by 32 bytes of random data encoded in URL-safe Base64.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::rngs::OsRng;

/// Token prefix for registry-firewall tokens
pub const TOKEN_PREFIX: &str = "rf_";

/// Length of the random part of the token in bytes
const TOKEN_RANDOM_BYTES: usize = 32;

/// Generate a new API token
///
/// The token format is: `rf_` + Base64-encoded 32 random bytes
/// The raw token should be shown to the user only once at creation time.
///
/// # Returns
///
/// A tuple of (raw_token, token_id) where:
/// - `raw_token`: The full token string (e.g., `rf_AbCdEf...`) to give to the user
/// - `token_id`: A unique identifier for the token
///
/// # Example
///
/// ```
/// use registry_firewall::auth::token::generate_token;
///
/// let (raw_token, token_id) = generate_token();
/// assert!(raw_token.starts_with("rf_"));
/// ```
pub fn generate_token() -> (String, String) {
    let mut random_bytes = [0u8; TOKEN_RANDOM_BYTES];
    getrandom(&mut random_bytes);

    let encoded = URL_SAFE_NO_PAD.encode(random_bytes);
    let raw_token = format!("{}{}", TOKEN_PREFIX, encoded);

    // Generate a unique token ID
    let mut id_bytes = [0u8; 16];
    getrandom(&mut id_bytes);
    let token_id = URL_SAFE_NO_PAD.encode(id_bytes);

    (raw_token, token_id)
}

/// Fill a byte slice with random bytes using OsRng
fn getrandom(dest: &mut [u8]) {
    use rand::RngCore;
    OsRng.fill_bytes(dest);
}

/// Hash a token using Argon2id
///
/// This function should be used to hash tokens before storing them in the database.
/// The hash includes a random salt and uses secure parameters.
///
/// # Arguments
///
/// * `token` - The raw token to hash
///
/// # Returns
///
/// The Argon2id hash string (PHC format)
///
/// # Errors
///
/// Returns an error if hashing fails (should not happen in normal operation)
///
/// # Example
///
/// ```
/// use registry_firewall::auth::token::{generate_token, hash_token};
///
/// let (raw_token, _) = generate_token();
/// let hash = hash_token(&raw_token).unwrap();
/// assert!(hash.starts_with("$argon2id$"));
/// ```
pub fn hash_token(token: &str) -> Result<String, HashError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(token.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| HashError::HashFailed(e.to_string()))
}

/// Verify a token against a stored hash
///
/// This function should be used to verify tokens during authentication.
///
/// # Arguments
///
/// * `token` - The raw token to verify
/// * `hash` - The stored Argon2id hash
///
/// # Returns
///
/// `true` if the token matches the hash, `false` otherwise
///
/// # Example
///
/// ```
/// use registry_firewall::auth::token::{generate_token, hash_token, verify_token};
///
/// let (raw_token, _) = generate_token();
/// let hash = hash_token(&raw_token).unwrap();
/// assert!(verify_token(&raw_token, &hash));
/// assert!(!verify_token("wrong_token", &hash));
/// ```
pub fn verify_token(token: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Check if a token has the correct format
///
/// Valid tokens start with `rf_` and have a base64-encoded body.
///
/// # Arguments
///
/// * `token` - The token to validate
///
/// # Returns
///
/// `true` if the token format is valid, `false` otherwise
pub fn is_valid_token_format(token: &str) -> bool {
    if !token.starts_with(TOKEN_PREFIX) {
        return false;
    }

    let body = &token[TOKEN_PREFIX.len()..];
    if body.is_empty() {
        return false;
    }

    // Check if the body is valid URL-safe Base64
    URL_SAFE_NO_PAD.decode(body).is_ok()
}

/// Error type for token hashing operations
#[derive(Debug, Clone, PartialEq)]
pub enum HashError {
    /// Hashing failed
    HashFailed(String),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashError::HashFailed(msg) => write!(f, "Hash failed: {}", msg),
        }
    }
}

impl std::error::Error for HashError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: generate_token creates token with rf_ prefix
    #[test]
    fn test_generate_token_has_prefix() {
        let (token, _id) = generate_token();
        assert!(
            token.starts_with(TOKEN_PREFIX),
            "Token should start with 'rf_'"
        );
    }

    // Test 2: generate_token creates unique tokens
    #[test]
    fn test_generate_token_is_unique() {
        let (token1, id1) = generate_token();
        let (token2, id2) = generate_token();

        assert_ne!(token1, token2, "Generated tokens should be unique");
        assert_ne!(id1, id2, "Generated token IDs should be unique");
    }

    // Test 3: generate_token creates tokens of correct length
    #[test]
    fn test_generate_token_length() {
        let (token, _) = generate_token();

        // rf_ (3 chars) + base64(32 bytes) = 3 + 43 = 46 chars
        let body = &token[TOKEN_PREFIX.len()..];
        let decoded = URL_SAFE_NO_PAD.decode(body).unwrap();
        assert_eq!(
            decoded.len(),
            TOKEN_RANDOM_BYTES,
            "Token should contain {} random bytes",
            TOKEN_RANDOM_BYTES
        );
    }

    // Test 4: hash_token produces argon2id hash
    #[test]
    fn test_hash_token_argon2id() {
        let (token, _) = generate_token();
        let hash = hash_token(&token).unwrap();

        assert!(
            hash.starts_with("$argon2id$"),
            "Hash should be in Argon2id format"
        );
    }

    // Test 5: hash_token produces different hashes for same token (due to salt)
    #[test]
    fn test_hash_token_unique_salts() {
        let (token, _) = generate_token();
        let hash1 = hash_token(&token).unwrap();
        let hash2 = hash_token(&token).unwrap();

        assert_ne!(
            hash1, hash2,
            "Same token should produce different hashes due to different salts"
        );
    }

    // Test 6: verify_token succeeds for matching token
    #[test]
    fn test_verify_token_success() {
        let (token, _) = generate_token();
        let hash = hash_token(&token).unwrap();

        assert!(verify_token(&token, &hash), "Verification should succeed");
    }

    // Test 7: verify_token fails for wrong token
    #[test]
    fn test_verify_token_wrong_token() {
        let (token, _) = generate_token();
        let hash = hash_token(&token).unwrap();

        assert!(
            !verify_token("rf_wrong_token", &hash),
            "Verification should fail for wrong token"
        );
    }

    // Test 8: verify_token fails for invalid hash format
    #[test]
    fn test_verify_token_invalid_hash() {
        let (token, _) = generate_token();

        assert!(
            !verify_token(&token, "not_a_valid_hash"),
            "Verification should fail for invalid hash format"
        );
    }

    // Test 9: is_valid_token_format accepts valid tokens
    #[test]
    fn test_is_valid_token_format_valid() {
        let (token, _) = generate_token();
        assert!(
            is_valid_token_format(&token),
            "Generated token should have valid format"
        );
    }

    // Test 10: is_valid_token_format rejects tokens without prefix
    #[test]
    fn test_is_valid_token_format_no_prefix() {
        assert!(
            !is_valid_token_format("abc123"),
            "Token without rf_ prefix should be invalid"
        );
    }

    // Test 11: is_valid_token_format rejects empty body
    #[test]
    fn test_is_valid_token_format_empty_body() {
        assert!(
            !is_valid_token_format("rf_"),
            "Token with empty body should be invalid"
        );
    }

    // Test 12: is_valid_token_format rejects invalid base64
    #[test]
    fn test_is_valid_token_format_invalid_base64() {
        assert!(
            !is_valid_token_format("rf_!!!invalid!!!"),
            "Token with invalid base64 body should be invalid"
        );
    }

    // Test 13: token_id is unique and has reasonable length
    #[test]
    fn test_token_id_format() {
        let (_, id) = generate_token();

        // ID should be base64-encoded 16 bytes = 22 characters
        let decoded = URL_SAFE_NO_PAD.decode(&id).unwrap();
        assert_eq!(decoded.len(), 16, "Token ID should be 16 bytes");
    }
}
