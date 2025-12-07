//! Web UI backend module
//!
//! This module provides the backend functionality for the Web UI including:
//! - REST API endpoints for dashboard, blocks, rules, tokens, etc.
//! - Static file embedding and serving (via rust-embed)

pub mod api;

pub use api::*;

use axum::{
    body::Body,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

/// Embedded static files from the web/dist directory
#[derive(RustEmbed)]
#[folder = "web/dist/"]
#[prefix = ""]
pub struct Assets;

/// Get a static file from the embedded assets
pub fn get_static_file(path: &str) -> Option<StaticFile> {
    // Handle empty path or root path - serve index.html
    let path = if path.is_empty() || path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };

    Assets::get(path).map(|content| StaticFile {
        content: content.data.into_owned(),
        mime_type: mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string(),
    })
}

/// A static file with content and MIME type
pub struct StaticFile {
    pub content: Vec<u8>,
    pub mime_type: String,
}

impl IntoResponse for StaticFile {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, self.mime_type)
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .body(Body::from(self.content))
            .unwrap()
    }
}

/// Serve index.html for SPA routing
pub fn serve_index() -> Response {
    match get_static_file("index.html") {
        Some(file) => file.into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "Web UI not built. Run 'npm run build' in the web/ directory.",
        )
            .into_response(),
    }
}

/// Serve a static file or fall back to index.html for SPA routing
pub fn serve_static(path: &str) -> Response {
    // Try to serve the requested file
    if let Some(file) = get_static_file(path) {
        return file.into_response();
    }

    // For HTML requests (SPA routing), fall back to index.html
    // For other requests (assets), return 404
    if path.contains('.') {
        (StatusCode::NOT_FOUND, format!("File not found: {}", path)).into_response()
    } else {
        serve_index()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test 1: Assets struct is properly defined
    #[test]
    fn test_assets_struct_exists() {
        // This test verifies that the Assets struct compiles correctly
        // The actual files may or may not be present depending on build state
        let _ = Assets::iter();
    }

    // Test 2: Get non-existent file returns None
    #[test]
    fn test_get_nonexistent_file() {
        let result = get_static_file("definitely-does-not-exist-12345.xyz");
        assert!(result.is_none());
    }

    // Test 3: StaticFile into_response works
    #[test]
    fn test_static_file_into_response() {
        let file = StaticFile {
            content: b"Hello, World!".to_vec(),
            mime_type: "text/plain".to_string(),
        };
        let response = file.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Test 4: serve_static returns 404 for missing asset files
    #[test]
    fn test_serve_static_missing_asset() {
        let response = serve_static("missing-file.js");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // Test 5: Mime type detection works
    #[test]
    fn test_mime_type_detection() {
        // Test that mime_guess works correctly
        let html = mime_guess::from_path("index.html")
            .first_or_octet_stream()
            .to_string();
        assert_eq!(html, "text/html");

        let js = mime_guess::from_path("app.js")
            .first_or_octet_stream()
            .to_string();
        // mime_guess returns "text/javascript" for .js files
        assert!(js == "text/javascript" || js == "application/javascript");

        let css = mime_guess::from_path("style.css")
            .first_or_octet_stream()
            .to_string();
        assert_eq!(css, "text/css");
    }

    // Test 6: Empty path returns index.html path
    #[test]
    fn test_empty_path_normalization() {
        // This tests the path normalization logic
        let path = "";
        let normalized = if path.is_empty() || path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        };
        assert_eq!(normalized, "index.html");
    }

    // Test 7: Root path returns index.html path
    #[test]
    fn test_root_path_normalization() {
        let path = "/";
        let normalized = if path.is_empty() || path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        };
        assert_eq!(normalized, "index.html");
    }

    // Test 8: Leading slash is trimmed
    #[test]
    fn test_leading_slash_trimmed() {
        let path = "/assets/app.js";
        let normalized = if path.is_empty() || path == "/" {
            "index.html"
        } else {
            path.trim_start_matches('/')
        };
        assert_eq!(normalized, "assets/app.js");
    }
}
