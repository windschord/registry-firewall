//! Package-related domain models
//!
//! This module defines models for package requests and request types.

use serde::{Deserialize, Serialize};

/// Request type for package operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestType {
    /// Metadata request (package index, version list)
    Metadata,
    /// Package file download request
    Download,
    /// Tag list request (Docker)
    TagList,
    /// Blob request (Docker)
    Blob,
    /// Manifest request (Docker)
    Manifest,
}

/// Parsed package request information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRequest {
    /// Ecosystem name (pypi, go, cargo, docker)
    pub ecosystem: String,

    /// Package name
    pub name: String,

    /// Optional version (None for metadata requests)
    pub version: Option<String>,

    /// Type of request
    pub request_type: RequestType,

    /// Original request path
    pub path: String,
}

impl PackageRequest {
    /// Create a new metadata request
    pub fn metadata(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: None,
            request_type: RequestType::Metadata,
            path: path.into(),
        }
    }

    /// Create a new download request
    pub fn download(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: Some(version.into()),
            request_type: RequestType::Download,
            path: path.into(),
        }
    }

    /// Check if this is a metadata request
    pub fn is_metadata(&self) -> bool {
        self.request_type == RequestType::Metadata
    }

    /// Check if this is a download request
    pub fn is_download(&self) -> bool {
        self.request_type == RequestType::Download
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_request_metadata() {
        let req = PackageRequest::metadata("pypi", "requests", "/pypi/simple/requests/");

        assert_eq!(req.ecosystem, "pypi");
        assert_eq!(req.name, "requests");
        assert_eq!(req.version, None);
        assert_eq!(req.request_type, RequestType::Metadata);
        assert!(req.is_metadata());
        assert!(!req.is_download());
    }

    #[test]
    fn test_package_request_download() {
        let req = PackageRequest::download(
            "pypi",
            "requests",
            "2.31.0",
            "/pypi/packages/requests-2.31.0.tar.gz",
        );

        assert_eq!(req.ecosystem, "pypi");
        assert_eq!(req.name, "requests");
        assert_eq!(req.version, Some("2.31.0".to_string()));
        assert_eq!(req.request_type, RequestType::Download);
        assert!(!req.is_metadata());
        assert!(req.is_download());
    }

    #[test]
    fn test_request_type_serialization() {
        let metadata = RequestType::Metadata;
        let download = RequestType::Download;

        let metadata_json = serde_json::to_string(&metadata).unwrap();
        let download_json = serde_json::to_string(&download).unwrap();

        assert_eq!(metadata_json, r#""metadata""#);
        assert_eq!(download_json, r#""download""#);

        let parsed_metadata: RequestType = serde_json::from_str(&metadata_json).unwrap();
        let parsed_download: RequestType = serde_json::from_str(&download_json).unwrap();

        assert_eq!(parsed_metadata, RequestType::Metadata);
        assert_eq!(parsed_download, RequestType::Download);
    }

    #[test]
    fn test_package_request_serialization() {
        let req = PackageRequest::download("cargo", "serde", "1.0.0", "/cargo/serde/1.0.0");

        let json = serde_json::to_string(&req).unwrap();
        let parsed: PackageRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(req, parsed);
    }

    #[test]
    fn test_all_request_types() {
        let types = vec![
            RequestType::Metadata,
            RequestType::Download,
            RequestType::TagList,
            RequestType::Blob,
            RequestType::Manifest,
        ];

        for t in types {
            let json = serde_json::to_string(&t).unwrap();
            let parsed: RequestType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, parsed);
        }
    }

    #[test]
    fn test_docker_request_types() {
        let manifest_req = PackageRequest {
            ecosystem: "docker".to_string(),
            name: "library/nginx".to_string(),
            version: Some("latest".to_string()),
            request_type: RequestType::Manifest,
            path: "/v2/library/nginx/manifests/latest".to_string(),
        };

        assert_eq!(manifest_req.request_type, RequestType::Manifest);

        let blob_req = PackageRequest {
            ecosystem: "docker".to_string(),
            name: "library/nginx".to_string(),
            version: Some("sha256:abc123".to_string()),
            request_type: RequestType::Blob,
            path: "/v2/library/nginx/blobs/sha256:abc123".to_string(),
        };

        assert_eq!(blob_req.request_type, RequestType::Blob);

        let tag_req = PackageRequest {
            ecosystem: "docker".to_string(),
            name: "library/nginx".to_string(),
            version: None,
            request_type: RequestType::TagList,
            path: "/v2/library/nginx/tags/list".to_string(),
        };

        assert_eq!(tag_req.request_type, RequestType::TagList);
    }
}
