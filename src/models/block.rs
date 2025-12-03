//! Block-related domain models
//!
//! This module defines models for blocked packages, block reasons, and severity levels.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for vulnerabilities and blocks
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Unknown severity
    #[default]
    Unknown,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Unknown => write!(f, "UNKNOWN"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "UNKNOWN" => Ok(Severity::Unknown),
            "LOW" => Ok(Severity::Low),
            "MEDIUM" => Ok(Severity::Medium),
            "HIGH" => Ok(Severity::High),
            "CRITICAL" => Ok(Severity::Critical),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

/// Reason for blocking a package
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReason {
    /// Source that identified the block (osv, openssf, custom, minage)
    pub source: String,

    /// Human-readable reason
    pub reason: String,

    /// Severity level
    pub severity: Severity,

    /// Advisory ID (e.g., CVE-2024-1234, GHSA-xxx)
    pub advisory_id: Option<String>,

    /// URL for more information
    pub advisory_url: Option<String>,
}

impl BlockReason {
    /// Create a new block reason
    pub fn new(source: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            reason: reason.into(),
            severity: Severity::Unknown,
            advisory_id: None,
            advisory_url: None,
        }
    }

    /// Set the severity level
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the advisory ID
    pub fn with_advisory_id(mut self, id: impl Into<String>) -> Self {
        self.advisory_id = Some(id.into());
        self
    }

    /// Set the advisory URL
    pub fn with_advisory_url(mut self, url: impl Into<String>) -> Self {
        self.advisory_url = Some(url.into());
        self
    }
}

/// A blocked package record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedPackage {
    /// Database ID (optional, set after insertion)
    pub id: Option<i64>,

    /// Ecosystem (pypi, go, cargo, docker)
    pub ecosystem: String,

    /// Package name
    pub package: String,

    /// Affected version
    pub version: String,

    /// Source that identified the block
    pub source: String,

    /// Human-readable reason
    pub reason: Option<String>,

    /// Severity level
    pub severity: Option<Severity>,

    /// Advisory ID
    pub advisory_id: Option<String>,

    /// When the record was created
    pub created_at: Option<DateTime<Utc>>,
}

impl BlockedPackage {
    /// Create a new blocked package record
    pub fn new(
        ecosystem: impl Into<String>,
        package: impl Into<String>,
        version: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            ecosystem: ecosystem.into(),
            package: package.into(),
            version: version.into(),
            source: source.into(),
            reason: None,
            severity: None,
            advisory_id: None,
            created_at: None,
        }
    }

    /// Set the reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Set the severity
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the advisory ID
    pub fn with_advisory_id(mut self, id: impl Into<String>) -> Self {
        self.advisory_id = Some(id.into());
        self
    }

    /// Convert to BlockReason
    pub fn to_block_reason(&self) -> BlockReason {
        BlockReason {
            source: self.source.clone(),
            reason: self.reason.clone().unwrap_or_else(|| "Blocked".to_string()),
            severity: self.severity.unwrap_or_default(),
            advisory_id: self.advisory_id.clone(),
            advisory_url: None,
        }
    }
}

/// Blocked version information (used in metadata filtering)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedVersion {
    /// The blocked version
    pub version: String,

    /// Reason for blocking
    pub reason: String,
}

impl BlockedVersion {
    /// Create a new blocked version
    pub fn new(version: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            reason: reason.into(),
        }
    }
}

/// Block event log entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockLog {
    /// Database ID (optional, set after insertion)
    pub id: Option<i64>,

    /// When the block occurred
    pub timestamp: DateTime<Utc>,

    /// Client ID (from token)
    pub client_id: Option<String>,

    /// Client IP address
    pub client_ip: Option<String>,

    /// Ecosystem
    pub ecosystem: String,

    /// Package name
    pub package: String,

    /// Package version
    pub version: String,

    /// Source that blocked
    pub source: String,

    /// Reason for blocking
    pub reason: Option<String>,
}

impl BlockLog {
    /// Create a new block log entry
    pub fn new(
        ecosystem: impl Into<String>,
        package: impl Into<String>,
        version: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            timestamp: Utc::now(),
            client_id: None,
            client_ip: None,
            ecosystem: ecosystem.into(),
            package: package.into(),
            version: version.into(),
            source: source.into(),
            reason: None,
        }
    }

    /// Set the client ID
    pub fn with_client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = Some(id.into());
        self
    }

    /// Set the client IP
    pub fn with_client_ip(mut self, ip: impl Into<String>) -> Self {
        self.client_ip = Some(ip.into());
        self
    }

    /// Set the reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Custom block rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomRule {
    /// Database ID (optional, set after insertion)
    pub id: Option<i64>,

    /// Ecosystem (pypi, go, cargo, docker)
    pub ecosystem: String,

    /// Package pattern (supports wildcards like `malicious-*`)
    pub package_pattern: String,

    /// Version constraint (e.g., `>=1.0.0, <2.0.0` or `*` for all)
    pub version_constraint: String,

    /// Reason for blocking
    pub reason: Option<String>,

    /// When the rule was created
    pub created_at: Option<DateTime<Utc>>,

    /// Who created the rule
    pub created_by: Option<String>,
}

impl CustomRule {
    /// Create a new custom rule
    pub fn new(
        ecosystem: impl Into<String>,
        package_pattern: impl Into<String>,
        version_constraint: impl Into<String>,
    ) -> Self {
        Self {
            id: None,
            ecosystem: ecosystem.into(),
            package_pattern: package_pattern.into(),
            version_constraint: version_constraint.into(),
            reason: None,
            created_at: None,
            created_by: None,
        }
    }

    /// Set the reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Set the creator
    pub fn with_created_by(mut self, created_by: impl Into<String>) -> Self {
        self.created_by = Some(created_by.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Unknown < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Unknown.to_string(), "UNKNOWN");
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!("UNKNOWN".parse::<Severity>().unwrap(), Severity::Unknown);
        assert_eq!("low".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("Medium".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);

        assert!("invalid".parse::<Severity>().is_err());
    }

    #[test]
    fn test_severity_serialization() {
        let severity = Severity::High;
        let json = serde_json::to_string(&severity).unwrap();
        assert_eq!(json, r#""HIGH""#);

        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, Severity::High);
    }

    #[test]
    fn test_block_reason_builder() {
        let reason = BlockReason::new("osv", "Remote code execution vulnerability")
            .with_severity(Severity::Critical)
            .with_advisory_id("CVE-2024-1234")
            .with_advisory_url("https://cve.mitre.org/...");

        assert_eq!(reason.source, "osv");
        assert_eq!(reason.reason, "Remote code execution vulnerability");
        assert_eq!(reason.severity, Severity::Critical);
        assert_eq!(reason.advisory_id, Some("CVE-2024-1234".to_string()));
        assert_eq!(
            reason.advisory_url,
            Some("https://cve.mitre.org/...".to_string())
        );
    }

    #[test]
    fn test_blocked_package_builder() {
        let pkg = BlockedPackage::new("pypi", "malicious-pkg", "1.0.0", "openssf")
            .with_reason("Known malware")
            .with_severity(Severity::Critical)
            .with_advisory_id("MAL-2024-001");

        assert_eq!(pkg.ecosystem, "pypi");
        assert_eq!(pkg.package, "malicious-pkg");
        assert_eq!(pkg.version, "1.0.0");
        assert_eq!(pkg.source, "openssf");
        assert_eq!(pkg.reason, Some("Known malware".to_string()));
        assert_eq!(pkg.severity, Some(Severity::Critical));
        assert_eq!(pkg.advisory_id, Some("MAL-2024-001".to_string()));
    }

    #[test]
    fn test_blocked_package_to_block_reason() {
        let pkg = BlockedPackage::new("pypi", "requests", "2.30.0", "osv")
            .with_reason("SQL injection vulnerability")
            .with_severity(Severity::High)
            .with_advisory_id("CVE-2024-5678");

        let reason = pkg.to_block_reason();

        assert_eq!(reason.source, "osv");
        assert_eq!(reason.reason, "SQL injection vulnerability");
        assert_eq!(reason.severity, Severity::High);
        assert_eq!(reason.advisory_id, Some("CVE-2024-5678".to_string()));
    }

    #[test]
    fn test_blocked_version() {
        let bv = BlockedVersion::new("2.31.0", "Contains vulnerability CVE-2024-1234");

        assert_eq!(bv.version, "2.31.0");
        assert_eq!(bv.reason, "Contains vulnerability CVE-2024-1234");

        let json = serde_json::to_string(&bv).unwrap();
        let parsed: BlockedVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(bv, parsed);
    }

    #[test]
    fn test_block_log() {
        let log = BlockLog::new("pypi", "requests", "2.31.0", "osv")
            .with_client_id("client-123")
            .with_client_ip("192.168.1.100")
            .with_reason("Known vulnerability");

        assert_eq!(log.ecosystem, "pypi");
        assert_eq!(log.package, "requests");
        assert_eq!(log.version, "2.31.0");
        assert_eq!(log.source, "osv");
        assert_eq!(log.client_id, Some("client-123".to_string()));
        assert_eq!(log.client_ip, Some("192.168.1.100".to_string()));
        assert_eq!(log.reason, Some("Known vulnerability".to_string()));
    }

    #[test]
    fn test_custom_rule() {
        let rule = CustomRule::new("pypi", "malicious-*", "*")
            .with_reason("Known malware pattern")
            .with_created_by("admin");

        assert_eq!(rule.ecosystem, "pypi");
        assert_eq!(rule.package_pattern, "malicious-*");
        assert_eq!(rule.version_constraint, "*");
        assert_eq!(rule.reason, Some("Known malware pattern".to_string()));
        assert_eq!(rule.created_by, Some("admin".to_string()));

        let json = serde_json::to_string(&rule).unwrap();
        let parsed: CustomRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, parsed);
    }

    #[test]
    fn test_blocked_package_serialization() {
        let pkg = BlockedPackage::new("cargo", "serde", "1.0.100", "osv")
            .with_reason("Test vulnerability")
            .with_severity(Severity::Medium);

        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: BlockedPackage = serde_json::from_str(&json).unwrap();

        assert_eq!(pkg.ecosystem, parsed.ecosystem);
        assert_eq!(pkg.package, parsed.package);
        assert_eq!(pkg.version, parsed.version);
        assert_eq!(pkg.source, parsed.source);
        assert_eq!(pkg.reason, parsed.reason);
        assert_eq!(pkg.severity, parsed.severity);
    }
}
