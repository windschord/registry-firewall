//! Database migrations for registry-firewall
//!
//! This module contains SQL migrations for the SQLite database schema.

/// SQL statement to create the initial database schema
pub const CREATE_SCHEMA: &str = r#"
-- Blocked packages table
CREATE TABLE IF NOT EXISTS blocked_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT,
    severity TEXT,
    advisory_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ecosystem, package, version, source)
);

CREATE INDEX IF NOT EXISTS idx_blocked_eco_pkg ON blocked_packages(ecosystem, package);
CREATE INDEX IF NOT EXISTS idx_blocked_source ON blocked_packages(source);

-- Sync status table
CREATE TABLE IF NOT EXISTS sync_status (
    source TEXT PRIMARY KEY,
    last_sync_at DATETIME,
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    records_count INTEGER DEFAULT 0
);

-- API tokens table
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    allowed_ecosystems TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    is_revoked INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash);

-- Block logs table
CREATE TABLE IF NOT EXISTS block_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    client_id TEXT,
    client_ip TEXT,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_block_logs_time ON block_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_block_logs_eco_pkg ON block_logs(ecosystem, package);

-- Custom block rules table
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem TEXT NOT NULL,
    package_pattern TEXT NOT NULL,
    version_constraint TEXT NOT NULL,
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_ecosystem ON custom_rules(ecosystem);
"#;

/// Get the migration version
pub fn migration_version() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_create_schema_valid_sql() {
        // Create an in-memory SQLite database
        let conn = Connection::open_in_memory().unwrap();

        // Execute the schema creation
        conn.execute_batch(CREATE_SCHEMA).unwrap();

        // Verify tables were created
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();

        assert!(tables.contains(&"blocked_packages".to_string()));
        assert!(tables.contains(&"sync_status".to_string()));
        assert!(tables.contains(&"api_tokens".to_string()));
        assert!(tables.contains(&"block_logs".to_string()));
        assert!(tables.contains(&"custom_rules".to_string()));
    }

    #[test]
    fn test_blocked_packages_unique_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();

        // Insert first record
        conn.execute(
            "INSERT INTO blocked_packages (ecosystem, package, version, source) VALUES (?, ?, ?, ?)",
            ["pypi", "test", "1.0.0", "osv"],
        ).unwrap();

        // Try to insert duplicate - should fail
        let result = conn.execute(
            "INSERT INTO blocked_packages (ecosystem, package, version, source) VALUES (?, ?, ?, ?)",
            ["pypi", "test", "1.0.0", "osv"],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_api_tokens_hash_unique() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(CREATE_SCHEMA).unwrap();

        // Insert first token
        conn.execute(
            "INSERT INTO api_tokens (id, name, token_hash) VALUES (?, ?, ?)",
            ["id1", "token1", "hash123"],
        )
        .unwrap();

        // Try to insert duplicate hash - should fail
        let result = conn.execute(
            "INSERT INTO api_tokens (id, name, token_hash) VALUES (?, ?, ?)",
            ["id2", "token2", "hash123"],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_migration_version() {
        assert_eq!(migration_version(), 1);
    }
}
