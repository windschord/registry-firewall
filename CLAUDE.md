# CLAUDE.md - AI Assistant Guide for registry-firewall

## Project Overview

**registry-firewall** is an integrated registry proxy designed to protect development environments from software supply chain attacks. It integrates with external security data sources like OSV and OpenSSF Malicious Packages to filter malicious packages and versions. The plugin architecture allows flexible extension for supported languages and security sources.

### Key Goals
- Automatic blocking of malicious packages
- Unified protection across multiple language ecosystems (PyPI, Go, Cargo, Docker)
- Low operational cost with continuous security assurance
- OpenTelemetry-based standard observability
- Intuitive management via Web UI

### Tech Stack
- **Language**: Rust 1.75+ (edition 2021)
- **Async Runtime**: tokio
- **HTTP Framework**: axum
- **Database**: SQLite (rusqlite)
- **Observability**: OpenTelemetry
- **Frontend**: React + TypeScript + Tailwind CSS (embedded via rust-embed)

## Repository Structure

```
registry-firewall/
├── CLAUDE.md              # This file - AI assistant guide
├── Cargo.toml             # Rust dependencies and project config
├── Cargo.lock             # Locked dependency versions
├── LICENSE                # Apache 2.0 License
├── .gitignore             # Git ignore patterns
├── docs/
│   ├── requirements.md    # Detailed requirements (Japanese)
│   ├── design.md          # Technical design document (Japanese)
│   └── tasks.md           # Implementation task list (Japanese)
├── src/
│   ├── main.rs            # Application entry point
│   ├── lib.rs             # Library root
│   ├── error.rs           # Common error types (AppError)
│   ├── config/            # Configuration management
│   │   ├── mod.rs
│   │   └── validation.rs
│   ├── server/            # HTTP server components
│   │   ├── mod.rs
│   │   ├── router.rs      # axum router setup
│   │   └── middleware.rs  # Auth, logging, tracing middleware
│   ├── auth/              # Authentication system
│   │   ├── mod.rs
│   │   ├── manager.rs     # AuthManager implementation
│   │   ├── token.rs       # Token generation/validation
│   │   └── ratelimit.rs   # Rate limiting for auth failures
│   ├── sync/              # Data synchronization infrastructure
│   │   ├── mod.rs
│   │   ├── scheduler.rs   # Auto-sync scheduler with jitter
│   │   ├── retry.rs       # Exponential backoff retry manager
│   │   └── http_client.rs # Rate-limited HTTP client
│   ├── plugins/           # Plugin system
│   │   ├── mod.rs
│   │   ├── registry/      # Registry plugins (PyPI, Go, Cargo, Docker)
│   │   │   ├── mod.rs
│   │   │   ├── traits.rs  # RegistryPlugin trait
│   │   │   ├── pypi.rs
│   │   │   ├── golang.rs
│   │   │   ├── cargo.rs
│   │   │   └── docker.rs
│   │   ├── security/      # Security source plugins
│   │   │   ├── mod.rs
│   │   │   ├── traits.rs  # SecuritySourcePlugin trait
│   │   │   ├── osv.rs     # OSV database integration
│   │   │   ├── openssf.rs # OpenSSF Malicious Packages
│   │   │   ├── custom.rs  # Custom blocklist
│   │   │   └── minage.rs  # Minimum age filter
│   │   └── cache/         # Cache plugins
│   │       ├── mod.rs
│   │       ├── traits.rs  # CachePlugin trait
│   │       ├── filesystem.rs
│   │       └── redis.rs
│   ├── database/          # Database layer
│   │   ├── mod.rs
│   │   ├── sqlite.rs      # SQLite implementation
│   │   └── migrations.rs  # Schema migrations
│   ├── otel/              # OpenTelemetry integration
│   │   └── mod.rs
│   ├── webui/             # Web UI backend
│   │   ├── mod.rs
│   │   └── api.rs         # REST API endpoints
│   └── models/            # Domain models
│       ├── mod.rs
│       ├── package.rs
│       ├── block.rs
│       └── token.rs
├── tests/                 # Integration tests
│   ├── common/mod.rs
│   ├── integration_pypi.rs
│   ├── integration_auth.rs
│   ├── integration_cache.rs
│   └── integration_sync.rs
├── web/                   # React frontend (to be created)
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── configs/               # Configuration files
│   ├── config.yaml
│   └── custom-blocklist.yaml
└── deployments/           # Deployment configurations
    ├── docker/
    │   └── Dockerfile
    └── docker-compose/
        ├── docker-compose.yaml
        └── otel-collector-config.yaml
```

## Development Workflow

### Test-Driven Development (TDD)

This project strictly follows TDD. **All implementation must follow the Red-Green-Refactor cycle:**

1. **Red**: Write a failing test first
2. **Green**: Write minimal implementation to pass the test
3. **Refactor**: Improve code quality while keeping tests green

### Test Coverage Goals
- Domain logic: 90%+
- Infrastructure: 70%+
- Overall: 80%+

### Running Tests

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test error           # Error handling tests
cargo test config          # Configuration tests
cargo test database        # Database tests
cargo test retry           # Retry manager tests
cargo test scheduler       # Sync scheduler tests
cargo test osv             # OSV plugin tests
cargo test pypi            # PyPI plugin tests

# Run integration tests
cargo test --test '*'

# Run with output
cargo test -- --nocapture
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Check without building
cargo check

# Build release
cargo build --release
```

## Key Conventions

### Error Handling

Use `thiserror` for defining errors:

```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    Auth(#[from] AuthError),

    #[error("Plugin error: {0}")]
    Plugin(#[from] PluginError),
    // ...
}
```

### Async Traits

Use `async_trait` for async trait methods:

```rust
#[async_trait]
pub trait SecuritySourcePlugin: Send + Sync {
    fn name(&self) -> &str;
    async fn sync(&self) -> Result<SyncResult, SyncError>;
    // ...
}
```

### Mocking for Tests

Use `mockall` with `#[automock]` attribute:

```rust
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Database: Send + Sync {
    async fn is_blocked(&self, ecosystem: &str, pkg: &str, version: &str)
        -> Result<Option<BlockReason>, DbError>;
}
```

### Configuration

- All configuration via YAML files or environment variables
- Environment variable expansion supported: `${VAR_NAME}`
- See `docs/design.md` for full config structure

### API Token Format

- Prefix: `rf_`
- 32 bytes random (Base64 encoded)
- Hashed with argon2id for storage

## Plugin Architecture

### Registry Plugins

Implement `RegistryPlugin` trait for new package registries:

```rust
#[async_trait]
pub trait RegistryPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn path_prefix(&self) -> &str;
    fn parse_request(&self, req: &Request<Body>) -> Result<PackageRequest, ParseError>;
    async fn handle_request(&self, ctx: RequestContext, req: Request<Body>)
        -> Result<Response<Body>, ProxyError>;
    fn filter_metadata(&self, metadata: &[u8], blocked: &[BlockedVersion])
        -> Result<Vec<u8>, FilterError>;
    fn cache_key(&self, pkg: &str, version: &str) -> String;
}
```

### Security Source Plugins

Implement `SecuritySourcePlugin` trait for new security data sources:

```rust
#[async_trait]
pub trait SecuritySourcePlugin: Send + Sync {
    fn name(&self) -> &str;
    fn supported_ecosystems(&self) -> &[String];
    async fn sync(&self) -> Result<SyncResult, SyncError>;
    fn sync_interval(&self) -> Duration;
    fn sync_status(&self) -> SyncStatus;
    async fn check_package(&self, ecosystem: &str, pkg: &str, version: &str)
        -> Option<BlockReason>;
}
```

### Cache Plugins

Implement `CachePlugin` trait for new cache backends:

```rust
#[async_trait]
pub trait CachePlugin: Send + Sync {
    fn name(&self) -> &str;
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError>;
    async fn set(&self, key: &str, data: Bytes, meta: CacheMeta) -> Result<(), CacheError>;
    async fn delete(&self, key: &str) -> Result<(), CacheError>;
    async fn stats(&self) -> CacheStats;
    async fn purge(&self) -> Result<(), CacheError>;
}
```

## Key Dependencies

```toml
# Core
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["macros"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# Database
rusqlite = { version = "0.31", features = ["bundled"] }
tokio-rusqlite = "0.5"

# HTTP Client
reqwest = { version = "0.12", features = ["json", "gzip"] }

# OpenTelemetry
opentelemetry = "0.22"
opentelemetry-otlp = "0.15"
tracing = "0.1"
tracing-opentelemetry = "0.23"

# Security
argon2 = "0.5"
semver = "1"

# Error handling
thiserror = "1"
anyhow = "1"

# Testing
mockall = "0.12"
axum-test = "14"
wiremock = "0.6"
tempfile = "3"
```

## HTTP Endpoints

### Proxy Endpoints
- `GET /pypi/*` - PyPI Simple API proxy
- `GET /go/*` - Go Module proxy
- `GET /cargo/*` - Cargo Sparse Index proxy
- `GET /v2/*` - Docker Registry v2 proxy

### Management Endpoints
- `GET /health` - Health check (no auth)
- `GET /metrics` - Prometheus metrics (no auth)
- `GET /ui/*` - Web UI static files
- `GET/POST/PUT/DELETE /api/*` - Management API

### API Endpoints
- `GET /api/dashboard` - Dashboard statistics
- `GET /api/blocks` - Block event logs
- `GET /api/security-sources` - Security source status
- `POST /api/security-sources/{name}/sync` - Manual sync trigger
- `GET /api/cache/stats` - Cache statistics
- `DELETE /api/cache` - Clear cache
- `GET/POST/PUT/DELETE /api/rules` - Custom block rules
- `GET/POST/DELETE /api/tokens` - API token management

## Database Schema

Main tables in SQLite:
- `blocked_packages` - Packages blocked by security sources
- `sync_status` - Security source sync state
- `api_tokens` - Client API tokens (hashed)
- `block_logs` - Block event audit log
- `custom_rules` - User-defined block rules

## Implementation Status

Current status: **Pre-implementation phase**

The repository contains comprehensive design documents but no source code yet. Implementation should follow the phased approach in `docs/tasks.md`:

1. Phase 1: Project foundation (Cargo.toml, directory structure)
2. Phase 2: Core infrastructure (config, models, database)
3. Phase 3: Sync infrastructure (retry, rate-limit, scheduler)
4. Phase 4: Security source plugins (OSV, OpenSSF, custom)
5. Phase 5: Cache layer
6. Phase 6: Registry plugins (PyPI, Go, Cargo, Docker)
7. Phase 7: Authentication
8. Phase 8: HTTP server
9. Phase 9: OpenTelemetry integration
10. Phase 10: Web UI
11. Phase 11: Integration and deployment

## Important Notes for AI Assistants

### When implementing features:
1. **Always write tests first** (TDD)
2. **Use the trait-based plugin architecture** as defined in design.md
3. **Follow the phased implementation plan** in tasks.md
4. **Keep modules decoupled** - use dependency injection via traits
5. **Apply exponential backoff** for external API calls
6. **Respect rate limits** for security data sources

### Security considerations:
- Never log sensitive tokens
- Hash all stored credentials with argon2id
- Use TLS 1.2+ for upstream connections
- Validate all user input
- Apply rate limiting on auth failures

### Performance targets:
- Cache hit response: <50ms
- Cache miss response: upstream latency + <100ms
- Security DB check: <1ms
- Auth token validation: <0.5ms
- Memory usage (idle): <256MB

### Documentation language:
The documentation in `docs/` is written in Japanese. Key terms:
- エコシステム (ecosystem) - package ecosystem (pypi, go, cargo, docker)
- プラグイン (plugin) - plugin module
- 同期 (sync) - synchronization
- ブロック (block) - blocking malicious packages

## Quick Start (After Implementation)

```bash
# Build the project
cargo build --release

# Run with default config
./target/release/registry-firewall --config configs/config.yaml

# Run with Docker
docker-compose -f deployments/docker-compose/docker-compose.yaml up
```

## Configuration Example

```yaml
server:
  host: "0.0.0.0"
  port: 8080

auth:
  enabled: true
  admin_password: "${ADMIN_PASSWORD}"

registry_plugins:
  pypi:
    enabled: true
    path_prefix: "/pypi"
    upstream: "https://pypi.org"

security_plugins:
  osv:
    enabled: true
    sync_interval_secs: 3600
    ecosystems: ["pypi", "go", "cargo"]

cache:
  plugin: "filesystem"
  filesystem:
    base_path: "/data/cache"
    max_size_gb: 50

database:
  path: "/data/db/registry-firewall.db"

otel:
  enabled: true
  endpoint: "http://otel-collector:4317"
```

## License

Apache License 2.0
