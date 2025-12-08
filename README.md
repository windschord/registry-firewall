# Registry Firewall

A unified registry proxy that protects development environments from software supply chain attacks. It integrates with external security data sources like OSV and OpenSSF Malicious Packages to filter malicious packages and versions.

## Features

- Automatic blocking of malicious packages
- Unified protection for multiple language ecosystems (PyPI, Go, Cargo, Docker)
- Plugin architecture for extending supported languages and security sources
- Web UI for intuitive management
- OpenTelemetry integration for observability

## Quick Start

### Prerequisites

- Rust 1.75+
- Node.js 18+ (for frontend development)

### Build and Run

```bash
# Build the project
cargo build --release

# Run with configuration
./target/release/registry-firewall --config configs/config.yaml
```

### Docker

```bash
docker-compose -f deployments/docker-compose/docker-compose.yaml up
```

## Frontend Development

The web UI is built with React, TypeScript, and Tailwind CSS, located in the `web/` directory.

### Setup

```bash
cd web
npm install
```

### Development Server

Start the development server with hot reload:

```bash
npm run dev
```

The development server runs at `http://localhost:5173/ui` and proxies API requests to the backend at `http://localhost:8080`.

### Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Build for production (outputs to `dist/`) |
| `npm run lint` | Run ESLint |
| `npm run test` | Run tests in watch mode |
| `npm run test -- --run` | Run tests once |
| `npm run test -- --coverage` | Run tests with coverage report |
| `npm run preview` | Preview production build locally |

### Project Structure

```
web/
├── src/
│   ├── api/          # API client and types
│   ├── pages/        # Page components (Dashboard, BlockLogs, Settings)
│   ├── App.tsx       # Main app with routing
│   └── main.tsx      # Entry point
├── index.html        # HTML template
├── vite.config.ts    # Vite configuration
├── tailwind.config.js # Tailwind CSS configuration
└── tsconfig.json     # TypeScript configuration
```

### Building for Production

The frontend is embedded into the Rust binary using `rust-embed`. To update the embedded UI:

```bash
cd web
npm run build
cd ..
cargo build --release
```

The built assets in `web/dist/` are automatically embedded at compile time.

### Testing

Tests use Vitest with jsdom for DOM testing:

```bash
# Run all tests
npm run test -- --run

# Run with coverage (80% threshold required)
npm run test -- --coverage

# Run specific test file
npm run test -- src/pages/Settings.test.tsx
```

## Backend Development

### Build and Test

```bash
# Run all tests
cargo test

# Run specific module tests
cargo test auth
cargo test database
cargo test pypi

# Check code without building
cargo check

# Format code
cargo fmt

# Run linter
cargo clippy
```

### API Endpoints

All API endpoints (except `/health` and `/metrics`) require authentication via Bearer token or Basic auth.

#### Public Endpoints (No Auth)

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check - returns `{"status": "healthy", "version": "x.x.x"}` |
| `GET /metrics` | Prometheus metrics |

#### Dashboard & Logs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboard` | GET | Dashboard statistics (blocked counts, sync status) |
| `/api/blocks` | GET | Block event logs with pagination |

**GET /api/blocks Query Parameters:**
- `limit` (optional): Number of logs to return (default: 50, max: 1000)
- `offset` (optional): Pagination offset (default: 0)

#### Security Sources

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/security-sources` | GET | List all security sources with sync status |
| `/api/security-sources/{name}/sync` | POST | Trigger manual sync for a source |

#### Cache Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/cache/stats` | GET | Cache statistics (hit rate, size) |
| `/api/cache` | DELETE | Clear all cached data (returns 200) |

#### Custom Block Rules

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/rules` | GET | List all custom block rules |
| `/api/rules` | POST | Create a new rule (returns 201) |
| `/api/rules/{id}` | GET | Get a specific rule |
| `/api/rules/{id}` | PUT | Update a rule |
| `/api/rules/{id}` | DELETE | Delete a rule (returns 204) |

**Rule Schema:**
```json
{
  "ecosystem": "pypi",
  "package_pattern": "malicious-*",
  "version_constraint": "*",
  "reason": "Known malware pattern"
}
```

**Validation:**
- `package_pattern`: Required, max 512 characters
- `version_constraint`: Optional, max 512 characters
- `reason`: Optional, max 1024 characters

#### API Tokens

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tokens` | GET | List all active tokens (masked) |
| `/api/tokens` | POST | Create a new token (returns 201) |
| `/api/tokens/{id}` | DELETE | Revoke a token (returns 204) |

**Create Token Request:**
```json
{
  "name": "my-ci-token",
  "allowed_ecosystems": ["pypi", "cargo"],
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Create Token Response:**
```json
{
  "id": "abc123",
  "name": "my-ci-token",
  "token": "rf_xxxxxxxxxxxxxxxxxxxxxxxx",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-12-31T23:59:59Z"
}
```

> **Security Note:** The full token value is only returned once at creation. Subsequent list operations show only a masked prefix (e.g., `rf_abc1***`).

#### Error Responses

All errors return JSON with an `error` field:

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid input (validation error) |
| 401 | Unauthorized - Missing or invalid authentication |
| 404 | Not Found - Resource does not exist |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error - Server-side error |

```json
{
  "error": "Package pattern cannot be empty"
}
```

## Configuration

See `configs/config.yaml` for configuration options. Environment variables can be used with `${VAR_NAME}` syntax.

## Documentation

- [Requirements](docs/requirements.md) - Detailed requirements specification
- [Design](docs/design.md) - Technical design document
- [Tasks](docs/tasks.md) - Implementation task list

## License

Apache License 2.0
