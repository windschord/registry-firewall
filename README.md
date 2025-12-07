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

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (no auth required) |
| `GET /metrics` | Prometheus metrics |
| `GET /ui/*` | Web UI static files |
| `GET /api/dashboard` | Dashboard statistics |
| `GET /api/blocks` | Block event logs |
| `GET /api/security-sources` | Security source status |
| `POST /api/security-sources/{name}/sync` | Trigger manual sync |
| `GET /api/cache/stats` | Cache statistics |
| `DELETE /api/cache` | Clear cache |
| `GET/POST/PUT/DELETE /api/rules` | Custom block rules |
| `GET/POST/DELETE /api/tokens` | API token management |

## Configuration

See `configs/config.yaml` for configuration options. Environment variables can be used with `${VAR_NAME}` syntax.

## Documentation

- [Requirements](docs/requirements.md) - Detailed requirements specification
- [Design](docs/design.md) - Technical design document
- [Tasks](docs/tasks.md) - Implementation task list

## License

Apache License 2.0
