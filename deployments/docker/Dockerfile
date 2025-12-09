# registry-firewall Multi-Stage Dockerfile
#
# This Dockerfile uses a multi-stage build to create a minimal production image.
# Stage 1: Build the Rust application
# Stage 2: Build the web UI (if applicable)
# Stage 3: Create the minimal runtime image

# ==============================================================================
# Stage 1: Build the Rust application
# ==============================================================================
FROM rust:1.75-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only Cargo files first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy source file to build dependencies
RUN mkdir -p src && \
    echo 'fn main() { println!("Dummy"); }' > src/main.rs && \
    echo 'pub fn lib() {}' > src/lib.rs

# Build dependencies (this layer will be cached unless Cargo.toml/lock changes)
RUN cargo build --release && \
    rm -rf src target/release/registry-firewall* target/release/deps/registry_firewall*

# Copy the actual source code
COPY src src/
COPY web web/

# Build the application
RUN cargo build --release

# ==============================================================================
# Stage 2: Create the minimal runtime image
# ==============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd --gid 1000 regfw && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home regfw

# Create necessary directories
RUN mkdir -p /data/cache /data/db /config && \
    chown -R regfw:regfw /data /config

# Copy the binary from builder
COPY --from=builder /app/target/release/registry-firewall /usr/local/bin/registry-firewall

# Copy default configuration
COPY configs/config.yaml /config/config.yaml

# Set ownership
RUN chown regfw:regfw /usr/local/bin/registry-firewall && \
    chmod +x /usr/local/bin/registry-firewall

# Switch to non-root user
USER regfw

# Set working directory
WORKDIR /home/regfw

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/registry-firewall", "--help"] || exit 1

# Environment variables
ENV REGISTRY_FIREWALL_CONFIG=/config/config.yaml \
    RUST_LOG=info

# Default command
CMD ["registry-firewall", "--config", "/config/config.yaml"]
