# 技術設計書: Dual Docker Image Release + Swagger自動生成

## 概要

本ドキュメントは、要件定義書 `docs/sdd/requirements-dual-docker.md` に基づき、registry-firewallに「デュアルDockerイメージリリース」と「OpenAPI仕様の自動生成」機能を追加するための技術設計を定義する。

### トレーサビリティ

本設計書は以下の要件に対応する:
- ストーリーA (REQ-101〜107): 軽量APIのみイメージ
- ストーリーB (REQ-110〜116): フル機能GUI付きイメージ
- ストーリーC (REQ-120〜129): OpenAPI仕様の自動生成
- NFR-101〜NFR-109: 非機能要件

---

## 1. Cargo.toml features設計

**対応要件**: REQ-101, REQ-102, REQ-105, REQ-120

### 1.1 features定義

```toml
[features]
default = ["webui"]
webui = ["dep:rust-embed", "dep:mime_guess"]
swagger-gen = ["dep:utoipa", "dep:utoipa-axum", "dep:utoipa-swagger-ui"]
```

#### 設計根拠

- `default = ["webui"]`: 既存の動作（Web UI有効）を維持する（NFR-107）
- `webui` featureに `rust-embed` と `mime_guess` を移動する（REQ-102）
- `swagger-gen` featureは独立した機能であり、`webui` featureに依存しない
  - swagger.json生成はAPIのみビルドでも実行可能にする（REQ-123）
  - Swagger UI表示は `webui` featureと組み合わせて使用する（REQ-127, REQ-128）

### 1.2 依存クレートの変更

#### Before

```toml
[dependencies]
# Embed static files
rust-embed = "8"
mime_guess = "2"
```

#### After

```toml
[dependencies]
# Embed static files (optional, enabled by "webui" feature)
rust-embed = { version = "8", optional = true }
mime_guess = { version = "2", optional = true }

# OpenAPI specification generation (optional, enabled by "swagger-gen" feature)
utoipa = { version = "4", features = ["axum_extras", "chrono"], optional = true }
utoipa-axum = { version = "0.1", optional = true }
utoipa-swagger-ui = { version = "7", features = ["axum"], optional = true }
```

### 1.3 影響範囲

- `Cargo.toml`: `[features]`セクション追加、`rust-embed`と`mime_guess`をoptional化
- 既存の `cargo test --all-features` は引き続き動作する（制約事項）

---

## 2. モジュール構造の変更設計

**対応要件**: REQ-103, REQ-104, REQ-105, REQ-121, REQ-122

### 2.1 問題の分析

現状の `src/webui/` モジュールは以下の2つの責務を混在している:

| ファイル | 責務 | featureへの依存 |
|---------|------|----------------|
| `src/webui/mod.rs` | 静的ファイル埋め込み・配信（`rust-embed`, `mime_guess`使用） | `webui` feature必須 |
| `src/webui/api.rs` | REST API型定義・ロジック（`DashboardStats`等） | feature不要（常に必要） |

`src/server/router.rs` はすでに `crate::webui::api` をインポートしており、`webui` モジュール全体をcfg(feature)にすると`router.rs`が壊れる。

### 2.2 モジュール再編成方針

`src/webui/api.rs` の内容を `src/api/` に移動し、featureに依存しない独立モジュールとする。

#### ディレクトリ構造（変更後）

```
src/
├── lib.rs              # webui モジュールを cfg(feature = "webui") で条件付き
├── api/                # 新規: API型定義・ロジック（feature非依存）
│   ├── mod.rs          # pub mod types; pub mod handlers; のre-export
│   ├── types.rs        # DashboardStats, BlockLogsResponse等の型定義
│   └── handlers.rs     # build_dashboard_stats等のビジネスロジック
└── webui/              # 静的ファイル配信のみ（cfg(feature = "webui")）
    └── mod.rs          # Assets, serve_index(), serve_static()
```

**注意**: `src/webui/api.rs` の内容は `src/api/` に移動するが、後方互換のため `src/webui/mod.rs` からre-exportは行わない。代わりに `src/server/router.rs` のインポートパスを `crate::api` に変更する。

### 2.3 src/lib.rs の変更

#### Before

```rust
pub mod webui;
```

#### After

```rust
pub mod api;  // feature非依存: REST API型定義とロジック

#[cfg(feature = "webui")]
pub mod webui;  // webui feature時のみ: 静的ファイル配信
```

### 2.4 src/server/router.rs の変更

#### インポート変更

**Before**

```rust
use crate::webui::api::{
    self, BlockLogsQuery, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MAX_PATTERN_LENGTH,
    MAX_REASON_LENGTH, MAX_TOKEN_NAME_LENGTH,
};
```

**After**

```rust
use crate::api::{
    self, BlockLogsQuery, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MAX_PATTERN_LENGTH,
    MAX_REASON_LENGTH, MAX_TOKEN_NAME_LENGTH,
};
```

#### build_router() の変更

**Before**

```rust
pub fn build_router<D: Database + 'static>(state: AppState<D>) -> Router {
    let auth_manager = Arc::clone(&state.auth_manager);

    Router::new()
        // ... 省略 ...
        // Web UI routes
        .route("/ui", get(webui_index_handler))
        .route("/ui/*path", get(webui_static_handler))
        .layer(middleware::from_fn_with_state(
            auth_manager,
            auth_middleware,
        ))
        .with_state(state)
}
```

**After**

```rust
pub fn build_router<D: Database + 'static>(state: AppState<D>) -> Router {
    let auth_manager = Arc::clone(&state.auth_manager);

    let router = Router::new()
        // ... 省略 ...
    ;

    #[cfg(feature = "webui")]
    let router = router
        .route("/ui", get(webui_index_handler))
        .route("/ui/*path", get(webui_static_handler));

    router
        .layer(middleware::from_fn_with_state(
            auth_manager,
            auth_middleware,
        ))
        .with_state(state)
}
```

#### Web UIハンドラの条件付きコンパイル

**Before**

```rust
async fn webui_index_handler() -> impl IntoResponse {
    crate::webui::serve_index()
}
async fn webui_static_handler(Path(path): Path<String>) -> impl IntoResponse {
    crate::webui::serve_static(&path)
}
```

**After**

```rust
#[cfg(feature = "webui")]
async fn webui_index_handler() -> impl IntoResponse {
    crate::webui::serve_index()
}

#[cfg(feature = "webui")]
async fn webui_static_handler(Path(path): Path<String>) -> impl IntoResponse {
    crate::webui::serve_static(&path)
}
```

#### router.rs テストの変更

`test_webui_index_endpoint` と `test_webui_static_endpoint` は `webui` feature時のみ有効。

**After**

```rust
// Test 13: Web UI index endpoint (webui feature only)
#[cfg(feature = "webui")]
#[tokio::test]
async fn test_webui_index_endpoint() {
    // ... 変更なし ...
}

// Test 14: Web UI static files endpoint (webui feature only)
#[cfg(feature = "webui")]
#[tokio::test]
async fn test_webui_static_endpoint() {
    // ... 変更なし ...
}
```

### 2.5 src/webui/mod.rs の変更

`src/webui/mod.rs` からAPIの再エクスポートを削除し、静的ファイル配信機能のみを残す。

**Before**

```rust
pub mod api;

pub use api::*;  // ← 削除

use rust_embed::RustEmbed;
// ...
```

**After**

```rust
// api モジュールは src/api/ に移動したため、ここではインポートしない

use rust_embed::RustEmbed;
// ...（残りは変更なし）
```

---

## 3. Dockerfile変更設計

**対応要件**: REQ-106, REQ-114, REQ-115, REQ-116, NFR-101, NFR-102, NFR-103

### 3.1 マルチステージビルドの再設計

APIのみビルドとフルビルドの両方をサポートするため、Dockerfileを以下の構造に変更する。

#### ステージ構成

```
Stage 1: builder    - Rustバイナリビルド（全パターン共通）
Stage 2: node-build - フロントエンドビルド（fullのみ使用）
Stage 3: runtime    - 最終イメージ（全パターン共通）
```

### 3.2 変更後Dockerfile

```dockerfile
# ==============================================================================
# Build arguments
# ==============================================================================
ARG CARGO_BUILD_FEATURES=""

# ==============================================================================
# Stage 1: Build the Rust application
# ==============================================================================
FROM rust:1-bookworm AS builder

ARG CARGO_BUILD_FEATURES

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

# ダミーソースでの依存キャッシュ（featureフラグを考慮）
RUN mkdir -p src && \
    echo 'fn main() { println!("Dummy"); }' > src/main.rs && \
    echo 'pub fn lib() {}' > src/lib.rs && \
    if [ -n "$CARGO_BUILD_FEATURES" ]; then \
        cargo build --release --features "$CARGO_BUILD_FEATURES"; \
    else \
        cargo build --release --no-default-features; \
    fi && \
    cargo clean -p registry-firewall --release && \
    rm -rf src

COPY src src/

# web/dist はfull buildの場合のみ必要だが、
# COPYはディレクトリが存在しない場合エラーになるため、
# 空ディレクトリを用意する（COPY --if-existsはBuildKit v0.14+で使用可能だが互換性のため回避）
COPY web web/

# featureフラグを使ってビルド
RUN if [ -n "$CARGO_BUILD_FEATURES" ]; then \
        cargo build --release --features "$CARGO_BUILD_FEATURES"; \
    else \
        cargo build --release --no-default-features; \
    fi

# ==============================================================================
# Stage 2: Build the frontend (full build only)
# ==============================================================================
FROM node:20-bookworm-slim AS node-build

WORKDIR /app/web

COPY web/package.json web/package-lock.json ./

RUN npm ci

COPY web/ ./

RUN npm run build

# ==============================================================================
# Stage 3: Create the minimal runtime image
# ==============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 regfw && \
    useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home regfw

RUN mkdir -p /data/cache /data/db /config && \
    chown -R regfw:regfw /data /config

COPY --from=builder /app/target/release/registry-firewall /usr/local/bin/registry-firewall
COPY configs/config.yaml /config/config.yaml

RUN chown regfw:regfw /usr/local/bin/registry-firewall && \
    chmod +x /usr/local/bin/registry-firewall

USER regfw
WORKDIR /home/regfw
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENV REGISTRY_FIREWALL_CONFIG=/config/config.yaml \
    RUST_LOG=info

CMD ["registry-firewall", "--config", "/config/config.yaml"]
```

### 3.3 ビルド引数とfeatureフラグのマッピング

| イメージ種別 | `--build-arg CARGO_BUILD_FEATURES` | cargo buildコマンド |
|------------|-------------------------------------|-------------------|
| APIのみ（デフォルト）| `""` （空文字列） | `cargo build --release --no-default-features` |
| GUI付き（full） | `"webui"` | `cargo build --release --features "webui"` |

#### 設計根拠

- `CARGO_BUILD_FEATURES=""` をデフォルトにすることで、`--no-default-features` が適用される（REQ-102）
- `web/dist/` のコピーは常に行われるが、`webui` feature無効時はRustコードがそれを参照しないため、ビルド成果物に含まれない
- APIのみイメージは `web/dist/` 内容を埋め込まないため、バイナリサイズが小さくなる（NFR-101, NFR-103）

### 3.4 web/dist ディレクトリの扱い

`COPY web web/` は `web/dist/` が存在しない場合でもエラーにならない（ディレクトリ全体をコピーするため）。ただし `webui` feature有効時は `web/dist/` が存在する必要があるため、full buildのDockerfileでは前段のnode-buildステージからコピーする。

**APIのみビルドのDockerfile（docker/Dockerfile）**: `web/dist/` 不要。`COPY web web/` を削除可能。

**GUI付きビルドのDockerfile（docker/Dockerfile.full）**: node-buildステージを使用。

#### 設計決定: Dockerfile分割 vs 単一Dockerfile

単一のDockerfileで両方をサポートするとbuild-argによる条件分岐が複雑になる。以下の設計を採用する:

| ファイル | 用途 |
|---------|------|
| `deployments/docker/Dockerfile` | APIのみビルド（web/ コピーなし、`--no-default-features`） |
| `deployments/docker/Dockerfile.full` | GUI付きビルド（node-buildステージあり、`--features webui`） |

---

## 4. release.yml変更設計

**対応要件**: REQ-110, REQ-111, REQ-112, REQ-113, REQ-115, REQ-124, NFR-104, NFR-105

### 4.1 ジョブ構成

```
test
├── generate-swagger (depends: test)
├── build-docker-api (depends: test)           ← APIのみ
├── build-docker-full (depends: test)          ← GUI付き
└── create-release (depends: test, generate-swagger, build-docker-api, build-docker-full)
```

`build-docker-api` と `build-docker-full` は並列実行される（NFR-105）。

### 4.2 タグ命名規則

#### APIのみイメージのタグ（現在の `latest` の置き換え）

| リリース種別 | タグ |
|------------|------|
| 安定版 `vX.Y.Z` | `latest`, `X.Y.Z`, `X.Y`, `X` |
| プレリリース `vX.Y.Z-alpha` | `X.Y.Z-alpha` のみ（`latest` なし） |

#### GUI付きイメージのタグ

| リリース種別 | タグ |
|------------|------|
| 安定版 `vX.Y.Z` | `latest-full`, `X.Y.Z-full`, `X.Y-full`, `X-full` |
| プレリリース `vX.Y.Z-alpha` | `X.Y.Z-alpha-full` のみ（`latest-full` なし） |

**注意**: `docker/metadata-action` の `type=semver` はハイフンサフィックスを自動でプレリリースと判定し `latest` タグを付与しない（REQ-113）。

### 4.3 変更後 release.yml（抜粋）

#### build-docker-api ジョブ

```yaml
build-docker-api:
  name: Build and Push Docker Image (API only)
  runs-on: ubuntu-latest
  needs: test
  permissions:
    contents: read
    packages: write
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up QEMU
      uses: docker/setup-qemu-action@v3

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Log in to GitHub Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata for API-only image
      id: meta-api
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}},enable=${{ needs.test.outputs.is_prerelease == 'false' }}
          type=semver,pattern={{major}},enable=${{ needs.test.outputs.is_prerelease == 'false' }}
          type=raw,value=latest,enable=${{ needs.test.outputs.is_prerelease == 'false' }}

    - name: Build and push API-only Docker image
      uses: docker/build-push-action@v7
      with:
        context: .
        file: deployments/docker/Dockerfile
        push: true
        tags: ${{ steps.meta-api.outputs.tags }}
        labels: ${{ steps.meta-api.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        platforms: linux/amd64,linux/arm64
```

#### build-docker-full ジョブ

```yaml
build-docker-full:
  name: Build and Push Docker Image (Full with Web UI)
  runs-on: ubuntu-latest
  needs: test
  permissions:
    contents: read
    packages: write
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up QEMU
      uses: docker/setup-qemu-action@v3

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Log in to GitHub Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata for full image
      id: meta-full
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=semver,pattern={{version}}-full
          type=semver,pattern={{major}}.{{minor}}-full,enable=${{ needs.test.outputs.is_prerelease == 'false' }}
          type=semver,pattern={{major}}-full,enable=${{ needs.test.outputs.is_prerelease == 'false' }}
          type=raw,value=latest-full,enable=${{ needs.test.outputs.is_prerelease == 'false' }}

    - name: Build and push full Docker image
      uses: docker/build-push-action@v7
      with:
        context: .
        file: deployments/docker/Dockerfile.full
        push: true
        tags: ${{ steps.meta-full.outputs.tags }}
        labels: ${{ steps.meta-full.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        platforms: linux/amd64,linux/arm64
```

#### generate-swagger ジョブ

```yaml
generate-swagger:
  name: Generate swagger.json
  runs-on: ubuntu-latest
  needs: test
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable

    - name: Cache cargo dependencies
      uses: Swatinem/rust-cache@v2

    - name: Generate swagger.json
      run: cargo run --features swagger-gen -- --generate-swagger

    - name: Upload swagger.json as artifact
      uses: actions/upload-artifact@v4
      with:
        name: swagger-json
        path: swagger.json
```

#### create-release ジョブの変更

```yaml
create-release:
  name: Create GitHub Release
  runs-on: ubuntu-latest
  needs: [test, generate-swagger, build-docker-api, build-docker-full]
  permissions:
    contents: write
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Download swagger.json
      uses: actions/download-artifact@v4
      with:
        name: swagger-json

    - name: Generate release notes
      run: |
        # ... 既存のリリースノート生成ロジック（変更なし） ...

    - name: Create GitHub Release
      uses: softprops/action-gh-release@v2
      with:
        prerelease: ${{ needs.test.outputs.is_prerelease }}
        body_path: release-notes.md
        files: swagger.json  # ← swagger.json をアセットに添付
```

---

## 5. utoipa統合設計

**対応要件**: REQ-120, REQ-121, REQ-122, REQ-123, REQ-125, REQ-126, REQ-127, REQ-128, REQ-129

### 5.1 アノテーション対象エンドポイント一覧

以下のすべての `/api/*` エンドポイントに `#[utoipa::path]` を付与する（REQ-121）。

| ハンドラ関数 | メソッド | パス | 説明 |
|-------------|---------|------|------|
| `api_dashboard_handler` | GET | `/api/dashboard` | ダッシュボード統計取得 |
| `api_blocks_handler` | GET | `/api/blocks` | ブロックログ一覧取得 |
| `api_security_sources_handler` | GET | `/api/security-sources` | セキュリティソース一覧 |
| `api_trigger_sync_handler` | POST | `/api/security-sources/{name}/sync` | 同期トリガー |
| `api_cache_stats_handler` | GET | `/api/cache/stats` | キャッシュ統計取得 |
| `api_cache_clear_handler` | DELETE | `/api/cache` | キャッシュクリア |
| `api_list_rules_handler` | GET | `/api/rules` | カスタムルール一覧 |
| `api_create_rule_handler` | POST | `/api/rules` | カスタムルール作成 |
| `api_get_rule_handler` | GET | `/api/rules/{id}` | カスタムルール取得 |
| `api_update_rule_handler` | PUT | `/api/rules/{id}` | カスタムルール更新 |
| `api_delete_rule_handler` | DELETE | `/api/rules/{id}` | カスタムルール削除 |
| `api_list_tokens_handler` | GET | `/api/tokens` | トークン一覧 |
| `api_create_token_handler` | POST | `/api/tokens` | トークン作成 |
| `api_delete_token_handler` | DELETE | `/api/tokens/{id}` | トークン削除 |

### 5.2 ToSchema derive対象の構造体一覧

以下の構造体に `ToSchema` を追加する（REQ-122）。

`src/api/types.rs`（移動後）:
- `DashboardStats`
- `SecuritySourceSummary`
- `BlockLogsQuery`
- `BlockLogsResponse`
- `BlockLogEntry`
- `SecuritySourcesResponse`
- `SecuritySourceInfo`
- `SyncTriggerResponse`
- `CacheStatsResponse`
- `CacheClearResponse`
- `RulesResponse`
- `TokensResponse`
- `TokenInfo`
- `CreateTokenRequest`
- `CreateTokenResponse`
- `MessageResponse`
- `ErrorResponse`

`src/server/router.rs`:
- `CreateTokenApiRequest`

`src/models/`:
- `CustomRule`（既存モデル）

### 5.3 utoipa アノテーション例

```rust
// src/server/router.rs

#[cfg_attr(feature = "swagger-gen", utoipa::path(
    get,
    path = "/api/dashboard",
    responses(
        (status = 200, description = "Dashboard statistics", body = DashboardStats),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    security(
        ("bearer_token" = []),
        ("basic_auth" = []),
    ),
    tag = "dashboard"
))]
async fn api_dashboard_handler<D: Database + 'static>(
    State(state): State<AppState<D>>,
) -> impl IntoResponse {
    // ...
}
```

`#[cfg_attr(feature = "swagger-gen", utoipa::path(...))]` を使用することで、`swagger-gen` feature無効時はアノテーションがコンパイル対象外になる。

### 5.4 ApiDoc 構造体定義

`src/server/router.rs` または `src/api/openapi.rs`（新規）に配置する。

```rust
#[cfg(feature = "swagger-gen")]
use utoipa::OpenApi;

#[cfg(feature = "swagger-gen")]
#[derive(OpenApi)]
#[openapi(
    info(
        title = "registry-firewall API",
        version = env!("CARGO_PKG_VERSION"),
        description = "A unified registry proxy that protects development environments from software supply chain attacks",
    ),
    paths(
        api_dashboard_handler,
        api_blocks_handler,
        api_security_sources_handler,
        api_trigger_sync_handler,
        api_cache_stats_handler,
        api_cache_clear_handler,
        api_list_rules_handler,
        api_create_rule_handler,
        api_get_rule_handler,
        api_update_rule_handler,
        api_delete_rule_handler,
        api_list_tokens_handler,
        api_create_token_handler,
        api_delete_token_handler,
    ),
    components(
        schemas(
            DashboardStats, SecuritySourceSummary, BlockLogsQuery, BlockLogsResponse,
            BlockLogEntry, SecuritySourcesResponse, SecuritySourceInfo, SyncTriggerResponse,
            CacheStatsResponse, CacheClearResponse, RulesResponse, TokensResponse,
            TokenInfo, CreateTokenRequest, CreateTokenResponse, MessageResponse, ErrorResponse,
            CustomRule, CreateTokenApiRequest,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "dashboard", description = "Dashboard statistics"),
        (name = "blocks", description = "Block log management"),
        (name = "security-sources", description = "Security source management"),
        (name = "cache", description = "Cache management"),
        (name = "rules", description = "Custom block rule management"),
        (name = "tokens", description = "API token management"),
    )
)]
pub struct ApiDoc;

/// Security schemes modifier
#[cfg(feature = "swagger-gen")]
struct SecurityAddon;

#[cfg(feature = "swagger-gen")]
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_token",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("token")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "basic_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Basic)
                    .build(),
            ),
        );
    }
}
```

**対応要件**: REQ-125（OpenAPI 3.0準拠）, REQ-126（タイトル・バージョン・説明文）, REQ-129（BearerToken・Basic認証のsecuritySchemes）

### 5.5 --generate-swagger CLIオプション

`src/main.rs` に `--generate-swagger` オプションを追加する。

#### Argsへの追加

```rust
#[derive(Parser, Debug)]
#[command(name = "registry-firewall")]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, env = "REGISTRY_FIREWALL_CONFIG")]
    config: Option<String>,

    /// Generate OpenAPI specification (swagger.json) and exit
    #[cfg(feature = "swagger-gen")]
    #[arg(long)]
    generate_swagger: bool,
}
```

#### main()への追加

```rust
#[cfg(feature = "swagger-gen")]
if args.generate_swagger {
    use registry_firewall::server::router::ApiDoc;
    use utoipa::OpenApi;
    let spec = ApiDoc::openapi().to_pretty_json().expect("Failed to serialize OpenAPI spec");
    std::fs::write("swagger.json", spec).expect("Failed to write swagger.json");
    eprintln!("swagger.json generated successfully");
    return Ok(());
}
```

**対応要件**: REQ-123（`--generate-swagger` コマンド実行時にswagger.jsonを出力）

### 5.6 Swagger UI エンドポイント

`webui` featureと `swagger-gen` featureが両方有効の場合、`/api/swagger-ui` でインタラクティブなSwagger UIを提供する。

```rust
// src/server/router.rs build_router() 内

#[cfg(all(feature = "webui", feature = "swagger-gen"))]
let router = router.merge(
    utoipa_swagger_ui::SwaggerUi::new("/api/swagger-ui")
        .url("/api/openapi.json", ApiDoc::openapi())
);
```

**対応要件**: REQ-127（webui feature有効時にSwagger UI提供）, REQ-128（webui feature無効時は提供不要）

---

## 6. CI (ci.yml) 変更設計

**対応要件**: REQ-104（`--no-default-features`でのビルド・テスト）

### 6.1 追加ジョブ

既存の `test` ジョブ（`--all-features`）に加えて、`test-no-default-features` ジョブを追加する。

```yaml
test-no-default-features:
  name: Test (no default features)
  runs-on: ubuntu-latest
  needs: changes
  if: ${{ needs.changes.outputs.rust == 'true' }}
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable

    - name: Cache cargo dependencies
      uses: Swatinem/rust-cache@v2

    - name: Build without default features
      run: cargo build --no-default-features

    - name: Run tests without default features
      run: cargo test --no-default-features
```

### 6.2 既存ジョブの維持

既存の `test`, `check`, `clippy` ジョブは `--all-features` を維持する（制約事項）。

#### check ジョブへの追加

`--no-default-features` ビルドのチェックを `check` ジョブの既存ステップに追加することも可能だが、CI分離性を高めるため独立ジョブとする。

### 6.3 docker-build ジョブの変更

両方のDockerfileをビルドチェックする。

```yaml
docker-build:
  name: Docker Build Check
  runs-on: ubuntu-latest
  needs: changes
  if: ${{ needs.changes.outputs.docker == 'true' }}
  permissions:
    contents: read
  steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Build API-only Docker image (no push)
      uses: docker/build-push-action@v7
      with:
        context: .
        file: deployments/docker/Dockerfile
        push: false
        tags: registry-firewall:ci-check-api
        cache-from: type=gha
        cache-to: type=gha,mode=max

    - name: Build full Docker image (no push)
      uses: docker/build-push-action@v7
      with:
        context: .
        file: deployments/docker/Dockerfile.full
        push: false
        tags: registry-firewall:ci-check-full
        cache-from: type=gha
        cache-to: type=gha,mode=max
```

---

## 7. ファイル変更一覧

| ファイル | 変更種別 | 変更内容 |
|---------|---------|---------|
| `Cargo.toml` | 変更 | `[features]`セクション追加、`rust-embed`・`mime_guess`をoptional化、`utoipa`・`utoipa-axum`・`utoipa-swagger-ui`追加 |
| `src/lib.rs` | 変更 | `webui`モジュールを`cfg(feature = "webui")`で条件付き、`api`モジュール追加 |
| `src/api/mod.rs` | 新規 | `src/webui/api.rs`から移動、re-export |
| `src/api/types.rs` | 新規 | 型定義（DashboardStats等）+ `ToSchema` derive追加 |
| `src/api/handlers.rs` | 新規 | APIビジネスロジック関数 |
| `src/api/openapi.rs` | 新規 | `ApiDoc`構造体、`SecurityAddon`（`swagger-gen` feature条件付き） |
| `src/webui/mod.rs` | 変更 | `pub mod api;`と`pub use api::*;`を削除 |
| `src/server/router.rs` | 変更 | インポートパス変更、Web UIルート・ハンドラを`cfg(feature = "webui")`で条件付き、`#[utoipa::path]`アノテーション追加 |
| `src/main.rs` | 変更 | `--generate-swagger` CLIオプション追加 |
| `deployments/docker/Dockerfile` | 変更 | `web/`コピーを削除、`--no-default-features`でビルド |
| `deployments/docker/Dockerfile.full` | 新規 | node-buildステージ追加、`--features webui`でビルド |
| `.github/workflows/release.yml` | 変更 | `build-docker-api`・`build-docker-full`・`generate-swagger`ジョブ追加 |
| `.github/workflows/ci.yml` | 変更 | `test-no-default-features`ジョブ追加、`docker-build`ジョブに`Dockerfile.full`追加 |

---

## 8. 設計上の制約と決定事項

### 8.1 `webui::api` → `api` への移動について

`src/webui/api.rs` に定義された型（`DashboardStats`等）は `src/server/router.rs` から直接使用されている。`webui` featureの条件付きコンパイルを適切に機能させるには、これらの型をfeatureに依存しない独立モジュールに移動する必要がある。

既存のコードは `crate::webui::api::DashboardStats` のような参照を持つ可能性があるため、移動後は `src/webui/mod.rs` からの再エクスポートを一時的に維持することも可能だが、モジュール構造の明確化のため直接参照に変更する。

### 8.2 NFR-106（後方互換性）の取り扱い

`latest` タグのセマンティクスが変わる（GUI付き → APIのみ）ため、リリース時のCHANGELOGへの記載が必要。本設計書はCHANGELOGの内容そのものは定義しないが、実装タスクにCHANGELOG更新を含める。

### 8.3 swagger.json のサーバー定義

REQ-129（NFR-109）に従い、swagger.json のサーバー定義には本番環境の内部ホスト名を含めない。

```rust
// SecurityAddon に加えて ServerAddon も実装
impl utoipa::Modify for ServerAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.servers = Some(vec![
            utoipa::openapi::ServerBuilder::new()
                .url("{scheme}://{host}:{port}")
                .description(Some("registry-firewall instance"))
                .build(),
        ]);
    }
}
```

---

## 変更履歴

| バージョン | 日付 | 変更内容 | 作成者 |
|-----------|------|----------|--------|
| 1.0 | 2026-03-18 | 初版作成 | - |
