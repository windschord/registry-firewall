# タスク計画書: Dual Docker Image Release + Swagger自動生成

## 概要

本ドキュメントは、設計書 `docs/sdd/design-dual-docker.md` に基づき、「デュアルDockerイメージリリース」と「OpenAPI仕様の自動生成」機能の実装タスクを定義する。

### トレーサビリティ

- 要件定義書: `docs/sdd/requirements-dual-docker.md`
- 技術設計書: `docs/sdd/design-dual-docker.md`

---

## 依存関係グラフ

```
Phase 1 (モジュール再編成)
├── TASK-001: src/webui/api.rs → src/api/ 移動
├── TASK-002: src/server/router.rs インポートパス変更
└── TASK-003: src/lib.rs 更新
        ↓ (Phase 1完了後)
Phase 2 (Cargo features導入)
├── TASK-004: Cargo.toml features定義
├── TASK-005: src/lib.rs cfg(feature)追加
└── TASK-006: src/server/router.rs 条件付きルート・ハンドラ
        ↓ (Phase 2完了後)
  ┌─────────────────────────────────────────────┐
  ↓                                             ↓
Phase 3 (Dockerfile変更)              Phase 4 (utoipa統合)
├── TASK-007: Dockerfile変更           ├── TASK-009: utoipa依存追加
└── TASK-008: Dockerfile.full新規      ├── TASK-010: ToSchema derive追加
                                       ├── TASK-011: #[utoipa::path]アノテーション
                                       ├── TASK-012: ApiDoc構造体実装
                                       └── TASK-013: --generate-swagger CLIオプション
        ↓ (Phase 3, 4完了後)
Phase 5 (CI/CD変更)
├── TASK-014: ci.yml test-no-default-features追加
├── TASK-015: ci.yml docker-buildジョブ拡張
├── TASK-016: release.yml デュアルイメージビルド
└── TASK-017: release.yml swagger.json生成・添付
```

### フェーズ間の並列実行

Phase 3とPhase 4は互いに独立しており、Phase 2完了後に並列実行が可能。

---

## Phase 1: モジュール再編成

**目的**: `src/webui/api.rs` の内容をfeature非依存の `src/api/` モジュールに移動し、後続のcfg(feature)適用を可能にする。

**前提**: なし（最初に実施）

**完了基準**: `cargo test --all-features` が全テストパス

---

### TASK-001: src/api/ モジュールの新規作成

**対応要件**: REQ-103, REQ-104, REQ-105

**対象ファイル**:
- `src/api/mod.rs` （新規作成）
- `src/api/types.rs` （新規作成、`src/webui/api.rs` から型定義を移動）
- `src/api/handlers.rs` （新規作成、`src/webui/api.rs` からハンドラロジックを移動）

#### Red（テスト作成）

`src/api/types.rs` に存在すべき型（`DashboardStats`等）のコンパイルテストを作成する。

```rust
// src/api/mod.rs に追加するテスト
#[cfg(test)]
mod tests {
    use super::*;

    // TASK-001-T1: DashboardStats がデフォルト値で生成できること
    #[test]
    fn test_dashboard_stats_default() {
        let stats = DashboardStats::default();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.blocked_requests, 0);
    }

    // TASK-001-T2: BlockLogsQuery がデシリアライズできること
    #[test]
    fn test_block_logs_query_deserialize() {
        let json = r#"{"limit": 10, "offset": 0}"#;
        let query: BlockLogsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.limit, Some(10));
    }
}
```

テスト実行（Redを確認）:
```bash
cargo test --all-features api::
# → コンパイルエラーまたはモジュール未発見でfail
```

#### Green（実装）

1. `src/api/mod.rs` を新規作成し、`pub mod types;` と `pub mod handlers;` を定義する
2. `src/webui/api.rs` から以下を `src/api/types.rs` にコピー（後でwebui側から削除）:
   - 全定数（`DEFAULT_PAGE_LIMIT`等）
   - 全型定義（`DashboardStats`等）
3. `src/webui/api.rs` からビジネスロジック関数を `src/api/handlers.rs` にコピー:
   - `build_dashboard_stats()`
   - その他のヘルパー関数

テスト実行（Greenを確認）:
```bash
cargo test --all-features api::
# → 全テストパス
```

#### Refactor

- 型定義とハンドラのモジュール境界を明確化する
- publicインターフェースを `src/api/mod.rs` から再エクスポートする

**完了基準**:
- `src/api/` モジュールが作成され、コンパイルが通る
- `DashboardStats` 等の型が `crate::api::DashboardStats` でアクセス可能
- `cargo test --all-features` が全テストパス

---

### TASK-002: src/server/router.rs のインポートパス変更

**対応要件**: REQ-103, REQ-104

**依存タスク**: TASK-001

**対象ファイル**:
- `src/server/router.rs`

#### Red（テスト作成）

既存のルーターテストが引き続き通ることを確認するテストを追加する（既存テストをそのまま活用）。

```bash
cargo test --all-features router::
# → TASK-001完了後の状態では、まだ旧パスを参照しているためビルドが通る状態
```

#### Green（実装）

`src/server/router.rs` のインポート文を変更する:

```rust
// Before
use crate::webui::api::{
    self, BlockLogsQuery, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MAX_PATTERN_LENGTH,
    MAX_REASON_LENGTH, MAX_TOKEN_NAME_LENGTH,
};

// After
use crate::api::{
    self, BlockLogsQuery, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, MAX_PATTERN_LENGTH,
    MAX_REASON_LENGTH, MAX_TOKEN_NAME_LENGTH,
};
```

テスト実行:
```bash
cargo test --all-features router::
# → 全テストパス
```

#### Refactor

- インポート文の整理（未使用インポートの除去）

**完了基準**:
- `src/server/router.rs` が `crate::api` からインポートしている
- `cargo test --all-features` が全テストパス

---

### TASK-003: src/lib.rs と src/webui/mod.rs の更新

**対応要件**: REQ-103, REQ-105

**依存タスク**: TASK-001, TASK-002

**対象ファイル**:
- `src/lib.rs`
- `src/webui/mod.rs`

#### Red（テスト作成）

`src/api` モジュールが `crate` ルートから直接アクセスできることを確認するテスト。

```rust
// src/lib.rs 経由でアクセスできることをコンパイルテストで確認
// tests/common/mod.rs などに追加
// use registry_firewall::api::DashboardStats;  // これがコンパイルできればOK
```

#### Green（実装）

1. `src/lib.rs` に `pub mod api;` を追加する:

```rust
// Before
pub mod webui;

// After  (一時的に両方を残す)
pub mod api;
pub mod webui;
```

2. `src/webui/mod.rs` から `pub mod api;` と `pub use api::*;` を削除する:

```rust
// Before
pub mod api;
pub use api::*;
use rust_embed::RustEmbed;
...

// After
// api モジュールは src/api/ に移動したため削除
use rust_embed::RustEmbed;
...
```

テスト実行:
```bash
cargo test --all-features
# → 全テストパス
```

#### Refactor

- `src/webui/api.rs` ファイル自体を削除する（内容は `src/api/` に移動済み）
- 不要なre-exportがないことを確認する

**完了基準**:
- `crate::api::DashboardStats` でアクセス可能
- `src/webui/api.rs` が削除されている
- `cargo test --all-features` が全テストパス

---

## Phase 2: Cargo features導入

**目的**: `webui` と `swagger-gen` featureを定義し、featureフラグによる条件付きコンパイルを実装する。

**前提**: Phase 1完了

**完了基準**: `cargo test --all-features` と `cargo test --no-default-features` の両方が全テストパス

---

### TASK-004: Cargo.toml features定義と依存クレートのoptional化

**対応要件**: REQ-101, REQ-102, REQ-105, REQ-120

**依存タスク**: TASK-003（Phase 1完了）

**対象ファイル**:
- `Cargo.toml`

#### Red（テスト作成）

`cargo build --no-default-features` がコンパイルエラーになることを確認する（現時点では `rust-embed` が通常依存のため、このコマンドは成功するが、feature設定前後の動作差分を把握するために実行する）。

```bash
# 現状の確認
cargo build --no-default-features
# → 現在は全依存が通常依存のため成功

# feature変更後にrust-embedがオプションになった後:
cargo build --no-default-features
# → rust-embedを参照するコードがcfg(feature)で囲まれていなければエラー
```

#### Green（実装）

`Cargo.toml` に以下を追加・変更する:

```toml
[features]
default = ["webui"]
webui = ["dep:rust-embed", "dep:mime_guess"]
swagger-gen = ["dep:utoipa", "dep:utoipa-axum", "dep:utoipa-swagger-ui"]

[dependencies]
# ... 既存の依存 ...

# Embed static files (optional, enabled by "webui" feature)
rust-embed = { version = "8", optional = true }
mime_guess = { version = "2", optional = true }

# OpenAPI specification generation (optional, enabled by "swagger-gen" feature)
utoipa = { version = "4", features = ["axum_extras", "chrono"], optional = true }
utoipa-axum = { version = "0.1", optional = true }
utoipa-swagger-ui = { version = "7", features = ["axum"], optional = true }
```

テスト実行:
```bash
cargo build --all-features
# → ビルド成功（依存関係の解決確認）
```

#### Refactor

- 依存クレートのバージョン指定が設計書と一致していることを確認する

**完了基準**:
- `[features]` セクションが定義されている（`default`, `webui`, `swagger-gen`）
- `rust-embed` と `mime_guess` が `optional = true` になっている
- `utoipa`、`utoipa-axum`、`utoipa-swagger-ui` が optional 依存として追加されている
- `cargo build --all-features` が成功する

---

### TASK-005: src/lib.rs に cfg(feature = "webui") 適用

**対応要件**: REQ-102, REQ-105

**依存タスク**: TASK-004

**対象ファイル**:
- `src/lib.rs`

#### Red（テスト作成）

```bash
# webui featureなしでビルドした際にsrc/webui/mod.rsがコンパイル対象外になることを確認
cargo build --no-default-features
# → 現状ではsrc/webui/が含まれるためrust-embedへの参照でエラー
```

#### Green（実装）

`src/lib.rs` の `webui` モジュール宣言に `#[cfg(feature = "webui")]` を追加する:

```rust
// Before
pub mod api;
pub mod webui;

// After
pub mod api;  // feature非依存: REST API型定義とロジック

#[cfg(feature = "webui")]
pub mod webui;  // webui feature時のみ: 静的ファイル配信
```

テスト実行:
```bash
cargo build --no-default-features
# → src/webui/がコンパイル対象外になる（rust-embedへの参照がない）
cargo build --all-features
# → 全機能でビルド成功
```

#### Refactor

- モジュール宣言のコメントが設計書と一致していることを確認する

**完了基準**:
- `pub mod webui;` に `#[cfg(feature = "webui")]` が付いている
- `cargo build --no-default-features` が成功する
- `cargo build --all-features` が成功する

---

### TASK-006: src/server/router.rs の条件付きルート・ハンドラ実装

**対応要件**: REQ-103, REQ-104

**依存タスク**: TASK-005

**対象ファイル**:
- `src/server/router.rs`

#### Red（テスト作成）

`webui` featureなしビルドで `/ui` エンドポイントが存在しないことを確認するテストを追加する:

```rust
// Test: webui featureなしでは/uiが404を返すことを確認
// Note: このテストはcfg(not(feature = "webui"))で条件付きにする
#[cfg(not(feature = "webui"))]
#[tokio::test]
async fn test_webui_not_available_without_feature() {
    // ... テスト実装 ...
    // GET /ui → 404
}
```

```bash
cargo test --no-default-features router::
# → webui関連ハンドラへの参照でコンパイルエラー（Redを確認）
```

#### Green（実装）

1. `build_router()` 内のWeb UIルートを条件付きに変更する:

```rust
pub fn build_router<D: Database + 'static>(state: AppState<D>) -> Router {
    let auth_manager = Arc::clone(&state.auth_manager);

    let router = Router::new()
        // ... 既存のルート（変更なし）
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

2. Web UIハンドラに `#[cfg(feature = "webui")]` を付ける:

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

3. 既存の `test_webui_index_endpoint` と `test_webui_static_endpoint` に `#[cfg(feature = "webui")]` を付ける:

```rust
#[cfg(feature = "webui")]
#[tokio::test]
async fn test_webui_index_endpoint() { ... }

#[cfg(feature = "webui")]
#[tokio::test]
async fn test_webui_static_endpoint() { ... }
```

テスト実行:
```bash
cargo test --all-features router::
# → 全テストパス（webui関連テストを含む）

cargo test --no-default-features router::
# → webui関連テストは実行されず、APIテストは全パス
```

#### Refactor

- `#[cfg(feature = "webui")]` の付与漏れがないことを確認する

**完了基準**:
- `cargo test --all-features` が全テストパス
- `cargo test --no-default-features` が全テストパス
- `cargo test --no-default-features` でwebui関連テストがスキップされる

---

## Phase 3: Dockerfile変更

**目的**: APIのみイメージとGUI付きイメージの2種類のDockerfileを用意する。

**前提**: Phase 2完了

**完了基準**: 両Dockerfileのビルド成功（ローカル環境での `docker build` 成功）

---

### TASK-007: deployments/docker/Dockerfile をAPIのみ用に変更

**対応要件**: REQ-106, REQ-107, NFR-101, NFR-103, NFR-108

**依存タスク**: TASK-006（Phase 2完了）

**対象ファイル**:
- `deployments/docker/Dockerfile`

#### Red（テスト作成）

現状のDockerfileをビルドして、`web/dist/` が含まれていることを確認する:

```bash
docker build -f deployments/docker/Dockerfile -t registry-firewall:before-test .
# → 現状はweb/distをコピーしてwebui付きでビルド
```

#### Green（実装）

`deployments/docker/Dockerfile` を以下のように変更する:

1. `ARG CARGO_BUILD_FEATURES` と関連するshell条件分岐を削除する（APIのみDockerfileは常に `--no-default-features`）
2. `COPY web web/` を削除する（web/distが不要）
3. ビルドコマンドを `cargo build --release --no-default-features` に固定する

設計書 3.2節の Dockerfile を参照しつつ、APIのみ用に簡略化する:
- builder ステージでは `--no-default-features` を使用
- `COPY web web/` ステップを除去
- 設計書 3.4節の「APIのみビルドのDockerfile」の仕様に従う

テスト実行:
```bash
docker build -f deployments/docker/Dockerfile -t registry-firewall:api-only .
# → ビルド成功

docker run --rm registry-firewall:api-only registry-firewall --help
# → ヘルプが表示される（バイナリが動作する）
```

#### Refactor

- Dockerfileのコメントを更新し、APIのみ用であることを明記する

**完了基準**:
- `docker build -f deployments/docker/Dockerfile` が成功する
- `COPY web web/` が含まれていない
- `--no-default-features` でビルドされている

---

### TASK-008: deployments/docker/Dockerfile.full を新規作成

**対応要件**: REQ-110, REQ-114, REQ-115, REQ-116, NFR-102

**依存タスク**: TASK-007

**対象ファイル**:
- `deployments/docker/Dockerfile.full` （新規作成）

#### Red（テスト作成）

`Dockerfile.full` が存在しないことを確認する:

```bash
ls deployments/docker/Dockerfile.full
# → No such file（Redを確認）
```

#### Green（実装）

`deployments/docker/Dockerfile.full` を新規作成する。設計書 3.2節の設計に従い、以下の3ステージ構成にする:

- **Stage 1 (builder)**: `cargo build --release --features webui`
- **Stage 2 (node-build)**: `npm run build` でフロントエンドをビルド
- **Stage 3 (runtime)**: `debian:bookworm-slim` ベース、バイナリとconfigのみコピー

設計書 3.2節のDockerfileを参照して実装する。

テスト実行:
```bash
docker build -f deployments/docker/Dockerfile.full -t registry-firewall:full .
# → ビルド成功

docker run --rm -p 8080:8080 registry-firewall:full registry-firewall --help
# → ヘルプが表示される
```

#### Refactor

- TASK-007のDockerfileと共通部分（runtimeステージ等）の整合性を確認する

**完了基準**:
- `deployments/docker/Dockerfile.full` が存在する
- `docker build -f deployments/docker/Dockerfile.full` が成功する
- node-buildステージを含む3ステージ構成になっている
- `--features webui` でビルドされている

---

## Phase 4: utoipa統合

**目的**: OpenAPI仕様の自動生成機能を実装する。

**前提**: Phase 2完了（Phase 3と並列実行可能）

**完了基準**: `cargo run --features swagger-gen -- --generate-swagger` で `swagger.json` が生成される

---

### TASK-009: Cargo.toml への utoipa 依存追加確認

**対応要件**: REQ-120

**依存タスク**: TASK-004（TASK-004で既にutoipa依存を追加済み）

**対象ファイル**:
- `Cargo.toml`

**注意**: このタスクは TASK-004 で utoipa 依存を追加した場合は確認のみ。TASK-004 で対応済みであれば TASK-009 はスキップ可能。

#### Green（確認）

`Cargo.toml` に以下が含まれていることを確認する:

```toml
utoipa = { version = "4", features = ["axum_extras", "chrono"], optional = true }
utoipa-axum = { version = "0.1", optional = true }
utoipa-swagger-ui = { version = "7", features = ["axum"], optional = true }
```

```bash
cargo build --features swagger-gen
# → utoipaクレートがダウンロード・コンパイルされる
```

**完了基準**:
- `cargo build --features swagger-gen` が成功する
- `cargo build --no-default-features` が引き続き成功する

---

### TASK-010: API型定義に ToSchema derive 追加

**対応要件**: REQ-122

**依存タスク**: TASK-009

**対象ファイル**:
- `src/api/types.rs`
- `src/models/` 内の対象ファイル（`CustomRule`を含むファイル）

#### Red（テスト作成）

`ToSchema` が derive されていない状態で `swagger-gen` featureを有効にしてコンパイルしようとすると、後のステップでエラーになることを確認する（`ApiDoc` 未定義のため、このステップ単体ではビルドが通る）。

#### Green（実装）

設計書 5.2節に記載されたすべての構造体に `ToSchema` を追加する。

`src/api/types.rs` の各構造体（`swagger-gen` feature有効時のみ）:

```rust
#[cfg_attr(feature = "swagger-gen", derive(utoipa::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardStats {
    ...
}
```

対象構造体（設計書 5.2節より）:
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

`src/server/router.rs` の `CreateTokenApiRequest` にも同様に追加する。

`src/models/` の `CustomRule` にも追加する。

テスト実行:
```bash
cargo build --features swagger-gen
# → ToSchema derivationが正常にコンパイルされる
cargo build --no-default-features
# → 引き続き成功
```

#### Refactor

- `cfg_attr` の書き方が一貫していることを確認する

**完了基準**:
- 設計書 5.2節の全構造体に `ToSchema` が追加されている
- `cargo build --features swagger-gen` が成功する
- `cargo build --no-default-features` が成功する

---

### TASK-011: ハンドラへの #[utoipa::path] アノテーション追加

**対応要件**: REQ-121

**依存タスク**: TASK-010

**対象ファイル**:
- `src/server/router.rs`

#### Red（テスト作成）

アノテーションなしの状態では `ApiDoc` に全エンドポイントが含まれないことを確認する（TASK-012実装後にテスト可能）。このタスクでは設計書のアノテーション例を参考にコンパイル確認を行う。

#### Green（実装）

設計書 5.1節の全エンドポイントに `#[cfg_attr(feature = "swagger-gen", utoipa::path(...))]` を追加する:

```rust
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
    ...
}
```

対象エンドポイント（設計書 5.1節より）:
- `api_dashboard_handler` (GET /api/dashboard)
- `api_blocks_handler` (GET /api/blocks)
- `api_security_sources_handler` (GET /api/security-sources)
- `api_trigger_sync_handler` (POST /api/security-sources/{name}/sync)
- `api_cache_stats_handler` (GET /api/cache/stats)
- `api_cache_clear_handler` (DELETE /api/cache)
- `api_list_rules_handler` (GET /api/rules)
- `api_create_rule_handler` (POST /api/rules)
- `api_get_rule_handler` (GET /api/rules/{id})
- `api_update_rule_handler` (PUT /api/rules/{id})
- `api_delete_rule_handler` (DELETE /api/rules/{id})
- `api_list_tokens_handler` (GET /api/tokens)
- `api_create_token_handler` (POST /api/tokens)
- `api_delete_token_handler` (DELETE /api/tokens/{id})

テスト実行:
```bash
cargo build --features swagger-gen
# → アノテーションが正常にコンパイルされる
cargo build --no-default-features
# → アノテーションがコンパイル対象外（cfg_attr）
```

#### Refactor

- アノテーションの記述スタイルが一貫していることを確認する
- `security` フィールドが全エンドポイントに設定されていることを確認する

**完了基準**:
- 設計書 5.1節の全14エンドポイントにアノテーションが付いている
- `cargo build --features swagger-gen` が成功する
- `cargo build --no-default-features` が成功する

---

### TASK-012: ApiDoc 構造体と SecurityAddon 実装

**対応要件**: REQ-125, REQ-126, REQ-129

**依存タスク**: TASK-011

**対象ファイル**:
- `src/api/openapi.rs` （新規作成）
- `src/api/mod.rs` （`openapi` モジュールの追加）
- `src/server/router.rs` （Swagger UI エンドポイントの追加）

#### Red（テスト作成）

`ApiDoc::openapi()` が有効なOpenAPI仕様を生成することを確認するテストを追加する:

```rust
// src/api/openapi.rs のテスト
#[cfg(test)]
#[cfg(feature = "swagger-gen")]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    // TASK-012-T1: ApiDocがOpenAPI仕様を生成できること
    #[test]
    fn test_apidoc_generates_openapi() {
        let openapi = ApiDoc::openapi();
        let json = openapi.to_pretty_json().unwrap();
        assert!(!json.is_empty());
    }

    // TASK-012-T2: バージョンがCargo.tomlと一致すること
    #[test]
    fn test_apidoc_version_matches_cargo() {
        let openapi = ApiDoc::openapi();
        assert_eq!(openapi.info.version, env!("CARGO_PKG_VERSION"));
    }

    // TASK-012-T3: securitySchemesにbearer_tokenとbasic_authが含まれること
    #[test]
    fn test_apidoc_security_schemes() {
        let openapi = ApiDoc::openapi();
        let components = openapi.components.unwrap();
        assert!(components.security_schemes.contains_key("bearer_token"));
        assert!(components.security_schemes.contains_key("basic_auth"));
    }
}
```

```bash
cargo test --features swagger-gen api::openapi::
# → モジュール未定義でfail（Redを確認）
```

#### Green（実装）

1. `src/api/openapi.rs` を新規作成し、設計書 5.4節の `ApiDoc`、`SecurityAddon`、`ServerAddon` を実装する
2. `src/api/mod.rs` に `#[cfg(feature = "swagger-gen")] pub mod openapi;` を追加する
3. `src/server/router.rs` に Swagger UI エンドポイントを追加する（設計書 5.6節）:

```rust
#[cfg(all(feature = "webui", feature = "swagger-gen"))]
let router = router.merge(
    utoipa_swagger_ui::SwaggerUi::new("/api/swagger-ui")
        .url("/api/openapi.json", ApiDoc::openapi())
);
```

テスト実行:
```bash
cargo test --features swagger-gen api::openapi::
# → 全テストパス
cargo test --all-features
# → 全テストパス
```

#### Refactor

- `ServerAddon` のサーバー定義にプレースホルダーを使用する（REQ-129 / NFR-109）
- タグ定義が設計書 5.4節と一致していることを確認する

**完了基準**:
- `ApiDoc::openapi()` が呼び出し可能
- バージョンが `CARGO_PKG_VERSION` と一致する
- `bearer_token` と `basic_auth` のsecuritySchemesが含まれる
- `cargo test --features swagger-gen` が全テストパス

---

### TASK-013: --generate-swagger CLIオプション実装

**対応要件**: REQ-123

**依存タスク**: TASK-012

**対象ファイル**:
- `src/main.rs`

#### Red（テスト作成）

`--generate-swagger` オプションを指定しても `swagger.json` が生成されないことを確認する:

```bash
cargo run --features swagger-gen -- --generate-swagger
# → 引数が認識されず、サーバー起動を試みる（Redを確認）
```

#### Green（実装）

設計書 5.5節に従い `src/main.rs` に以下を追加する:

1. `Args` 構造体に `--generate-swagger` フラグを追加する:

```rust
/// Generate OpenAPI specification (swagger.json) and exit
#[cfg(feature = "swagger-gen")]
#[arg(long)]
generate_swagger: bool,
```

2. `main()` に処理を追加する:

```rust
#[cfg(feature = "swagger-gen")]
if args.generate_swagger {
    use registry_firewall::api::openapi::ApiDoc;
    use utoipa::OpenApi;
    let spec = ApiDoc::openapi()
        .to_pretty_json()
        .expect("Failed to serialize OpenAPI spec");
    std::fs::write("swagger.json", spec)
        .expect("Failed to write swagger.json");
    eprintln!("swagger.json generated successfully");
    return Ok(());
}
```

テスト実行:
```bash
cargo run --features swagger-gen -- --generate-swagger
# → swagger.json が生成される

ls -la swagger.json
# → ファイルが存在する

# OpenAPI 3.0フォーマットの確認
cat swagger.json | python3 -m json.tool > /dev/null
# → JSONとして有効
```

#### Refactor

- `swagger.json` の出力パスが設計書と一致していることを確認する（カレントディレクトリ）

**完了基準**:
- `cargo run --features swagger-gen -- --generate-swagger` で `swagger.json` が生成される
- 生成されたJSONが有効なOpenAPI 3.0フォーマット
- バージョンが `Cargo.toml` のバージョンと一致する
- `cargo run --no-default-features -- --help` が成功する（`--generate-swagger` オプションが表示されない）

---

## Phase 5: CI/CD変更

**目的**: GitHub Actions ワークフローをデュアルイメージとswagger.json生成に対応させる。

**前提**: Phase 3完了、Phase 4完了

**完了基準**: ワークフローファイルが設計書と一致する

---

### TASK-014: ci.yml に test-no-default-features ジョブ追加

**対応要件**: REQ-104（CIでの検証）

**依存タスク**: TASK-006（Phase 2完了）

**対象ファイル**:
- `.github/workflows/ci.yml`

#### Red（テスト作成）

`test-no-default-features` ジョブが存在しないことを確認する:

```bash
grep -n "test-no-default-features" .github/workflows/ci.yml
# → 見つからない（Redを確認）
```

#### Green（実装）

設計書 6.1節に従い、`test-no-default-features` ジョブを `ci.yml` に追加する:

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

テスト実行（YAMLの妥当性確認）:
```bash
# GitHub Actions のYAML構文確認
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
# → エラーなし
```

#### Refactor

- ジョブの配置位置が既存の `test` ジョブの近くになっていることを確認する

**完了基準**:
- `ci.yml` に `test-no-default-features` ジョブが追加されている
- ジョブは `cargo build --no-default-features` と `cargo test --no-default-features` を実行する
- YAMLとして構文的に正しい

---

### TASK-015: ci.yml の docker-build ジョブを Dockerfile.full 対応に拡張

**対応要件**: REQ-110（CI段階での検証）

**依存タスク**: TASK-008, TASK-014

**対象ファイル**:
- `.github/workflows/ci.yml`

#### Red（テスト作成）

既存の `docker-build` ジョブが `Dockerfile.full` をビルドしないことを確認する:

```bash
grep -n "Dockerfile.full" .github/workflows/ci.yml
# → 見つからない（Redを確認）
```

#### Green（実装）

設計書 6.3節に従い、`docker-build` ジョブに `Dockerfile.full` のビルドステップを追加する:

```yaml
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

既存のDockerfileのビルドステップのタグも `registry-firewall:ci-check-api` に変更する（設計書 6.3節に合わせる）。

テスト実行（YAMLの妥当性確認）:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
# → エラーなし
```

**完了基準**:
- `docker-build` ジョブが `Dockerfile` と `Dockerfile.full` の両方をビルドする
- YAMLとして構文的に正しい

---

### TASK-016: release.yml のデュアルイメージビルド実装

**対応要件**: REQ-110, REQ-111, REQ-112, REQ-113, REQ-115, NFR-104, NFR-105

**依存タスク**: TASK-015

**対象ファイル**:
- `.github/workflows/release.yml`

#### Red（テスト作成）

現状の `release.yml` が単一イメージのみをビルドすることを確認する:

```bash
grep -n "build-docker-full\|Dockerfile.full" .github/workflows/release.yml
# → 見つからない（Redを確認）
```

#### Green（実装）

設計書 4.1〜4.3節に従い、`release.yml` を変更する:

1. 既存の `build-and-push-docker` ジョブを `build-docker-api` にリネームし、APIのみイメージのタグ設定に変更する
2. `build-docker-full` ジョブを新規追加する（設計書 4.3節の YAML を参照）
3. `create-release` ジョブの `needs` を `[test, generate-swagger, build-docker-api, build-docker-full]` に更新する

タグ命名規則（設計書 4.2節）:
- APIのみ: `latest`, `X.Y.Z`, `X.Y`, `X`（安定版のみlatest付与）
- GUI付き: `latest-full`, `X.Y.Z-full`, `X.Y-full`, `X-full`（安定版のみlatest-full付与）

テスト実行（YAMLの妥当性確認）:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
# → エラーなし
```

#### Refactor

- `build-docker-api` と `build-docker-full` が並列実行されることを確認する（両ジョブの `needs` が `test` のみであること）

**完了基準**:
- `build-docker-api` ジョブが `Dockerfile` を使用してAPIのみイメージをビルド・プッシュする
- `build-docker-full` ジョブが `Dockerfile.full` を使用してGUI付きイメージをビルド・プッシュする
- プレリリース時は `latest` / `latest-full` タグが付与されない
- 両ジョブが `test` ジョブ完了後に並列実行される
- YAMLとして構文的に正しい

---

### TASK-017: release.yml の swagger.json 生成・リリースアセット添付

**対応要件**: REQ-124

**依存タスク**: TASK-013, TASK-016

**対象ファイル**:
- `.github/workflows/release.yml`

#### Red（テスト作成）

現状の `release.yml` が `generate-swagger` ジョブを持たず、`swagger.json` をリリースアセットに添付しないことを確認する:

```bash
grep -n "generate-swagger\|swagger.json" .github/workflows/release.yml
# → 見つからない（Redを確認）
```

#### Green（実装）

設計書 4.1〜4.3節に従い、以下を追加する:

1. `generate-swagger` ジョブを追加する（設計書 4.3節の YAML を参照）:
   - `needs: test` で `test` ジョブ完了後に実行
   - `cargo run --features swagger-gen -- --generate-swagger` を実行
   - `actions/upload-artifact` で `swagger-json` アーティファクトとしてアップロード

2. `create-release` ジョブを変更する:
   - `needs` に `generate-swagger` を追加する
   - `actions/download-artifact` で `swagger-json` をダウンロードする
   - `softprops/action-gh-release` の `files` に `swagger.json` を追加する

テスト実行（YAMLの妥当性確認）:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
# → エラーなし
```

#### Refactor

- `generate-swagger` と `build-docker-api`、`build-docker-full` が並列実行されることを確認する（いずれも `needs: test` のみ）

**完了基準**:
- `generate-swagger` ジョブが追加されている
- `create-release` ジョブが `swagger.json` をリリースアセットに添付する
- `generate-swagger`、`build-docker-api`、`build-docker-full` が並列実行可能
- YAMLとして構文的に正しい

---

## タスクステータス一覧

| タスクID | タイトル | フェーズ | 依存タスク | ステータス |
|---------|--------|---------|-----------|---------|
| TASK-001 | src/api/ モジュール新規作成 | Phase 1 | なし | TODO |
| TASK-002 | router.rs インポートパス変更 | Phase 1 | TASK-001 | TODO |
| TASK-003 | lib.rs・webui/mod.rs 更新 | Phase 1 | TASK-001, TASK-002 | TODO |
| TASK-004 | Cargo.toml features定義 | Phase 2 | TASK-003 | TODO |
| TASK-005 | lib.rs cfg(feature = "webui")適用 | Phase 2 | TASK-004 | TODO |
| TASK-006 | router.rs 条件付きルート・ハンドラ | Phase 2 | TASK-005 | TODO |
| TASK-007 | Dockerfile APIのみ用に変更 | Phase 3 | TASK-006 | TODO |
| TASK-008 | Dockerfile.full 新規作成 | Phase 3 | TASK-007 | TODO |
| TASK-009 | utoipa依存追加確認 | Phase 4 | TASK-004 | TODO |
| TASK-010 | ToSchema derive追加 | Phase 4 | TASK-009 | TODO |
| TASK-011 | #[utoipa::path]アノテーション追加 | Phase 4 | TASK-010 | TODO |
| TASK-012 | ApiDoc・SecurityAddon実装 | Phase 4 | TASK-011 | TODO |
| TASK-013 | --generate-swagger CLIオプション | Phase 4 | TASK-012 | TODO |
| TASK-014 | ci.yml no-default-featuresジョブ追加 | Phase 5 | TASK-006 | TODO |
| TASK-015 | ci.yml docker-buildジョブ拡張 | Phase 5 | TASK-008, TASK-014 | TODO |
| TASK-016 | release.yml デュアルイメージビルド | Phase 5 | TASK-015 | TODO |
| TASK-017 | release.yml swagger.json生成・添付 | Phase 5 | TASK-013, TASK-016 | TODO |

---

## 変更ファイル一覧（設計書との対応）

| ファイル | 変更種別 | 対応タスク | 対応要件 |
|---------|---------|-----------|---------|
| `Cargo.toml` | 変更 | TASK-004 | REQ-101, REQ-102, REQ-105, REQ-120 |
| `src/lib.rs` | 変更 | TASK-003, TASK-005 | REQ-103, REQ-105 |
| `src/api/mod.rs` | 新規 | TASK-001 | REQ-103, REQ-104 |
| `src/api/types.rs` | 新規 | TASK-001, TASK-010 | REQ-103, REQ-122 |
| `src/api/handlers.rs` | 新規 | TASK-001 | REQ-103 |
| `src/api/openapi.rs` | 新規 | TASK-012 | REQ-125, REQ-126, REQ-129 |
| `src/webui/mod.rs` | 変更 | TASK-003 | REQ-105 |
| `src/webui/api.rs` | 削除 | TASK-003 | REQ-105 |
| `src/server/router.rs` | 変更 | TASK-002, TASK-006, TASK-011 | REQ-103, REQ-104, REQ-121 |
| `src/main.rs` | 変更 | TASK-013 | REQ-123 |
| `deployments/docker/Dockerfile` | 変更 | TASK-007 | REQ-106, REQ-107, NFR-101 |
| `deployments/docker/Dockerfile.full` | 新規 | TASK-008 | REQ-114, REQ-115, REQ-116, NFR-102 |
| `.github/workflows/ci.yml` | 変更 | TASK-014, TASK-015 | REQ-104 |
| `.github/workflows/release.yml` | 変更 | TASK-016, TASK-017 | REQ-110〜REQ-113, REQ-124, NFR-104, NFR-105 |

---

## 変更履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 1.0 | 2026-03-18 | 初版作成 |
