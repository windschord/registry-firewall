# CLAUDE.md - AIアシスタント向けガイド

## プロジェクト概要

**registry-firewall**は、ソフトウェアサプライチェーン攻撃から開発環境を保護するための統合レジストリプロキシです。OSVやOpenSSF Malicious Packagesなどの外部セキュリティデータソースと連携し、悪意あるパッケージやバージョンをフィルタリングします。プラグインアーキテクチャにより、対応言語やセキュリティソースを柔軟に拡張できます。

### 主な目標
- 悪意あるパッケージの自動ブロック
- 複数言語エコシステムの統一的な保護（PyPI、Go、Cargo、Docker）
- 低運用コストでの継続的なセキュリティ確保
- OpenTelemetryによる標準的な可観測性の提供
- Web UIによる直感的な管理インターフェース

### 技術スタック
- **言語**: Rust 1.75+（edition 2021）
- **非同期ランタイム**: tokio
- **HTTPフレームワーク**: axum
- **データベース**: SQLite（rusqlite）
- **可観測性**: OpenTelemetry
- **フロントエンド**: React + TypeScript + Tailwind CSS（rust-embedで埋め込み）

## リポジトリ構成

```
registry-firewall/
├── CLAUDE.md              # 本ファイル - AIアシスタント向けガイド
├── Cargo.toml             # Rust依存関係とプロジェクト設定
├── Cargo.lock             # 依存関係のロックファイル
├── LICENSE                # Apache 2.0ライセンス
├── .gitignore             # Git除外パターン
├── docs/
│   ├── requirements.md    # 詳細な要件定義書
│   ├── design.md          # 技術設計書
│   └── tasks.md           # 実装タスク一覧
├── src/
│   ├── main.rs            # アプリケーションエントリーポイント
│   ├── lib.rs             # ライブラリルート
│   ├── error.rs           # 共通エラー型（AppError）
│   ├── config/            # 設定管理
│   │   ├── mod.rs
│   │   └── validation.rs
│   ├── server/            # HTTPサーバーコンポーネント
│   │   ├── mod.rs
│   │   ├── router.rs      # axumルーター設定
│   │   └── middleware.rs  # 認証・ロギング・トレーシングミドルウェア
│   ├── auth/              # 認証システム
│   │   ├── mod.rs
│   │   ├── manager.rs     # AuthManager実装
│   │   ├── token.rs       # トークン生成・検証
│   │   └── ratelimit.rs   # 認証失敗時のレートリミット
│   ├── sync/              # データ同期インフラストラクチャ
│   │   ├── mod.rs
│   │   ├── scheduler.rs   # ジッター付き自動同期スケジューラー
│   │   ├── retry.rs       # 指数バックオフリトライマネージャー
│   │   └── http_client.rs # レートリミット付きHTTPクライアント
│   ├── plugins/           # プラグインシステム
│   │   ├── mod.rs
│   │   ├── registry/      # レジストリプラグイン（PyPI、Go、Cargo、Docker）
│   │   │   ├── mod.rs
│   │   │   ├── traits.rs  # RegistryPluginトレイト
│   │   │   ├── pypi.rs
│   │   │   ├── golang.rs
│   │   │   ├── cargo.rs
│   │   │   └── docker.rs
│   │   ├── security/      # セキュリティソースプラグイン
│   │   │   ├── mod.rs
│   │   │   ├── traits.rs  # SecuritySourcePluginトレイト
│   │   │   ├── osv.rs     # OSVデータベース連携
│   │   │   ├── openssf.rs # OpenSSF Malicious Packages
│   │   │   ├── custom.rs  # カスタムブロックリスト
│   │   │   └── minage.rs  # 最小経過時間フィルタ
│   │   └── cache/         # キャッシュプラグイン
│   │       ├── mod.rs
│   │       ├── traits.rs  # CachePluginトレイト
│   │       ├── filesystem.rs
│   │       └── redis.rs
│   ├── database/          # データベース層
│   │   ├── mod.rs
│   │   ├── sqlite.rs      # SQLite実装
│   │   └── migrations.rs  # スキーママイグレーション
│   ├── otel/              # OpenTelemetry統合
│   │   └── mod.rs
│   ├── webui/             # Web UIバックエンド
│   │   ├── mod.rs
│   │   └── api.rs         # REST APIエンドポイント
│   └── models/            # ドメインモデル
│       ├── mod.rs
│       ├── package.rs
│       ├── block.rs
│       └── token.rs
├── tests/                 # 統合テスト
│   ├── common/mod.rs
│   ├── integration_pypi.rs
│   ├── integration_auth.rs
│   ├── integration_cache.rs
│   └── integration_sync.rs
├── web/                   # Reactフロントエンド（作成予定）
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── configs/               # 設定ファイル
│   ├── config.yaml
│   └── custom-blocklist.yaml
└── deployments/           # デプロイ設定
    ├── docker/
    │   └── Dockerfile
    └── docker-compose/
        ├── docker-compose.yaml
        └── otel-collector-config.yaml
```

## 開発ワークフロー

### テスト駆動開発（TDD）

本プロジェクトはTDDを厳守します。**すべての実装はRed-Green-Refactorサイクルに従ってください：**

1. **Red**: まず失敗するテストを書く
2. **Green**: テストを通す最小限の実装を書く
3. **Refactor**: テストを通したまま、コード品質を改善する

### テストカバレッジ目標
- ドメインロジック: 90%以上
- インフラストラクチャ: 70%以上
- 全体: 80%以上

### テスト実行

```bash
# 全テスト実行
cargo test

# 特定モジュールのテスト実行
cargo test error           # エラーハンドリングテスト
cargo test config          # 設定テスト
cargo test database        # データベーステスト
cargo test retry           # リトライマネージャーテスト
cargo test scheduler       # 同期スケジューラーテスト
cargo test osv             # OSVプラグインテスト
cargo test pypi            # PyPIプラグインテスト

# 統合テスト実行
cargo test --test '*'

# 出力付きで実行
cargo test -- --nocapture
```

### コード品質

```bash
# コードフォーマット
cargo fmt

# リンター実行
cargo clippy

# ビルドせずにチェック
cargo check

# リリースビルド
cargo build --release
```

## 主要な規約

### エラーハンドリング

`thiserror`を使用してエラーを定義：

```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("認証に失敗しました: {0}")]
    Auth(#[from] AuthError),

    #[error("プラグインエラー: {0}")]
    Plugin(#[from] PluginError),
    // ...
}
```

### 非同期トレイト

非同期トレイトメソッドには`async_trait`を使用：

```rust
#[async_trait]
pub trait SecuritySourcePlugin: Send + Sync {
    fn name(&self) -> &str;
    async fn sync(&self) -> Result<SyncResult, SyncError>;
    // ...
}
```

### テスト用モック

`mockall`の`#[automock]`属性を使用：

```rust
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Database: Send + Sync {
    async fn is_blocked(&self, ecosystem: &str, pkg: &str, version: &str)
        -> Result<Option<BlockReason>, DbError>;
}
```

### 設定

- すべての設定はYAMLファイルまたは環境変数で指定可能
- 環境変数展開をサポート: `${VAR_NAME}`
- 完全な設定構造は`docs/design.md`を参照

### APIトークン形式

- プレフィックス: `rf_`
- 32バイトランダム（Base64エンコード）
- argon2idでハッシュ化して保存

## プラグインアーキテクチャ

### レジストリプラグイン

新しいパッケージレジストリには`RegistryPlugin`トレイトを実装：

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

### セキュリティソースプラグイン

新しいセキュリティデータソースには`SecuritySourcePlugin`トレイトを実装：

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

### キャッシュプラグイン

新しいキャッシュバックエンドには`CachePlugin`トレイトを実装：

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

## 主要な依存クレート

```toml
# コア
tokio = { version = "1", features = ["full"] }
axum = { version = "0.7", features = ["macros"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# データベース
rusqlite = { version = "0.31", features = ["bundled"] }
tokio-rusqlite = "0.5"

# HTTPクライアント
reqwest = { version = "0.12", features = ["json", "gzip"] }

# OpenTelemetry
opentelemetry = "0.22"
opentelemetry-otlp = "0.15"
tracing = "0.1"
tracing-opentelemetry = "0.23"

# セキュリティ
argon2 = "0.5"
semver = "1"

# エラーハンドリング
thiserror = "1"
anyhow = "1"

# テスト
mockall = "0.12"
axum-test = "14"
wiremock = "0.6"
tempfile = "3"
```

## HTTPエンドポイント

### プロキシエンドポイント
- `GET /pypi/*` - PyPI Simple APIプロキシ
- `GET /go/*` - Go Moduleプロキシ
- `GET /cargo/*` - Cargo Sparse Indexプロキシ
- `GET /v2/*` - Docker Registry v2プロキシ

### 管理エンドポイント
- `GET /health` - ヘルスチェック（認証不要）
- `GET /metrics` - Prometheusメトリクス（認証不要）
- `GET /ui/*` - Web UI静的ファイル
- `GET/POST/PUT/DELETE /api/*` - 管理API

### APIエンドポイント
- `GET /api/dashboard` - ダッシュボード統計
- `GET /api/blocks` - ブロックイベントログ
- `GET /api/security-sources` - セキュリティソース状態
- `POST /api/security-sources/{name}/sync` - 手動同期トリガー
- `GET /api/cache/stats` - キャッシュ統計
- `DELETE /api/cache` - キャッシュクリア
- `GET/POST/PUT/DELETE /api/rules` - カスタムブロックルール
- `GET/POST/DELETE /api/tokens` - APIトークン管理

## データベーススキーマ

SQLiteの主要テーブル：
- `blocked_packages` - セキュリティソースによりブロックされたパッケージ
- `sync_status` - セキュリティソースの同期状態
- `api_tokens` - クライアントAPIトークン（ハッシュ化）
- `block_logs` - ブロックイベント監査ログ
- `custom_rules` - ユーザー定義ブロックルール

## 実装状況

現在のステータス: **実装前フェーズ**

リポジトリには包括的な設計ドキュメントが含まれていますが、ソースコードはまだありません。実装は`docs/tasks.md`のフェーズに従って進めてください：

1. フェーズ1: プロジェクト基盤（Cargo.toml、ディレクトリ構造）
2. フェーズ2: コアインフラストラクチャ（設定、モデル、データベース）
3. フェーズ3: 同期インフラストラクチャ（リトライ、レートリミット、スケジューラー）
4. フェーズ4: セキュリティソースプラグイン（OSV、OpenSSF、カスタム）
5. フェーズ5: キャッシュレイヤー
6. フェーズ6: レジストリプラグイン（PyPI、Go、Cargo、Docker）
7. フェーズ7: 認証
8. フェーズ8: HTTPサーバー
9. フェーズ9: OpenTelemetry統合
10. フェーズ10: Web UI
11. フェーズ11: 統合・デプロイ

## AIアシスタント向け重要事項

### 機能実装時の注意点
1. **必ずテストを先に書く**（TDD）
2. **design.mdで定義されたトレイトベースのプラグインアーキテクチャを使用する**
3. **tasks.mdのフェーズ別実装計画に従う**
4. **モジュールの疎結合を保つ** - トレイトを使った依存性注入を活用
5. **外部API呼び出しには指数バックオフを適用する**
6. **セキュリティデータソースのレートリミットを尊重する**

### セキュリティ上の考慮事項
- 機密トークンをログに出力しない
- 保存する認証情報はすべてargon2idでハッシュ化
- アップストリーム接続にはTLS 1.2以上を使用
- すべてのユーザー入力を検証
- 認証失敗にはレートリミットを適用

### パフォーマンス目標
- キャッシュヒット時のレスポンス: 50ms以内
- キャッシュミス時のレスポンス: アップストリームレイテンシ + 100ms以内
- セキュリティDBチェック: 1ms以内
- 認証トークン検証: 0.5ms以内
- メモリ使用量（アイドル時）: 256MB以下

## クイックスタート（実装完了後）

```bash
# プロジェクトをビルド
cargo build --release

# デフォルト設定で実行
./target/release/registry-firewall --config configs/config.yaml

# Dockerで実行
docker-compose -f deployments/docker-compose/docker-compose.yaml up
```

## 設定例

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

## ライセンス

Apache License 2.0
