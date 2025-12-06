# タスク

> このドキュメントはAIエージェント（Claude Code等）が実装を行うことを前提としています。
> すべてのタスクはTDD（テスト駆動開発）で進めます。テストを先に書き、テストが失敗することを確認してから実装を行ってください。

## 実装計画

### フェーズ1: プロジェクト基盤
*推定期間: 60分（AIエージェント作業時間）*

#### タスク1.1: Cargoプロジェクト初期化
**説明**:
Rustプロジェクトの基盤を作成する
- `Cargo.toml`に必要な依存関係を定義
- ワークスペース構成は不要（単一クレート）
- `src/main.rs`と`src/lib.rs`を作成

**技術的文脈**:
- Rust 1.75+
- design.mdの「Rustクレート一覧」を参照
- edition = "2021"

**受入基準**:
- [x] `Cargo.toml`が作成され、すべての依存関係が定義されている
- [x] `cargo check`がエラーなく通過する
- [x] `src/main.rs`が存在し、`fn main()`が定義されている
- [x] `src/lib.rs`が存在する

**依存関係**: なし
**推定工数**: 15分
**ステータス**: `DONE`

#### タスク1.2: ディレクトリ構造の作成
**説明**:
design.mdで定義されたディレクトリ構造を作成する
- `src/`以下のモジュールディレクトリを作成
- 各ディレクトリに`mod.rs`を配置
- `tests/`ディレクトリを作成

**技術的文脈**:
- design.mdの「ディレクトリ構造」セクションを参照
- 各`mod.rs`には`// TODO: implement`コメントを記載

**受入基準**:
- [x] `src/config/mod.rs`が存在する
- [x] `src/server/mod.rs`が存在する
- [x] `src/auth/mod.rs`が存在する
- [x] `src/sync/mod.rs`が存在する
- [x] `src/plugins/mod.rs`が存在する
- [x] `src/plugins/registry/mod.rs`が存在する
- [x] `src/plugins/security/mod.rs`が存在する
- [x] `src/plugins/cache/mod.rs`が存在する
- [x] `src/database/mod.rs`が存在する
- [x] `src/otel/mod.rs`が存在する
- [x] `src/webui/mod.rs`が存在する
- [x] `src/models/mod.rs`が存在する
- [x] `src/error.rs`が存在する
- [x] `tests/common/mod.rs`が存在する
- [x] `cargo check`がエラーなく通過する

**依存関係**: タスク1.1
**推定工数**: 20分
**ステータス**: `DONE`

#### タスク1.3: 共通エラー型の定義
**説明**:
TDDで`src/error.rs`にアプリケーション共通のエラー型を実装する

**実装手順（TDD）**:
1. テスト作成: `src/error.rs`内に`#[cfg(test)]`モジュールでテストを作成
   - エラー型の変換テスト
   - エラーメッセージのテスト
2. テスト実行: `cargo test error`で失敗を確認
3. 実装: `AppError` enumを実装してテストを通過させる

**技術的文脈**:
- `thiserror`クレートを使用
- design.mdの「エラーハンドリング」セクションを参照
- `AuthError`, `PluginError`, `CacheError`, `DbError`, `SyncError`を定義

**受入基準**:
- [x] `AppError` enumが定義されている
- [x] 各エラーバリアントが`#[error("...")]`でメッセージを持つ
- [x] `From`トレイトによる変換が実装されている
- [x] テストが3つ以上存在する
- [x] `cargo test error`が通過する

**依存関係**: タスク1.2
**推定工数**: 25分
**ステータス**: `DONE`

---

### フェーズ2: コアインフラストラクチャ
*推定期間: 120分（AIエージェント作業時間）*

#### タスク2.1: 設定モデルの定義
**説明**:
TDDで`src/config/mod.rs`に設定構造体を実装する

**実装手順（TDD）**:
1. テスト作成: YAML文字列からのデシリアライズテスト
   - 完全な設定のパース
   - デフォルト値の適用
   - 環境変数の展開
2. テスト実行: 失敗を確認
3. 実装: `Config`構造体と関連型を実装

**技術的文脈**:
- `serde`と`serde_yaml`を使用
- `config`クレートで環境変数展開
- design.mdの「設定ファイル構造」セクションを参照

**受入基準**:
- [x] `Config`構造体が定義されている
- [x] `ServerConfig`, `AuthConfig`, `RegistryPluginConfig`等のサブ構造体が定義されている
- [x] `RetryConfig`, `RateLimitConfig`が定義されている
- [x] `Config::from_file(path)`メソッドが実装されている
- [x] `Config::from_env()`メソッドが実装されている
- [x] デシリアライズテストが通過する
- [x] `cargo test config`が通過する

**依存関係**: タスク1.3
**推定工数**: 40分
**ステータス**: `DONE`

#### タスク2.2: ドメインモデルの定義
**説明**:
TDDで`src/models/`に共通のドメインモデルを実装する

**実装手順（TDD）**:
1. テスト作成: 各モデルのシリアライズ/デシリアライズテスト
2. テスト実行: 失敗を確認
3. 実装: モデル構造体を実装

**技術的文脈**:
- `src/models/package.rs`: `PackageRequest`, `RequestType`
- `src/models/block.rs`: `BlockedPackage`, `BlockReason`, `Severity`
- `src/models/token.rs`: `Token`, `Client`, `CreateTokenRequest`

**受入基準**:
- [x] `PackageRequest`構造体が定義されている
- [x] `BlockedPackage`構造体が定義されている
- [x] `BlockReason`構造体が定義されている
- [x] `Severity` enumが定義されている
- [x] `Token`構造体が定義されている
- [x] すべてのモデルが`Serialize`/`Deserialize`を実装
- [x] `cargo test models`が通過する

**依存関係**: タスク1.3
**推定工数**: 30分
**ステータス**: `DONE`

#### タスク2.3: データベーストレイトの定義
**説明**:
TDDで`src/database/mod.rs`にデータベーストレイトを定義する

**実装手順（TDD）**:
1. テスト作成: モック実装を使ったトレイトの振る舞いテスト
2. テスト実行: 失敗を確認
3. 実装: `Database`トレイトを定義

**技術的文脈**:
- `async_trait`を使用
- `mockall`で`#[automock]`属性を付与
- design.mdの「Database Trait」セクションを参照

**受入基準**:
- [x] `Database`トレイトが定義されている
- [x] `insert_blocked_package`, `get_blocked_packages`, `is_blocked`メソッドが定義されている
- [x] `update_sync_status`, `get_sync_status`メソッドが定義されている
- [x] `create_token`, `get_token_by_hash`, `revoke_token`, `list_tokens`メソッドが定義されている
- [x] `insert_block_log`, `get_block_logs`メソッドが定義されている
- [x] `MockDatabase`が生成可能
- [x] `cargo test database`が通過する

**依存関係**: タスク2.2
**推定工数**: 25分
**ステータス**: `DONE`

#### タスク2.4: SQLite実装
**説明**:
TDDで`src/database/sqlite.rs`にSQLite実装を作成する

**実装手順（TDD）**:
1. テスト作成: インメモリSQLiteを使った各メソッドのテスト
   - CRUD操作のテスト
   - トランザクションのテスト
2. テスト実行: 失敗を確認
3. 実装: `SqliteDatabase`構造体を実装

**技術的文脈**:
- `rusqlite`と`tokio-rusqlite`を使用
- design.mdの「SQLite Schema」セクションを参照
- マイグレーションは`src/database/migrations.rs`に定義

**受入基準**:
- [x] `SqliteDatabase`構造体が定義されている
- [x] `Database`トレイトが実装されている
- [x] `SqliteDatabase::new(path)`でDB接続が作成される
- [x] `SqliteDatabase::new(":memory:")`でインメモリDBが作成される
- [x] 初回接続時にスキーマが自動作成される
- [x] 各CRUDメソッドのテストが存在する
- [x] `cargo test sqlite`が通過する

**依存関係**: タスク2.3
**推定工数**: 45分
**ステータス**: `DONE`

---

### フェーズ3: 同期インフラストラクチャ
*推定期間: 150分（AIエージェント作業時間）*

#### タスク3.1: リトライマネージャーの実装
**説明**:
TDDで`src/sync/retry.rs`にリトライ機能を実装する

**実装手順（TDD）**:
1. テスト作成:
   - 成功時は即座に返却するテスト
   - 一時的エラーでリトライするテスト
   - 最大リトライ回数で諦めるテスト
   - 指数バックオフの計算テスト
2. テスト実行: 失敗を確認
3. 実装: `RetryManager`構造体を実装

**技術的文脈**:
- design.mdの「Retry Manager」セクションを参照
- `RetryConfig`を使用
- `RetryableError`トレイトを定義

**受入基準**:
- [x] `RetryConfig`構造体が定義されている（max_retries, initial_backoff_secs, max_backoff_secs, backoff_multiplier, jitter）
- [x] `RetryableError`トレイトが定義されている
- [x] `RetryManager::execute()`が実装されている
- [x] 指数バックオフが正しく計算される
- [x] ジッター付きバックオフが実装されている
- [x] テストが5つ以上存在する（12テスト）
- [x] `cargo test retry`が通過する

**依存関係**: タスク1.3
**推定工数**: 40分
**ステータス**: `DONE`

#### タスク3.2: レートリミット付きHTTPクライアントの実装
**説明**:
TDDで`src/sync/http_client.rs`にレートリミット機能付きHTTPクライアントを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 基本的なGETリクエストのテスト
   - ETag/If-Modified-Sinceヘッダーのテスト
   - 304 Not Modifiedのテスト
   - 429 Too Many Requestsのテスト
   - 同時リクエスト制限のテスト
2. テスト実行: 失敗を確認
3. 実装: `HttpClientWithRateLimit`構造体を実装

**技術的文脈**:
- `reqwest`を使用
- `tokio::sync::Semaphore`で同時リクエスト制限
- design.mdの「Rate Limiter」セクションを参照
- `wiremock`でモックサーバーを使用してテスト

**受入基準**:
- [x] `RateLimitConfig`構造体が定義されている
- [x] `HttpClientWithRateLimit`構造体が定義されている
- [x] `get(url)`メソッドが実装されている
- [x] `get_with_cache_headers(url, etag, last_modified)`メソッドが実装されている
- [x] `ConditionalResponse` enumが定義されている（NotModified, Modified）
- [x] ドメイン単位のリクエスト間隔制御が実装されている
- [x] 同時リクエスト数制限が実装されている
- [x] テストが5つ以上存在する（14テスト）
- [x] `cargo test http_client`が通過する

**依存関係**: タスク2.1
**推定工数**: 50分
**ステータス**: `DONE`

#### タスク3.3: 同期スケジューラーの実装
**説明**:
TDDで`src/sync/scheduler.rs`に自動同期スケジューラーを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 指定間隔で同期が実行されるテスト
   - ジッター付きスケジューリングのテスト
   - シャットダウン時の停止テスト
   - 手動トリガーのテスト
2. テスト実行: 失敗を確認
3. 実装: `SyncScheduler`構造体を実装

**技術的文脈**:
- `tokio::time`を使用
- `tokio::sync::broadcast`でシャットダウン通知
- design.mdの「Sync Scheduler」セクションを参照
- `tokio::time::pause()`を使ってテスト

**受入基準**:
- [x] `SchedulerConfig`構造体が定義されている
- [x] `SyncScheduler`構造体が定義されている
- [x] `SyncScheduler::run()`が実装されている（バックグラウンドタスク）
- [x] `SyncScheduler::trigger_sync(plugin_name)`が実装されている（ManualSyncHandleとして）
- [x] ジッター付き次回実行時刻計算が実装されている
- [x] グレースフルシャットダウンが実装されている
- [x] テストが4つ以上存在する（12テスト）
- [x] `cargo test scheduler`が通過する

**依存関係**: タスク3.1
**推定工数**: 45分
**ステータス**: `DONE`

---

### フェーズ4: セキュリティソースプラグイン
*推定期間: 200分（AIエージェント作業時間）*

#### タスク4.1: SecuritySourcePluginトレイトの定義
**説明**:
TDDで`src/plugins/security/traits.rs`にセキュリティソースプラグインのトレイトを定義する

**実装手順（TDD）**:
1. テスト作成: モック実装を使ったトレイトの振る舞いテスト
2. テスト実行: 失敗を確認
3. 実装: `SecuritySourcePlugin`トレイトを定義

**技術的文脈**:
- `async_trait`を使用
- `mockall`で`#[automock]`属性を付与
- design.mdの「SecuritySourcePlugin Trait」セクションを参照

**受入基準**:
- [x] `SecuritySourcePlugin`トレイトが定義されている
- [x] `name()`, `supported_ecosystems()`, `sync()`, `sync_interval()`, `sync_status()`, `check_package()`, `get_blocked_packages()`メソッドが定義されている
- [x] `SyncResult`構造体が定義されている
- [x] `SyncStatus`構造体が定義されている
- [x] `MockSecuritySourcePlugin`が生成可能
- [x] `cargo test security::traits`が通過する

**依存関係**: タスク2.2
**推定工数**: 25分
**ステータス**: `DONE`

#### タスク4.2: OSVプラグインの実装
**説明**:
TDDで`src/plugins/security/osv.rs`にOSVプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 304 Not Modifiedでスキップするテスト
   - 正常同期のテスト
   - リトライ動作のテスト
   - パッケージチェックのテスト（脆弱性あり/なし）
   - バージョン範囲マッチングのテスト
2. テスト実行: 失敗を確認
3. 実装: `OsvPlugin`構造体を実装

**技術的文脈**:
- design.mdの「OSV Plugin」セクションを参照
- OSV形式のJSON解析
- GCSバケットからのZIPダウンロード
- `semver`クレートでバージョン範囲解析
- `wiremock`でモックサーバーを使用

**受入基準**:
- [x] `OsvPlugin`構造体が定義されている
- [x] `OsvConfig`構造体が定義されている
- [x] `SecuritySourcePlugin`トレイトが実装されている
- [x] `OsvEntry`, `Affected`, `Range`, `Event`構造体が定義されている
- [x] ETag/Last-Modifiedによるキャッシュ状態管理が実装されている
- [x] ZIP展開とOSV JSON解析が実装されている
- [x] バージョン範囲マッチングが実装されている
- [x] テストが6つ以上存在する (14 tests)
- [x] `cargo test osv`が通過する

**依存関係**: タスク4.1, タスク3.1, タスク3.2
**推定工数**: 60分
**ステータス**: `DONE`

#### タスク4.3: OpenSSFプラグインの実装
**説明**:
TDDで`src/plugins/security/openssf.rs`にOpenSSF Malicious Packagesプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - コミット変更なしでスキップするテスト
   - 正常同期のテスト
   - リトライ動作のテスト
   - パッケージチェックのテスト
2. テスト実行: 失敗を確認
3. 実装: `OpenSsfPlugin`構造体を実装

**技術的文脈**:
- design.mdの「OpenSSF Malicious Plugin」セクションを参照
- `git2`クレートでGit操作
- shallow clone + sparse checkout
- OSV形式のJSON解析

**受入基準**:
- [x] `OpenSsfPlugin`構造体が定義されている
- [x] `OpenSsfConfig`構造体が定義されている
- [x] `SecuritySourcePlugin`トレイトが実装されている
- [x] shallow clone機能が実装されている
- [x] sparse checkout機能が実装されている
- [x] コミットハッシュによる差分検出が実装されている
- [x] テストが4つ以上存在する (12 tests)
- [x] `cargo test openssf`が通過する

**依存関係**: タスク4.1, タスク3.1
**推定工数**: 50分
**ステータス**: `DONE`

#### タスク4.4: カスタムブロックリストプラグインの実装
**説明**:
TDDで`src/plugins/security/custom.rs`にカスタムブロックリストプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - YAMLファイル読み込みテスト
   - セマンティックバージョン範囲マッチングテスト
   - ワイルドカードパターンマッチングテスト
   - 自動リロードテスト
2. テスト実行: 失敗を確認
3. 実装: `CustomBlocklistPlugin`構造体を実装

**技術的文脈**:
- `serde_yaml`でYAML解析
- `semver`でバージョン範囲解析
- ファイル変更監視は`notify`クレート（オプション）

**受入基準**:
- [x] `CustomBlocklistPlugin`構造体が定義されている
- [x] `SecuritySourcePlugin`トレイトが実装されている
- [x] YAMLファイル形式が定義されている（ドキュメント）
- [x] セマンティックバージョン範囲（`>=1.0.0, <2.0.0`）が解析できる
- [x] ワイルドカードパターン（`malicious-*`）が解析できる
- [x] テストが4つ以上存在する (16 tests)
- [x] `cargo test custom`が通過する

**依存関係**: タスク4.1
**推定工数**: 35分
**ステータス**: `DONE`

#### タスク4.5: 最小経過時間プラグインの実装
**説明**:
TDDで`src/plugins/security/minage.rs`に最小経過時間プラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 公開から十分な時間が経過したパッケージは許可するテスト
   - 新しすぎるパッケージはブロックするテスト
2. テスト実行: 失敗を確認
3. 実装: `MinAgePlugin`構造体を実装

**技術的文脈**:
- 同期不要（リアルタイムチェック）
- 各レジストリAPIから公開日時を取得

**受入基準**:
- [x] `MinAgePlugin`構造体が定義されている
- [x] `MinAgeConfig`構造体が定義されている（min_age_hours）
- [x] `SecuritySourcePlugin`トレイトが実装されている
- [x] `sync()`は何もしない（`SyncResult { skipped: true }`を返す）
- [x] `check_package()`がリアルタイムで公開日時をチェックする
- [x] テストが3つ以上存在する (13 tests)
- [x] `cargo test minage`が通過する

**依存関係**: タスク4.1
**推定工数**: 30分
**ステータス**: `DONE`

---

### フェーズ5: キャッシュレイヤー
*推定期間: 90分（AIエージェント作業時間）*

#### タスク5.1: CachePluginトレイトの定義
**説明**:
TDDで`src/plugins/cache/traits.rs`にキャッシュプラグインのトレイトを定義する

**実装手順（TDD）**:
1. テスト作成: モック実装を使ったトレイトの振る舞いテスト
2. テスト実行: 失敗を確認
3. 実装: `CachePlugin`トレイトを定義

**技術的文脈**:
- `async_trait`を使用
- `mockall`で`#[automock]`属性を付与
- design.mdの「CachePlugin Trait」セクションを参照

**受入基準**:
- [x] `CachePlugin`トレイトが定義されている
- [x] `name()`, `get()`, `set()`, `delete()`, `stats()`, `purge()`, `purge_expired()`メソッドが定義されている
- [x] `CacheEntry`構造体が定義されている
- [x] `CacheMeta`構造体が定義されている
- [x] `CacheStats`構造体が定義されている
- [x] `MockCachePlugin`が生成可能
- [x] `cargo test cache::traits`が通過する (13 tests)

**依存関係**: タスク2.2
**推定工数**: 20分
**ステータス**: `DONE`

#### タスク5.2: ファイルシステムキャッシュの実装
**説明**:
TDDで`src/plugins/cache/filesystem.rs`にファイルシステムキャッシュを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 保存と取得のテスト
   - TTL期限切れのテスト
   - LRU削除のテスト
   - 統計情報のテスト
2. テスト実行: 失敗を確認
3. 実装: `FilesystemCache`構造体を実装

**技術的文脈**:
- `tempfile`クレートでテスト用一時ディレクトリ
- `.meta.json`ファイルでメタデータ管理
- design.mdの「Filesystem Cache」セクションを参照

**受入基準**:
- [x] `FilesystemCache`構造体が定義されている
- [x] `CachePlugin`トレイトが実装されている
- [x] ディレクトリ構造でファイルが保存される
- [x] `.meta.json`ファイルにメタデータが保存される
- [x] TTL期限切れファイルが`purge_expired()`で削除される
- [x] 最大サイズを超えた場合LRUで削除される
- [x] テストが5つ以上存在する (17 tests)
- [x] `cargo test filesystem`が通過する

**依存関係**: タスク5.1
**推定工数**: 45分
**ステータス**: `DONE`

#### タスク5.3: Redisキャッシュの実装（オプション）
**説明**:
TDDで`src/plugins/cache/redis.rs`にRedisキャッシュを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 保存と取得のテスト
   - TTL設定のテスト
   - 統計情報のテスト
2. テスト実行: 失敗を確認
3. 実装: `RedisCache`構造体を実装

**技術的文脈**:
- `redis`クレートを使用
- テストはモックまたはテストコンテナを使用

**受入基準**:
- [x] `RedisCache`構造体が定義されている
- [x] `CachePlugin`トレイトが実装されている
- [x] Redis接続が設定可能
- [x] TTLがRedisのEXPIREで設定される（プレースホルダー実装）
- [x] テストが3つ以上存在する (12 tests)
- [x] `cargo test redis`が通過する（Redisが利用可能な場合）

**依存関係**: タスク5.1
**推定工数**: 25分
**ステータス**: `DONE`

---

### フェーズ6: レジストリプラグイン
*推定期間: 240分（AIエージェント作業時間）*

#### タスク6.1: RegistryPluginトレイトの定義
**説明**:
TDDで`src/plugins/registry/traits.rs`にレジストリプラグインのトレイトを定義する

**実装手順（TDD）**:
1. テスト作成: モック実装を使ったトレイトの振る舞いテスト
2. テスト実行: 失敗を確認
3. 実装: `RegistryPlugin`トレイトを定義

**技術的文脈**:
- `async_trait`を使用
- design.mdの「RegistryPlugin Trait」セクションを参照

**受入基準**:
- [ ] `RegistryPlugin`トレイトが定義されている
- [ ] `name()`, `path_prefix()`, `parse_request()`, `handle_request()`, `filter_metadata()`, `cache_key()`メソッドが定義されている
- [ ] `RequestContext`構造体が定義されている
- [ ] `ParseError`, `ProxyError`, `FilterError`が定義されている
- [ ] `cargo test registry::traits`が通過する

**依存関係**: タスク2.2
**推定工数**: 25分
**ステータス**: `TODO`

#### タスク6.2: PyPIプラグインの実装
**説明**:
TDDで`src/plugins/registry/pypi.rs`にPyPIプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - Simple APIリクエストパースのテスト
   - パッケージファイルリクエストパースのテスト
   - HTMLメタデータフィルタリングのテスト
   - キャッシュキー生成のテスト
2. テスト実行: 失敗を確認
3. 実装: `PyPIPlugin`構造体を実装

**技術的文脈**:
- アップストリーム: `https://pypi.org`
- `/pypi/simple/{package}/`のメタデータ取得
- `/pypi/packages/{package}/{version}/{file}`のファイル取得
- HTML解析で`<a>`タグをフィルタリング

**受入基準**:
- [ ] `PyPIPlugin`構造体が定義されている
- [ ] `RegistryPlugin`トレイトが実装されている
- [ ] Simple APIのHTMLメタデータをパースできる
- [ ] ブロック対象バージョンを含む`<a>`タグを除外できる
- [ ] キャッシュキーが一意に生成される
- [ ] テストが5つ以上存在する
- [ ] `cargo test pypi`が通過する

**依存関係**: タスク6.1
**推定工数**: 50分
**ステータス**: `TODO`

#### タスク6.3: Go Moduleプラグインの実装
**説明**:
TDDで`src/plugins/registry/golang.rs`にGo Moduleプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - `/@v/list`リクエストパースのテスト
   - `/@v/{version}.info`リクエストパースのテスト
   - `/@v/{version}.mod`リクエストパースのテスト
   - `/@v/{version}.zip`リクエストパースのテスト
   - バージョンリストフィルタリングのテスト
2. テスト実行: 失敗を確認
3. 実装: `GoModulePlugin`構造体を実装

**技術的文脈**:
- アップストリーム: `https://proxy.golang.org`
- Go Module Proxy Protocol準拠

**受入基準**:
- [ ] `GoModulePlugin`構造体が定義されている
- [ ] `RegistryPlugin`トレイトが実装されている
- [ ] モジュールパスのエスケープ処理が実装されている
- [ ] `/@v/list`のバージョン一覧をフィルタリングできる
- [ ] テストが5つ以上存在する
- [ ] `cargo test golang`が通過する

**依存関係**: タスク6.1
**推定工数**: 50分
**ステータス**: `TODO`

#### タスク6.4: Cargoプラグインの実装
**説明**:
TDDで`src/plugins/registry/cargo.rs`にCargoプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - インデックスリクエストパースのテスト
   - ダウンロードリクエストパースのテスト
   - JSON Linesフィルタリングのテスト
2. テスト実行: 失敗を確認
3. 実装: `CargoPlugin`構造体を実装

**技術的文脈**:
- Index: `https://index.crates.io`
- Download: `https://static.crates.io/crates`
- Sparse Index形式（JSON Lines）

**受入基準**:
- [ ] `CargoPlugin`構造体が定義されている
- [ ] `RegistryPlugin`トレイトが実装されている
- [ ] クレート名のプレフィックスディレクトリ計算が実装されている
- [ ] JSON Linesからブロック対象バージョンを除外できる
- [ ] テストが4つ以上存在する
- [ ] `cargo test cargo_plugin`が通過する

**依存関係**: タスク6.1
**推定工数**: 45分
**ステータス**: `TODO`

#### タスク6.5: Dockerプラグインの実装
**説明**:
TDDで`src/plugins/registry/docker.rs`にDockerプラグインを実装する

**実装手順（TDD）**:
1. テスト作成:
   - マニフェストリクエストパースのテスト
   - Blobリクエストパースのテスト
   - タグ一覧リクエストパースのテスト
   - 認証トークン中継のテスト
2. テスト実行: 失敗を確認
3. 実装: `DockerPlugin`構造体を実装

**技術的文脈**:
- アップストリーム: `https://registry-1.docker.io`
- Registry API v2準拠
- Docker Hub認証トークンの中継

**受入基準**:
- [ ] `DockerPlugin`構造体が定義されている
- [ ] `RegistryPlugin`トレイトが実装されている
- [ ] `/v2/{name}/manifests/{reference}`がハンドルできる
- [ ] `/v2/{name}/blobs/{digest}`がハンドルできる
- [ ] `/v2/{name}/tags/list`がハンドルできる
- [ ] 認証トークンの中継が実装されている
- [ ] テストが4つ以上存在する
- [ ] `cargo test docker`が通過する

**依存関係**: タスク6.1
**推定工数**: 50分
**ステータス**: `TODO`

---

### フェーズ7: 認証機能
*推定期間: 90分（AIエージェント作業時間）*

#### タスク7.1: トークン管理の実装
**説明**:
TDDで`src/auth/token.rs`にトークン生成・検証機能を実装する

**実装手順（TDD）**:
1. テスト作成:
   - トークン生成のテスト
   - トークンハッシュ化のテスト
   - トークン検証のテスト
2. テスト実行: 失敗を確認
3. 実装: トークン関連関数を実装

**技術的文脈**:
- `rf_`プレフィックス + 32バイトランダム（Base64）
- `argon2`でハッシュ化
- design.mdの「セキュリティ」セクションを参照

**受入基準**:
- [ ] `generate_token()`関数が実装されている
- [ ] トークンが`rf_`で始まる
- [ ] `hash_token()`関数が実装されている（argon2id）
- [ ] `verify_token()`関数が実装されている
- [ ] テストが3つ以上存在する
- [ ] `cargo test token`が通過する

**依存関係**: タスク2.2
**推定工数**: 25分
**ステータス**: `TODO`

#### タスク7.2: レートリミッターの実装
**説明**:
TDDで`src/auth/ratelimit.rs`に認証失敗時のレートリミッターを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 失敗カウントのテスト
   - ブロック判定のテスト
   - ブロック解除のテスト
2. テスト実行: 失敗を確認
3. 実装: `RateLimiter`構造体を実装

**技術的文脈**:
- IP単位でトラッキング
- 10回失敗で5分ブロック
- インメモリで管理

**受入基準**:
- [ ] `RateLimiter`構造体が定義されている
- [ ] `record_failure(ip)`メソッドが実装されている
- [ ] `is_blocked(ip)`メソッドが実装されている
- [ ] `reset(ip)`メソッドが実装されている
- [ ] 設定可能な閾値とブロック時間
- [ ] テストが3つ以上存在する
- [ ] `cargo test ratelimit`が通過する

**依存関係**: なし
**推定工数**: 25分
**ステータス**: `TODO`

#### タスク7.3: AuthManagerの実装
**説明**:
TDDで`src/auth/manager.rs`に認証マネージャーを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 有効なトークンでの認証テスト
   - 無効なトークンでの認証テスト
   - Basic認証のテスト
   - トークンCRUDのテスト
   - エコシステム制限のテスト
2. テスト実行: 失敗を確認
3. 実装: `AuthManager`構造体を実装

**技術的文脈**:
- design.mdの「Auth Manager」セクションを参照
- データベースと連携

**受入基準**:
- [ ] `AuthManager`構造体が定義されている
- [ ] `validate_token(token)`メソッドが実装されている
- [ ] `validate_basic_auth(user, pass)`メソッドが実装されている
- [ ] `create_token(req)`メソッドが実装されている
- [ ] `revoke_token(id)`メソッドが実装されている
- [ ] `list_tokens()`メソッドが実装されている
- [ ] 許可エコシステムのチェックが実装されている
- [ ] テストが5つ以上存在する
- [ ] `cargo test auth::manager`が通過する

**依存関係**: タスク7.1, タスク7.2, タスク2.4
**推定工数**: 40分
**ステータス**: `TODO`

---

### フェーズ8: HTTPサーバー
*推定期間: 120分（AIエージェント作業時間）*

#### タスク8.1: ルーターの構築
**説明**:
TDDで`src/server/router.rs`にaxumルーターを実装する

**実装手順（TDD）**:
1. テスト作成:
   - ヘルスチェックエンドポイントのテスト
   - メトリクスエンドポイントのテスト
   - 各プラグインパスへのルーティングテスト
2. テスト実行: 失敗を確認
3. 実装: ルーター構築関数を実装

**技術的文脈**:
- `axum`を使用
- design.mdのルーティング定義を参照

**受入基準**:
- [ ] `build_router()`関数が実装されている
- [ ] `/health`エンドポイントが定義されている
- [ ] `/metrics`エンドポイントが定義されている
- [ ] `/pypi/*`, `/go/*`, `/cargo/*`, `/v2/*`がルーティングされている
- [ ] `/ui/*`, `/api/*`がルーティングされている
- [ ] テストが4つ以上存在する
- [ ] `cargo test router`が通過する

**依存関係**: タスク6.2-6.5
**推定工数**: 35分
**ステータス**: `TODO`

#### タスク8.2: ミドルウェアの実装
**説明**:
TDDで`src/server/middleware.rs`にミドルウェアを実装する

**実装手順（TDD）**:
1. テスト作成:
   - 認証ミドルウェアのテスト
   - ロギングミドルウェアのテスト
   - トレーシングミドルウェアのテスト
2. テスト実行: 失敗を確認
3. 実装: 各ミドルウェアを実装

**技術的文脈**:
- `tower`のミドルウェアパターン
- 認証スキップパス（/health, /metrics）

**受入基準**:
- [ ] `AuthMiddleware`が実装されている
- [ ] `LoggingMiddleware`が実装されている
- [ ] `TracingMiddleware`が実装されている
- [ ] 認証スキップパスが設定可能
- [ ] テストが3つ以上存在する
- [ ] `cargo test middleware`が通過する

**依存関係**: タスク7.3
**推定工数**: 35分
**ステータス**: `TODO`

#### タスク8.3: サーバー構造体の実装
**説明**:
TDDで`src/server/mod.rs`にサーバー構造体を実装する

**実装手順（TDD）**:
1. テスト作成:
   - サーバー起動のテスト
   - グレースフルシャットダウンのテスト
2. テスト実行: 失敗を確認
3. 実装: `Server`構造体を実装

**技術的文脈**:
- design.mdの「HTTP Server」セクションを参照
- `tokio::signal`でシャットダウン処理

**受入基準**:
- [ ] `Server`構造体が定義されている
- [ ] `Server::new(config)`が実装されている
- [ ] `Server::run(shutdown)`が実装されている
- [ ] グレースフルシャットダウンが実装されている
- [ ] テストが2つ以上存在する
- [ ] `cargo test server`が通過する

**依存関係**: タスク8.1, タスク8.2
**推定工数**: 30分
**ステータス**: `TODO`

#### タスク8.4: プロキシハンドラーの実装
**説明**:
TDDで各レジストリのプロキシハンドラーを実装する

**実装手順（TDD）**:
1. テスト作成:
   - セキュリティチェック統合のテスト
   - キャッシュ統合のテスト
   - アップストリーム転送のテスト
   - ブロック時の403レスポンステスト
2. テスト実行: 失敗を確認
3. 実装: プロキシハンドラーを実装

**技術的文脈**:
- design.mdの「パッケージリクエストフロー」を参照
- モックを使った統合テスト

**受入基準**:
- [ ] プロキシハンドラー関数が実装されている
- [ ] セキュリティプラグインが順番にチェックされる
- [ ] キャッシュヒット時はキャッシュから返却される
- [ ] キャッシュミス時はアップストリームに転送される
- [ ] ブロック対象は403で返却される
- [ ] テストが4つ以上存在する
- [ ] `cargo test proxy`が通過する

**依存関係**: タスク8.1, タスク4.2-4.5, タスク5.2
**推定工数**: 40分
**ステータス**: `TODO`

---

### フェーズ9: OpenTelemetry統合
*推定期間: 60分（AIエージェント作業時間）*

#### タスク9.1: OTELプロバイダーの実装
**説明**:
TDDで`src/otel/mod.rs`にOpenTelemetryプロバイダーを実装する

**実装手順（TDD）**:
1. テスト作成:
   - プロバイダー初期化のテスト
   - トレーサー取得のテスト
   - メーター取得のテスト
2. テスト実行: 失敗を確認
3. 実装: `OtelProvider`構造体を実装

**技術的文脈**:
- `opentelemetry`と`opentelemetry-otlp`を使用
- design.mdの「OTEL Provider」セクションを参照

**受入基準**:
- [ ] `OtelProvider`構造体が定義されている
- [ ] `OtelProvider::new(config)`が実装されている
- [ ] `tracer()`メソッドが実装されている
- [ ] `meter()`メソッドが実装されている
- [ ] `shutdown()`メソッドが実装されている
- [ ] テストが3つ以上存在する
- [ ] `cargo test otel`が通過する

**依存関係**: タスク2.1
**推定工数**: 30分
**ステータス**: `TODO`

#### タスク9.2: メトリクス定義の実装
**説明**:
TDDでアプリケーションメトリクスを定義・実装する

**実装手順（TDD）**:
1. テスト作成:
   - 各メトリクスの記録テスト
2. テスト実行: 失敗を確認
3. 実装: `Metrics`構造体を実装

**技術的文脈**:
- design.mdの「メトリクス定義」セクションを参照

**受入基準**:
- [ ] `Metrics`構造体が定義されている
- [ ] `requests_total` Counterが定義されている
- [ ] `blocked_total` Counterが定義されている
- [ ] `cache_hits_total`, `cache_misses_total` Counterが定義されている
- [ ] `request_duration`, `upstream_duration` Histogramが定義されている
- [ ] `cache_size_bytes`, `blocked_packages_count` Gaugeが定義されている
- [ ] テストが2つ以上存在する
- [ ] `cargo test metrics`が通過する

**依存関係**: タスク9.1
**推定工数**: 20分
**ステータス**: `TODO`

---

### フェーズ10: Web UI
*推定期間: 180分（AIエージェント作業時間）*

#### タスク10.1: Web UI APIエンドポイントの実装
**説明**:
TDDで`src/webui/api.rs`にWeb UI用のAPIエンドポイントを実装する

**実装手順（TDD）**:
1. テスト作成:
   - ダッシュボードAPI（/api/dashboard）のテスト
   - ブロックログAPI（/api/blocks）のテスト
   - セキュリティソースAPI（/api/security-sources）のテスト
   - キャッシュAPI（/api/cache）のテスト
   - ルールAPI（/api/rules）のテスト
   - トークンAPI（/api/tokens）のテスト
2. テスト実行: 失敗を確認
3. 実装: 各APIハンドラーを実装

**技術的文脈**:
- design.mdの「Web UI API エンドポイント」セクションを参照
- JSON形式でレスポンス

**受入基準**:
- [ ] `GET /api/dashboard`が実装されている
- [ ] `GET /api/blocks`が実装されている
- [ ] `GET /api/security-sources`が実装されている
- [ ] `POST /api/security-sources/{name}/sync`が実装されている
- [ ] `GET /api/cache/stats`が実装されている
- [ ] `DELETE /api/cache`が実装されている
- [ ] `GET/POST/PUT/DELETE /api/rules`が実装されている
- [ ] `GET/POST/DELETE /api/tokens`が実装されている
- [ ] テストが8つ以上存在する
- [ ] `cargo test webui::api`が通過する

**依存関係**: タスク2.4, タスク7.3, タスク5.2
**推定工数**: 60分
**ステータス**: `TODO`

#### タスク10.2: Reactフロントエンドの作成
**説明**:
`web/`ディレクトリにReactフロントエンドを作成する

**実装手順**:
1. Viteプロジェクト初期化
2. 基本的なコンポーネント構造作成
3. APIクライアント実装
4. 各ページコンポーネント実装

**技術的文脈**:
- React + TypeScript + Tailwind CSS
- Viteでビルド
- design.mdの「Web UI」セクションを参照

**受入基準**:
- [ ] `web/package.json`が存在する
- [ ] `web/src/App.tsx`が存在する
- [ ] ダッシュボードページが実装されている
- [ ] ブロックログページが実装されている
- [ ] 設定ページが実装されている
- [ ] `npm run build`が成功する
- [ ] ビルド成果物が`web/dist/`に生成される

**依存関係**: タスク10.1
**推定工数**: 90分
**ステータス**: `TODO`

#### タスク10.3: 静的ファイル埋め込みの実装
**説明**:
`rust-embed`を使ってWeb UIをRustバイナリに埋め込む

**実装手順（TDD）**:
1. テスト作成:
   - 静的ファイル取得のテスト
   - Content-Type判定のテスト
2. テスト実行: 失敗を確認
3. 実装: 埋め込みとハンドラーを実装

**技術的文脈**:
- `rust-embed`クレートを使用
- `web/dist/`ディレクトリを埋め込み

**受入基準**:
- [ ] `#[derive(RustEmbed)]`で静的ファイルが埋め込まれている
- [ ] `/ui/`パスで静的ファイルが配信される
- [ ] Content-Typeが適切に設定される
- [ ] テストが2つ以上存在する
- [ ] `cargo test webui::embed`が通過する

**依存関係**: タスク10.2
**推定工数**: 20分
**ステータス**: `TODO`

---

### フェーズ11: 統合・デプロイ
*推定期間: 120分（AIエージェント作業時間）*

#### タスク11.1: main関数の実装
**説明**:
`src/main.rs`にアプリケーションのエントリーポイントを実装する

**実装手順**:
1. 設定ファイル読み込み
2. 各コンポーネント初期化
3. サーバー起動
4. シャットダウン処理

**技術的文脈**:
- `tokio::main`マクロを使用
- `tracing_subscriber`でロギング初期化

**受入基準**:
- [ ] 設定ファイルパスがCLI引数または環境変数で指定可能
- [ ] すべてのコンポーネントが初期化される
- [ ] サーバーが起動する
- [ ] SIGTERM/SIGINTでグレースフルシャットダウン
- [ ] `cargo run`で起動できる

**依存関係**: フェーズ1-10のすべてのタスク
**推定工数**: 30分
**ステータス**: `TODO`

#### タスク11.2: 統合テストの実装
**説明**:
`tests/`ディレクトリに統合テストを実装する

**実装手順（TDD）**:
1. PyPIプロキシの統合テスト
2. 認証フローの統合テスト
3. キャッシュ動作の統合テスト
4. 同期機能の統合テスト

**技術的文脈**:
- `wiremock`でアップストリームをモック
- インメモリSQLiteを使用
- テストサーバーを起動

**受入基準**:
- [ ] `tests/integration_pypi.rs`が存在する
- [ ] `tests/integration_auth.rs`が存在する
- [ ] `tests/integration_cache.rs`が存在する
- [ ] `tests/integration_sync.rs`が存在する
- [ ] 各ファイルに3つ以上のテストが存在する
- [ ] `cargo test --test '*'`が通過する

**依存関係**: タスク11.1
**推定工数**: 45分
**ステータス**: `TODO`

#### タスク11.3: Dockerfileの作成
**説明**:
`deployments/docker/Dockerfile`にマルチステージビルドのDockerfileを作成する

**実装手順**:
1. ビルドステージ（Rust）
2. フロントエンドビルドステージ（Node.js）
3. 実行ステージ（distroless or alpine）

**技術的文脈**:
- マルチステージビルドでイメージサイズ最小化
- `cargo build --release`
- 非rootユーザーで実行

**受入基準**:
- [ ] `Dockerfile`が存在する
- [ ] マルチステージビルドが使用されている
- [ ] 最終イメージサイズが100MB以下
- [ ] `docker build`が成功する
- [ ] `docker run`で起動できる

**依存関係**: タスク11.1
**推定工数**: 25分
**ステータス**: `TODO`

#### タスク11.4: docker-compose.yamlの作成
**説明**:
`deployments/docker-compose/docker-compose.yaml`を作成する

**実装手順**:
1. registry-firewallサービス定義
2. OTEL Collectorサービス定義（オプション）
3. Redisサービス定義（オプション）
4. ボリューム・ネットワーク定義

**技術的文脈**:
- design.mdの設定ファイル構造を参照
- 環境変数で設定をオーバーライド可能に

**受入基準**:
- [ ] `docker-compose.yaml`が存在する
- [ ] registry-firewallサービスが定義されている
- [ ] ボリュームマウントが設定されている
- [ ] 環境変数が設定可能
- [ ] `docker-compose up`で起動できる

**依存関係**: タスク11.3
**推定工数**: 20分
**ステータス**: `TODO`

---

## タスクステータスの凡例
- `TODO` - 未着手
- `IN_PROGRESS` - 作業中
- `BLOCKED` - 依存関係や問題によりブロック中
- `REVIEW` - レビュー待ち
- `DONE` - 完了

---

## リスクと軽減策

### リスク1: OSV/OpenSSFデータソースの仕様変更
**影響度**: 中
**発生確率**: 低
**軽減策**: プラグインアーキテクチャにより、データソースごとに独立して対応可能。定期的にアップストリームの変更を監視する。

### リスク2: 大量パッケージ同期時のメモリ使用量
**影響度**: 高
**発生確率**: 中
**軽減策**: ストリーミング処理を採用し、一度にすべてのデータをメモリに載せない。エコシステムごとに分割同期する。

### リスク3: アップストリームレジストリの一時的な障害
**影響度**: 中
**発生確率**: 高
**軽減策**: リトライ機能とキャッシュフォールバックにより、一時的な障害を吸収する。

### リスク4: Raspberry Pi 4でのリソース制約
**影響度**: 中
**発生確率**: 中
**軽減策**: メモリ使用量256MB以下を目標に設計。不要なエコシステムは無効化可能。

---

## 備考

### TDD実施のポイント
- 各タスクでテストを先に書き、Red→Green→Refactorのサイクルを守る
- テストのみのコミットと実装のコミットを分ける
- モックを活用して単体テストの独立性を保つ

### コーディング規約
- `cargo fmt`でフォーマット
- `cargo clippy`で静的解析
- ドキュメントコメント（`///`）を公開APIに付与

### 依存関係グラフ
```
フェーズ1（基盤）
    ↓
フェーズ2（コアインフラ）
    ↓
    ├─→ フェーズ3（同期インフラ）
    │       ↓
    │   フェーズ4（セキュリティプラグイン）
    │
    ├─→ フェーズ5（キャッシュ）
    │
    └─→ フェーズ6（レジストリプラグイン）
            ↓
        フェーズ7（認証）
            ↓
        フェーズ8（HTTPサーバー）
            ↓
        フェーズ9（OTEL）
            ↓
        フェーズ10（Web UI）
            ↓
        フェーズ11（統合・デプロイ）
```

---

## 変更履歴

| バージョン | 日付 | 変更内容 | 作成者 |
|-----------|------|----------|--------|
| 1.0 | 2025-12-03 | 初版作成 | - |
