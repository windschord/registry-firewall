# 要件定義書: Dual Docker Image Release + Swagger自動生成

## 概要

本ドキュメントは、registry-firewallに「デュアルDockerイメージリリース」と「OpenAPI仕様の自動生成」機能を追加するための要件を定義する。EARS記法（Easy Approach to Requirements Syntax）を用いて記述する。

### 背景

現在のリリースパイプラインは単一のDockerイメージのみをビルドしており、Web UIを含む全機能が常に含まれる。運用環境によってはWeb UIが不要（CI/CDパイプライン、ヘッドレスサーバー等）であり、その場合でもrust-embedによるUIアセット埋め込みが発生する。また、API仕様をSwagger/OpenAPI形式で提供する手段がなく、外部システムとのインテグレーション時に仕様を手動で参照する必要がある。

### 関連ドキュメント

- 既存要件: `docs/requirements.md`（REQ-001〜REQ-045、NFR-001〜NFR-024）
- 技術設計: `docs/design.md`
- タスク計画: `docs/tasks.md`

### 現在の実装状態（起点）

| コンポーネント | 現状 |
|--------------|------|
| Cargo.toml | `features`セクション未定義。`rust-embed`と`mime_guess`は通常依存 |
| Dockerfile | マルチステージビルド（rust:1-bookworm → debian:bookworm-slim）。`web/dist`をコピー |
| release.yml | 単一イメージのビルド・プッシュ。GHCR使用。linux/amd64+arm64 |
| src/webui/mod.rs | `RustEmbed`で`web/dist`を埋め込み |
| src/server/router.rs | `/ui`、`/ui/*path`ルートがハードコード |

---

## ユーザーストーリー

### ストーリーA: 軽量APIのみイメージ

**私は** 運用者として
**〜したい** Web UIが不要な環境（CI/CD、ヘッドレスサーバー）向けに軽量なDockerイメージを使いたい
**なぜなら** UIアセットの埋め込みによるバイナリ肥大化を避け、攻撃対象領域を最小化したいから

#### 受入基準（EARS記法）

- **REQ-101** [Ubiquitous] Cargo.tomlは`[features]`セクションを持ち、`default = ["webui"]`と`webui = ["rust-embed", "mime_guess"]`を定義しなければならない
- **REQ-102** [State-driven] `webui` featureが無効化された状態でビルドされた場合、バイナリはrust-embedおよびmime_guessの依存を含んではならない
- **REQ-103** [State-driven] `webui` featureが無効化された状態でビルドされた場合、`/ui`および`/ui/*`エンドポイントはルーターに登録されず、リクエストは404を返さなければならない
- **REQ-104** [Event-driven] `--no-default-features`フラグを指定してビルドした時、システムはすべてのAPIエンドポイント（`/api/*`）を正常に提供しなければならない
- **REQ-105** [State-driven] `webui` featureが無効化された状態でビルドされた場合、`webui`モジュール（`src/webui/`）のコードはコンパイルの対象外となり、コンパイル時間を削減しなければならない
- **REQ-106** [Ubiquitous] APIのみビルド用の`deployments/docker/Dockerfile`は`--no-default-features`でビルドし、GUI付きビルド用の`deployments/docker/Dockerfile.full`は`--features webui`およびNode.jsフロントエンドビルドステージを含めなければならない
- **REQ-107** [Event-driven] APIのみイメージ（`latest`、`X.Y.Z`）がビルドされた時、タグには`-full`サフィックスが付かないデフォルトタグが使用されなければならない

#### 受入テスト

```shell
# featureなしビルドのテスト
cargo build --no-default-features
# → webui関連のコンパイルエラーがないこと

cargo test --no-default-features
# → すべてのテストがパスすること

# /ui エンドポイントが存在しないことの確認
curl -s http://localhost:8080/ui
# → HTTP 404が返ること

# /api エンドポイントが動作することの確認
curl -s http://localhost:8080/api/dashboard
# → HTTP 200が返ること
```

---

### ストーリーB: フル機能GUI付きイメージ

**私は** 管理者として
**〜したい** Web UIでブロック状況を視覚的に確認・管理したい場合にGUI付きイメージを使いたい
**なぜなら** CLIを使わず直感的にシステム状態を把握・操作したいから

#### 受入基準（EARS記法）

- **REQ-110** [Ubiquitous] GitHub Actionsリリースワークフローは、同一リリースで2種類のDockerイメージをビルドしてGHCRにプッシュしなければならない
- **REQ-111** [Event-driven] リリースタグ`v X.Y.Z`がプッシュされた時、APIのみイメージは`latest`および`X.Y.Z`タグでGHCRにプッシュされなければならない
- **REQ-112** [Event-driven] リリースタグ`v X.Y.Z`がプッシュされた時、GUI付きイメージは`latest-full`および`X.Y.Z-full`タグでGHCRにプッシュされなければならない
- **REQ-113** [Event-driven] プレリリースタグ（`v X.Y.Z-alpha`等、ハイフンを含むタグ）がプッシュされた時、`latest`および`latest-full`タグは付与されず、バージョンタグのみ付与されなければならない
- **REQ-114** [State-driven] `webui` featureが有効化された状態でビルドされた場合、`/ui`エンドポイントは`web/dist`の組み込みアセットを正常に配信しなければならない
- **REQ-115** [Ubiquitous] 両イメージは`linux/amd64`および`linux/arm64`の両プラットフォーム向けにビルドされなければならない
- **REQ-116** [Ubiquitous] 両イメージのDockerfileは同一のベースイメージ（`debian:bookworm-slim`）を使用しなければならない

#### 受入テスト

```shell
# GHCRでのイメージタグ確認（v1.2.3リリース時）
docker pull ghcr.io/windschord/registry-firewall:latest       # APIのみ
docker pull ghcr.io/windschord/registry-firewall:1.2.3        # APIのみ
docker pull ghcr.io/windschord/registry-firewall:latest-full  # GUI付き
docker pull ghcr.io/windschord/registry-firewall:1.2.3-full   # GUI付き

# full イメージでの /ui エンドポイント確認
docker run -p 8080:8080 ghcr.io/windschord/registry-firewall:latest-full
curl -s http://localhost:8080/ui
# → HTTP 200が返ること（もしくはindex.htmlが返ること）
```

---

### ストーリーC: OpenAPI仕様の自動生成

**私は** 開発者/インテグレーターとして
**〜したい** APIの仕様書（Swagger）をリリースごとに最新状態で参照したい
**なぜなら** 外部システムとの連携実装時に手動でエンドポイントを調査する手間を省きたいから

#### 受入基準（EARS記法）

- **REQ-120** [Ubiquitous] Cargo.tomlは`utoipa`クレートを依存関係に含み、axum向けの統合（`utoipa-axum`）を使用しなければならない
- **REQ-121** [Ubiquitous] すべての管理APIエンドポイント（`/api/*`）はutoipaの`#[utoipa::path]`アトリビュートでアノテーションされなければならない
- **REQ-122** [Ubiquitous] リクエスト・レスポンスのすべての構造体は`ToSchema`トレイトをderiveしなければならない
- **REQ-123** [Event-driven] `cargo run --features swagger-gen -- --generate-swagger`コマンドが実行された時、システムは`swagger.json`をカレントディレクトリに出力しなければならない
- **REQ-124** [Event-driven] リリースタグがプッシュされた時、GitHub Actionsワークフローは`swagger.json`を自動生成し、GitHubリリースのアセットとして添付しなければならない
- **REQ-125** [Ubiquitous] 生成された`swagger.json`はOpenAPI 3.0仕様に準拠しなければならない
- **REQ-126** [Ubiquitous] `swagger.json`にはAPIのタイトル、バージョン（Cargo.tomlのバージョンと一致）、説明文を含めなければならない
- **REQ-127** [State-driven] `webui` featureが有効化されている場合、`/api/swagger-ui`エンドポイントにアクセスすると、インタラクティブなSwagger UIが表示されなければならない
- **REQ-128** [State-driven] `webui` featureが無効化されている場合、Swagger UIエンドポイントは提供されなくてよい（swagger.jsonのリリース添付は常に行う）
- **REQ-129** [Ubiquitous] 生成された`swagger.json`はすべての認証方式（BearerToken、Basic認証）をsecuritySchemesとして記述しなければならない

#### 受入テスト

```shell
# swagger.json の生成確認
cargo run --features swagger-gen -- --generate-swagger
ls -la swagger.json
# → ファイルが生成されること

# OpenAPI 3.0 検証
npx @redocly/cli lint swagger.json
# → バリデーションエラーがないこと

# バージョン一致確認
CARGO_VERSION=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')
SWAGGER_VERSION=$(jq -r '.info.version' swagger.json)
test "$CARGO_VERSION" = "$SWAGGER_VERSION"
# → バージョンが一致すること

# GitHubリリースアセット確認（リリース後）
gh release view v1.2.3 --json assets | jq '.[].name' | grep swagger.json
# → swagger.json がアセットに含まれること
```

---

## 非機能要件

### イメージサイズ

- **NFR-101** [Ubiquitous] APIのみイメージ（`latest`）の圧縮サイズは80MB以下でなければならない
- **NFR-102** [Ubiquitous] GUI付きイメージ（`latest-full`）の圧縮サイズは120MB以下でなければならない
- **NFR-103** [Ubiquitous] APIのみイメージはGUI付きイメージと比較して、少なくとも20%小さくなければならない

### ビルド時間

- **NFR-104** [Ubiquitous] GitHub Actionsキャッシュ（`Swatinem/rust-cache`）を利用した場合、各イメージの増分ビルド時間は10分以内でなければならない
- **NFR-105** [Ubiquitous] APIのみイメージのビルドはGUI付きイメージのビルドと並列実行可能でなければならない（GitHub Actionsの並列ジョブとして）

### 後方互換性

- **NFR-106** [Ubiquitous] `latest`タグのセマンティクスがGUI付きからAPIのみに変わることは、破壊的変更としてCHANGELOGおよびリリースノートで明示的に告知されなければならない
- **NFR-107** [Ubiquitous] `webui` featureが有効化された状態でビルドした場合、既存の`/ui/*`エンドポイントおよびすべての`/api/*`エンドポイントの動作が変わってはならない

### セキュリティ

- **NFR-108** [Ubiquitous] APIのみイメージはrust-embedによるファイルシステムアクセスのコードパスを含まないため、ファイル読み取り関連のCVEリスクが低減されなければならない
- **NFR-109** [Ubiquitous] swagger.jsonは本番環境の内部ホスト名やIPアドレスを含んではならない（サーバー定義にはプレースホルダーを使用する）

---

## 制約事項

| 制約 | 内容 |
|-----|------|
| 既存テストの維持 | 既存の`cargo test --all-features`がすべてパスし続けること |
| Cargo.tomlの変更 | `rust-embed`と`mime_guess`を`[dependencies]`から`[dev-dependencies]`相当ではなくfeature依存に移動する |
| GHCR命名規則 | タグ命名はセマンティックバージョニングに従い、既存のGHCR URLパターンを維持する |
| CI/CDの変更最小化 | release.ymlへの変更はdual image buildのために最小限の追加にとどめる |
| utoipa統合 | `utoipa-axum`を使用し、既存のaxumルーター構造への変更を最小限にする |

---

## 用語集

| 用語 | 定義 |
|------|------|
| Cargo feature | Rustの条件付きコンパイル機構。`Cargo.toml`の`[features]`セクションで定義する |
| GHCR | GitHub Container Registry。GitHubが提供するコンテナイメージレジストリ |
| utoipa | Rust向けOpenAPI仕様自動生成クレート。マクロベースでエンドポイントを注釈する |
| OpenAPI | RESTful APIの仕様記述標準（旧Swagger）。バージョン3.0を使用 |
| swagger.json | OpenAPI仕様をJSON形式で出力したファイル |
| APIのみイメージ | `webui` featureなし（`--no-default-features`）でビルドされたDockerイメージ |
| GUI付きイメージ | `webui` feature有効（デフォルト）でビルドされたDockerイメージ |
| `-full` サフィックス | GUI付きDockerイメージを示すタグの接尾辞（例: `latest-full`、`1.2.3-full`） |
| `swagger-gen` feature | swagger.json生成用コマンドラインオプションを有効にするCargo feature |

---

## 変更履歴

| バージョン | 日付 | 変更内容 | 作成者 |
|-----------|------|----------|--------|
| 1.0 | 2026-03-18 | 初版作成（Dual Docker Image Release + Swagger自動生成） | - |
