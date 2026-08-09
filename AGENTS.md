# AGENTS.md

ARROW (**A**synchronous **R**ust **R**estaurant **O**rder **W**orkflow) Server: Axum 0.8 + diesel-async + MySQL REST API, Rust edition 2024.

## Commands

- Build/run: `cargo build`, `cargo run` (binds `0.0.0.0:3000`, all routes nested under `/api/v1/*`, CORS configured by `CORS_ALLOWED_ORIGINS`)
- Tests: `cargo test` — one integration binary at `tests/integration/` hitting a **real MySQL** instance via `DATABASE_URL`; the suite is fully parallel (no `--test-threads=1` needed). Test rows accumulate in the shared DB — periodically reset with `scripts/cleanup_test_db.sql` (TRUNCATE children-first; re-seed happens on next server start / test run)
- Migrations: `diesel migration run`, `diesel migration generate NAME` — stored in the non-standard dir `src/data/migrations` (per `diesel.toml`); after schema changes run `diesel print-schema` (writes `src/data/models/schema.rs`)
- CI (`.github/workflows/rust.yml`) only runs `cargo build` on master — no clippy/fmt/test gate

## Lint

- Deny lints live in `[lints.clippy]` in Cargo.toml (package-wide): `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`
- `src/` must stay clippy-clean with NO `#[allow(...)]` annotations — errors are handled via typed error enums (hand-written `Display`/`std::error::Error` impls), never suppressed
- Tests are exempt via one crate-level `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]` at the root of the single test binary (`tests/integration/main.rs`); tests always live in `tests/` (no `#[cfg(test)]` in `src/`)
- No `clippy.toml` — all lint configuration lives in Cargo.toml
- Clippy is local-only today: CI runs `cargo build` only

## Setup

- Required env, loaded from `.env` via dotenvy in `src/data/database.rs`: `DATABASE_URL`, `JWT_SECRET`, `JWT_EXPIRATION_MINUTES` — see `.env.example` and `compose.yml.example` (local MySQL)
- Optional Azure Blob Storage env (all in `src/api/config.rs`): `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_CONTAINER`, `AZURE_STORAGE_ACCOUNT_KEY` (dev SAS signing), `IMAGE_SAS_TTL_MINUTES`, `IMAGE_MAX_BYTES` — unset account/container disables the store (image endpoints return 503); tests run without Azure via the `StubBlobStore` in `tests/integration/common/mod.rs`
- `Database::new()` is cheap: it clones a handle to a global `once_cell::sync::Lazy` deadpool pool; call `get_connection().await` per operation
- Lib crate is named `arrow_server_lib` — integration tests import it that way, not `arrow_server`

## Architecture

- Layered: `src/api/` (controllers + `dto/`, `routes/`, `extractors.rs` `AccessClaims`, `server.rs`) → `src/services/` (stateless business logic) → `src/data/` (`database.rs`, `models/`, `repos/`), plus `src/security/` (JWT in `jwt.rs`, argon2 in `auth.rs`)
- Blob storage behind a trait: `BlobStore` in `src/services/blob_storage_service.rs` (`AzureBlobStore` impl = azure_storage_blob + hand-rolled service SAS; `BlobStoreError` typed errors); `ProductService::with_blob_store(Arc<dyn BlobStore>)` injects a stub in tests, `new()` builds the production store lazily
- Repository pattern: `Repository` trait in `src/data/repos/traits/repository.rs` uses GATs (`type NewItem<'a>`, `type UpdateForm<'a>`, `Id = i32`); concrete impls live in `src/data/repos/implementors/` with `#[async_trait]`
- Each entity in `src/data/models/` has three structs: `Xxx` (`Queryable, Selectable, Identifiable`), `NewXxx<'a>` (`Insertable`), `UpdateXxx<'a>` (`AsChangeset`); DTO ↔ model conversions are `From` impls in `src/utils/mappers.rs`

## Conventions

- All writes (insert/update/delete) MUST be wrapped in `conn.transaction(|c| async move { ... }.scope_boxed()).await` — `.scope_boxed()` is required by diesel-async (see any file in `implementors/`)
- Repos return `Ok(None)` for both NotFound and empty loads — never `Ok(vec![])` or a NotFound error
- CPU-bound work (argon2 hashing in `AuthService`) goes through `tokio::task::spawn_blocking`
- Rate limiting (`tower_governor`) is configured in `src/api/server.rs` only: `GovernorLayer` applied to the nested auth and orders routers, tunables are `const`s at the top of that file. `SmartIpKeyExtractor` trusts `X-Forwarded-For`/`X-Real-IP`/`Forwarded` (spoofable if the app is reachable without the ACA ingress in front — acceptable for demo)
- Adding an entity: migration → run → `diesel print-schema` → three model structs → repo trait impl → service → controller/DTO → route; wire each in the matching `mod.rs`
- Integration tests own their fixtures: every row is created through the factories in `tests/integration/common/mod.rs` with `uniq()`-generated names, tests assert only on rows they created, and nothing ever wipes tables (rows accumulate in the shared DB). The only `#[serial_test::serial(admin_seed)]` tests are the ones touching the fixed env-admin row (seed/login/register-conflict in `user_controller_tests.rs`). One canonical test per behavior lives at the lowest layer that exercises it: repo = CRUD/constraints, service = permissions/business rules, controller = HTTP contract only

## Docs

- `API.md` and `openapi.yaml` at the root; ready-to-use API collection in `bruno/`
