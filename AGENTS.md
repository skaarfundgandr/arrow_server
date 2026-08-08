# AGENTS.md

ARROW (**A**synchronous **R**ust **R**estaurant **O**rder **W**orkflow) Server: Axum 0.8 + diesel-async + MySQL REST API, Rust edition 2024.

## Commands

- Build/run: `cargo build`, `cargo run` (binds `0.0.0.0:3000`, all routes nested under `/api/v1/*`, CORS allow-any)
- Tests: `cargo test` — integration tests in `tests/` hit a **real MySQL** instance via `DATABASE_URL`; use `cargo test -- --test-threads=1` (DB-shared tests are annotated `#[serial_test::serial]`)
- Migrations: `diesel migration run`, `diesel migration generate NAME` — stored in the non-standard dir `src/data/migrations` (per `diesel.toml`); after schema changes run `diesel print-schema` (writes `src/data/models/schema.rs`)
- CI (`.github/workflows/rust.yml`) only runs `cargo build` on master — no clippy/fmt/test gate

## Lint

- Deny lints live in `[lints.clippy]` in Cargo.toml (package-wide): `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`
- `src/` must stay clippy-clean with NO `#[allow(...)]` annotations — errors are handled via typed error enums (hand-written `Display`/`std::error::Error` impls), never suppressed
- Tests are exempt via a crate-level `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]` at the top of each file in `tests/`; tests always live in `tests/` (no `#[cfg(test)]` in `src/`)
- No `clippy.toml` — all lint configuration lives in Cargo.toml
- Clippy is local-only today: CI runs `cargo build` only

## Setup

- Required env, loaded from `.env` via dotenvy in `src/data/database.rs`: `DATABASE_URL`, `JWT_SECRET`, `JWT_EXPIRATION_MINUTES` — see `.env.example` and `compose.yml.example` (local MySQL)
- `Database::new()` is cheap: it clones a handle to a global `once_cell::sync::Lazy` deadpool pool; call `get_connection().await` per operation
- Lib crate is named `arrow_server_lib` — integration tests import it that way, not `arrow_server`

## Architecture

- Layered: `src/api/` (controllers + `dto/`, `routes/`, `extractors.rs` `AccessClaims`, `server.rs`) → `src/services/` (stateless business logic) → `src/data/` (`database.rs`, `models/`, `repos/`), plus `src/security/` (JWT in `jwt.rs`, argon2 in `auth.rs`)
- Repository pattern: `Repository` trait in `src/data/repos/traits/repository.rs` uses GATs (`type NewItem<'a>`, `type UpdateForm<'a>`, `Id = i32`); concrete impls live in `src/data/repos/implementors/` with `#[async_trait]`
- Each entity in `src/data/models/` has three structs: `Xxx` (`Queryable, Selectable, Identifiable`), `NewXxx<'a>` (`Insertable`), `UpdateXxx<'a>` (`AsChangeset`); DTO ↔ model conversions are `From` impls in `src/utils/mappers.rs`

## Conventions

- All writes (insert/update/delete) MUST be wrapped in `conn.transaction(|c| async move { ... }.scope_boxed()).await` — `.scope_boxed()` is required by diesel-async (see any file in `implementors/`)
- Repos return `Ok(None)` for both NotFound and empty loads — never `Ok(vec![])` or a NotFound error
- CPU-bound work (argon2 hashing in `AuthService`) goes through `tokio::task::spawn_blocking`
- Rate limiting (`tower_governor`) is configured in `src/api/server.rs` only: `GovernorLayer` applied to the nested auth and orders routers, tunables are `const`s at the top of that file. `SmartIpKeyExtractor` trusts `X-Forwarded-For`/`X-Real-IP`/`Forwarded` (spoofable if the app is reachable without the ACA ingress in front — acceptable for demo)
- Adding an entity: migration → run → `diesel print-schema` → three model structs → repo trait impl → service → controller/DTO → route; wire each in the matching `mod.rs`

## Docs

- `API.md` and `openapi.yaml` at the root; ready-to-use API collection in `bruno/`
