# Arrow Server - Copilot Instructions

## Project Overview
Arrow Server (Asynchronous Rust Restaurant Order Workflow) is a REST API for restaurant order management using **Axum**, **Diesel** (async), and **MySQL**. Designed for high-performance concurrent order processing with Argon2 authentication.

## Planned Features (API Scope)
- REST endpoints for order submission, status updates, and retrieval
- Order validation, total calculation, and workflow state management
- User/role management with Argon2 password hashing
- Role-based access control (customer vs employee permissions)
- MySQL persistence for orders, users, sales records with audit timestamps
- Photo/media endpoints serving files from filesystem (optional: Azure Blob Storage)

## Architecture

```
src/
├── api/
│   ├── server.rs       # Server setup (start function, router configuration)
│   ├── routes/         # Route definitions (grouped by domain)
│   ├── controllers/    # HTTP handlers (receive DTOs, return responses)
│   │   └── dto/        # Request/response data transfer objects
│   ├── extractors.rs   # Axum extractors (e.g., AccessClaims)
│   └── errors.rs       # API-specific errors
├── services/           # Business logic (auth, validation, hashing)
├── security/           # Security components (JWT, Auth)
├── data/
│   ├── database.rs     # Connection pool (Lazy static, deadpool)
│   ├── models/         # Diesel ORM structs (Queryable, Insertable)
│   ├── repos/
│   │   ├── traits/     # Repository trait definitions
│   │   └── implementors/ # Concrete repo implementations
│   └── migrations/     # Diesel SQL migrations
├── builders/           # Builder pattern implementations
└── utils/
    └── mappers.rs      # DTO <-> Model conversions via From trait
```

## Key Patterns

### Repository Pattern
- Define traits in `src/data/repos/traits/repository.rs` with GATs for type flexibility
- Implement in `src/data/repos/implementors/` using async Diesel
- Example: `UserRepo` implements `Repository` trait with `async_trait`

```rust
// Pattern for new repos:
#[async_trait]
impl Repository for XxxRepo {
    type Id = i32;
    type Item = Xxx;
    type NewItem<'a> = NewXxx<'a>;
    type UpdateForm<'a> = UpdateXxx<'a>;
    // ... implement methods
}
```

### Model Structs
Each entity in `src/data/models/` needs three structs:
- `Xxx`: Main queryable struct with `#[derive(Queryable, Selectable, Identifiable)]`
- `NewXxx<'a>`: For inserts with `#[derive(Insertable)]`
- `UpdateXxx<'a>`: For updates with `#[derive(AsChangeset)]`

### DTOs and Mappers
- DTOs in `src/api/controllers/dto/` use `#[derive(Serialize, Deserialize)]`
- Implement `From<&'a XxxDTO> for NewXxx<'a>` in `src/utils/mappers.rs`

### Database Access Pattern
```rust
let db = Database::new().await;
let mut conn = db.get_connection().await.map_err(/* ... */)?;
// Use diesel async operations with &mut conn
```
Note: `Database::new()` is cheap as it clones a handle to a global `Lazy` static pool.

### Transaction Pattern (Critical for Diesel Async)
All write operations (insert/update/delete) MUST wrap in transactions with `.scope_boxed()`:

```rust
conn.transaction(|connection| {
    async move {
        diesel::insert_into(table)
            .values(&item)
            .execute(connection)
            .await?;
        Ok(())
    }
    .scope_boxed()  // Required for diesel-async transactions
})
.await
```

### Service Layer
- Services (e.g., `AuthService`) are stateless structs.
- CPU-intensive tasks (like password hashing) should be offloaded using `tokio::task::spawn_blocking`.

### Authentication & Security
- JWT implementation in `src/security/` using `jsonwebtoken`.
- `AccessClaims` extractor in `src/api/extractors.rs` handles token validation.
- Use `JwtService` for token generation and decoding.

## Commands

### Build & Run
```fish
cargo build                              # Compile
cargo run                                # Start server on http://127.0.0.1:3000
DATABASE_URL=mysql://... cargo run       # With explicit DB URL
```

### Docker Build
```fish
docker build -t arrow_server .           # Build using cargo-chef caching
docker run -p 3000:3000 arrow_server     # Run container
```

### Database Migrations
```fish
diesel setup                             # Initialize database
diesel database reset                    # Revert all migrations
diesel migration run                     # Apply pending migrations
diesel migration generate NAME           # Create new migration in src/data/migrations/
diesel print-schema                      # Regenerate src/data/models/schema.rs
```

### Testing
```fish
cargo test                               # Run all tests
cargo test -- --test-threads=1           # Serial execution (use `#[serial_test::serial]`)
```

## Configuration
- `DATABASE_URL` env var required (loaded from `.env` via `dotenvy`)
- `diesel.toml` configures schema output to `src/data/models/schema.rs`
- Migrations stored in `src/data/migrations/` (non-standard path)

## Adding New Features

1. **New table**: Create migration → run → regenerate schema
2. **New model**: Add to `src/data/models/` with three struct variants
3. **New repo**: Add trait impl in `implementors/`, wire in `mod.rs`
4. **New endpoint**: Controller in `api/controllers/`, register route in `api/routes/`
5. **Wire modules**: Update `mod.rs` files in each directory
