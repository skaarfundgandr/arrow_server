# ARROW Server

**A**synchronous **R**ust **R**estaurant **O**rder **W**orkflow — a high-performance, async-first REST API backend for a **mini QR-ordering system**: guests scan a QR code, browse the menu, place an order, and pay — no app install, no account required.

Built with Rust, [Axum](https://crates.io/crates/axum), [diesel-async](https://crates.io/crates/diesel-async) and MySQL, ARROW manages the full ordering lifecycle: public menu browsing, guest & registered ordering, JWT authentication with role-based access control, a signed receipt-link flow, kitchen order status management, and a deterministic mock payment.

## Highlights

- **QR ordering flow** — an admin-only endpoint renders an SVG QR code; scanning it redirects the guest (302) to the ordering page.
- **Guest & attributed ordering** — `POST /api/v1/orders` works without a JWT (guest, `user_id: null`); with a valid JWT the order is attributed to the user; an invalid JWT is rejected with 401.
- **Signed receipt links** — every created order returns an `order_url` (HMAC-SHA256 signed, expiring). Anyone holding it can view and pay the order without an account; tampering → 400, expiry → 410.
- **Env-seeded admin** — the admin account is created automatically at server startup from `ADMIN_USERNAME` / `ADMIN_PASSWORD` (idempotent). No manual DB insert needed.
- **Deterministic mock payment** — payment succeeds unless the order total exceeds `MAX_PAYMENT_AMOUNT` (default 1000.00), which makes the failure path easy to demo and test.
- **Azure Blob Storage product images** — uploads go into a private container through the backend (magic-byte MIME validation, size cap), and read endpoints return short-lived minted SAS URLs instead of the stored blob path.

## Technologies & Libraries

* **[Axum](https://crates.io/crates/axum)** — ergonomic, modular web framework on top of Hyper/Tokio.
* **[Diesel Async](https://crates.io/crates/diesel-async)** — fully asynchronous ORM over MySQL, with a `deadpool` connection pool.
* **[Tokio](https://crates.io/crates/tokio)** — the industry-standard async runtime.
* **[Argon2](https://crates.io/crates/argon2)** — prize-winning password hashing.
* **[Jsonwebtoken](https://crates.io/crates/jsonwebtoken)** — JWT creation/validation.
* **[HMAC-SHA256](https://crates.io/crates/hmac) + [hex](https://crates.io/crates/hex)** — signing and encoding of order receipt links.
* **[qrcode](https://crates.io/crates/qrcode)** — SVG QR rendering.
* **[Bigdecimal](https://crates.io/crates/bigdecimal)** — arbitrary-precision currency arithmetic.
* **[Tracing](https://crates.io/crates/tracing)** — structured, event-based diagnostics.

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [MySQL](https://dev.mysql.com/downloads/) 8.x, running locally
- [diesel_cli](https://diesel.rs/guides/getting-started) with the `mysql` feature:

```bash
cargo install diesel_cli --no-default-features --features mysql
```

Optional: [Docker Compose](https://docs.docker.com/compose/) (see `compose.yml.example`) or [Bruno](https://www.usebruno.com/) for API testing (see `bruno/`).

## Quick Start

### 1. Environment

Copy the example and fill in real values (every required variable is marked):

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | **yes** | — | MySQL connection string (`mysql://user:pass@host:3306/db`) |
| `JWT_SECRET` | **yes** | — | Secret used to sign/verify JWT access tokens |
| `JWT_EXPIRATION_MINUTES` | no | `60` | Access-token lifetime in minutes |
| `ADMIN_USERNAME` | no | `admin` | Username of the seeded admin account |
| `ADMIN_PASSWORD` | **yes** | — | Password of the seeded admin account |
| `QR_SIGNING_SECRET` | **yes** | — | HMAC-SHA256 key for signed `order_url` links |
| `ORDER_LINK_EXPIRATION_MINUTES` | no | `1440` | `order_url` lifetime in minutes (24h) |
| `API_BASE_URL` | no | `http://localhost:3000` | Public API base URL used when building links/QRs |
| `ORDERING_BASE_URL` | no | `{API_BASE_URL}/api/v1/products` | Redirect target of `GET /api/v1/qr/visit` |
| `MAX_PAYMENT_AMOUNT` | no | `1000.00` | Order total above which mock payment fails |
| `AZURE_STORAGE_ACCOUNT` | no | — | Azure storage account for product image uploads (unset → image endpoints return 503) |
| `AZURE_STORAGE_CONTAINER` | no | — | Private container that holds uploaded product images |
| `AZURE_STORAGE_ACCOUNT_KEY` | no | — | Dev account key: signs the short-lived SAS tokens (upload/delete/read); unset → managed identity auth, no SAS minting |
| `IMAGE_SAS_TTL_MINUTES` | no | `15` | Lifetime of minted read SAS URLs in minutes |
| `IMAGE_MAX_BYTES` | no | `2097152` | Maximum accepted product image size in bytes (2 MiB) |

> Missing `DATABASE_URL`, `JWT_SECRET`, `ADMIN_PASSWORD` or `QR_SIGNING_SECRET` fails startup: the error is logged via `tracing` and the process exits with a non-zero status.

### 2. Create the database and run migrations

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS test_db;"
diesel migration run
```

This applies all migrations from `src/data/migrations/` (users, products, orders, order_products, categories, roles, user_roles, plus payment/guest-order changes). A single-file snapshot of the full schema is also available as `schema.sql` at the repo root.

### 3. Optional: seed roles and a starter menu

```bash
mysql -u root -p test_db < seed.sql
```

`seed.sql` inserts the `ADMIN` and `CUSTOMER` roles and a small menu (3 categories, 7 products — including a 550.00 item so a multi-item order can exceed `MAX_PAYMENT_AMOUNT` and demonstrate payment failure). It deliberately contains **no admin user**: the admin account is seeded from the environment at server startup.

### 4. Run

```bash
cargo run
```

The server listens on port 3000. **On first start it seeds the admin account** (username `ADMIN_USERNAME`, password `ADMIN_PASSWORD`) and the `ADMIN`/`CUSTOMER` roles if missing — log in at `POST /api/v1/auth/login` with those credentials. Registration of a user named exactly `ADMIN_USERNAME` is rejected with 409; every other registration is auto-assigned the `CUSTOMER` role.

## API Overview

Base URL: `http://localhost:3000/api/v1` — full reference: [API.md](API.md), machine-readable spec: [openapi.yaml](openapi.yaml).

**Public (no auth)**

| Method | Path | Description |
|---|---|---|
| GET | `/products` | List products |
| GET | `/products/{id}` | Product details |
| GET | `/categories` | List categories |
| GET | `/categories/{name}/products` | Products in a category |
| POST | `/auth/register` | Register (→ CUSTOMER role; reserved admin username → 409) |
| POST | `/orders` | Create order — guest (`user_id: null`) or JWT-attributed; returns `{ order, order_url }` (201) |
| GET | `/qr/visit` | 302 redirect to the ordering page |

**Authenticated (JWT, any role)**

| Method | Path | Description |
|---|---|---|
| GET | `/auth/refresh` | Rotate the access token |
| GET | `/users` | List users (`user_id` hidden for non-admins) |
| GET | `/users/{id}` · `/users/search?username=` | User details |
| GET | `/orders/{id}` | Order details — ADMIN, JWT owner, or valid `order_url` |
| POST | `/orders/{id}/pay` | Mock payment — ADMIN or valid `order_url` (owner JWT alone does not suffice) |
| POST | `/orders/{id}/cancel` | Cancel — JWT owner or ADMIN |
| GET | `/orders/user/{username}` | A user's orders — self or ADMIN |

**Admin only (JWT + ADMIN role)**

| Method | Path | Description |
|---|---|---|
| GET | `/orders` · `/orders?status=Pending` | All orders, optional status filter |
| GET | `/orders/role/{role_name}` | Orders filtered by customer role |
| POST | `/orders/{id}` | Kitchen status update (`Pending`, `Accepted`, `Ready`, `Completed`, `Cancelled`) |
| DELETE | `/orders/{id}` | Delete an order |
| GET | `/qr/ordering` | SVG QR code (image/svg+xml) encoding `{API_BASE_URL}/api/v1/qr/visit` |
| POST | `/users/create` · POST `/users/{id}` · DELETE `/users/{id}` | User management |
| GET/POST/PATCH/DELETE | `/roles...` | Role & permission management |
| POST | `/products` · PUT/DELETE `/products/{id}` · POST/DELETE `/products/{id}/image` | Product & product-image management |
| POST | `/categories` · PUT/DELETE `/categories/{id}` · POST `/categories/product[/remove]` | Category management |

## How the QR Ordering Flow Works

1. Admin calls `GET /api/v1/qr/ordering` with a JWT → receives an **SVG QR image** encoding `{API_BASE_URL}/api/v1/qr/visit`.
2. The QR is printed on a table card. A guest scans it → `GET /api/v1/qr/visit` responds **302 Found** with `Location: ORDERING_BASE_URL` (the ordering frontend — default: `{API_BASE_URL}/api/v1/products`).
3. The guest browses products and calls `POST /api/v1/orders` **without a JWT** → a guest order is created (`user_id: null`) and the response contains the signed `order_url`.

## Signed Receipt Links (`order_url`)

Every order creation returns:

```json
{
  "order": { "order_id": 1, "user_id": null, "products": [ ... ], "total_amount": "13.49",
             "status": "Pending", "payment_status": "unpaid", "created_at": "...", "updated_at": "..." },
  "order_url": "http://localhost:3000/api/v1/orders/1?exp=1770000000&sig=3f2a9c..."
}
```

- Format: `{API_BASE_URL}/api/v1/orders/{id}?exp={unix}&sig={hex}`.
- `sig` is the **HMAC-SHA256** hex digest of `order_id={id}&exp={exp}`, keyed with `QR_SIGNING_SECRET`.
- TTL is `ORDER_LINK_EXPIRATION_MINUTES` (default 1440 min / 24 h).
- Holding a valid `order_url` grants **viewing** (`GET /orders/{id}`) and **paying** (`POST /orders/{id}/pay`) without any account.
- Tampered signature → **400 Bad Request**; expired link → **410 Gone**; no/partial query params → **403 Forbidden** (or 401 when an invalid JWT is supplied).

## Mock Payment Rule

`POST /api/v1/orders/{id}/pay` (ADMIN or valid `order_url`) is a deterministic mock:

- `total_amount ≤ MAX_PAYMENT_AMOUNT` (default `1000.00`) → `payment_status: "paid"`, message `"Payment successful"`.
- `total_amount > MAX_PAYMENT_AMOUNT` → `payment_status: "failed"`, message `"Payment failed: amount exceeds the maximum allowed"` (HTTP 200 either way; the status is in the body).
- Already paid (or any status other than `unpaid`/`failed`) → **409 Conflict**.
- Unknown order → 404.

Response body: `{ "order_id": 1, "payment_status": "paid", "message": "Payment successful" }`.

## Testing

Integration tests require a running MySQL and the `.env` file (tests read `DATABASE_URL` via dotenv):

```bash
cargo test
```

Test modules live in `tests/` and cover controllers, repos and services (auth, orders incl. payment, QR, roles, products, categories). Bruno collections under `bruno/` provide ready-made HTTP requests for manual end-to-end verification.

## Why Rust Instead of the Recommended Laravel / NodeJS Stack?

The brief recommended a Laravel (PHP) or Node.js stack, and Rust is a deliberate deviation worth being able to defend in an interview:

- **Compile-time guarantees** — the type system catches null-deref, mismatched types and concurrency bugs at build time rather than at runtime; the whole HTTP layer is statically typed end to end (request DTOs → services → response mappers).
- **Performance** — Axum on Tokio delivers very high throughput with low, predictable latency and near-zero memory footprint per connection, which matters for a point-of-sale-adjacent workload on cheap hardware.
- **Correctness-first data layer** — `diesel-async` compiles SQL against the schema at compile time, so a renamed column is a compile error, not a 500 at 2 a.m.; `BigDecimal` avoids floating-point money bugs that PHP/JS are prone to.
- **Single static binary** — `cargo build --release` produces one binary with no runtime dependencies: trivial to containerize (see `Dockerfile`) and deploy.
- **Cost** — no PHP/Node runtime on servers; the trade-off is a slower initial development cadence (borrow checker), which the repository-pattern/GAT structure and a small route surface keep manageable.

## Project Structure

```text
arrow_server/
├── bruno/                # API collection for manual testing (Bruno format)
├── src/
│   ├── api/
│   │   ├── controllers/  # Request handlers
│   │   ├── routes/       # Endpoint definitions
│   │   ├── extractors.rs # JWT extractors (AccessClaims / OptionalAccessClaims)
│   │   ├── config.rs     # Environment configuration
│   │   └── server.rs     # Router assembly and startup
│   ├── data/
│   │   ├── migrations/   # Diesel SQL migrations
│   │   ├── models/       # Diesel structs (schema.rs: table definitions)
│   │   ├── repos/        # Repository implementations (generic trait with GATs)
│   │   └── database.rs   # Async connection pool
│   ├── security/         # JWT and password hashing
│   ├── services/         # Business logic layer
│   └── utils/            # Mappers and order_url signing
├── tests/                # Integration tests (controllers, repos, services)
├── API.md                # Human-readable API reference
├── openapi.yaml          # OpenAPI 3.0 specification
├── schema.sql            # Full schema snapshot (concatenated migrations)
└── seed.sql              # Optional roles + starter menu
```

**Interesting techniques:** the data layer uses a `Repository` trait with **Generic Associated Types** (`type NewItem<'a>`), auth is enforced declaratively via **custom Axum extractors** (`AccessClaims` implements `FromRequestParts`), the DB pool is a **lazy global `once_cell::sync::Lazy`** deadpool instance, and all SQL goes through **`diesel-async`**.

## Known Limitations

- Product images are uploaded to a **private Azure Blob Storage container** through `POST /products/{id}/image`; the read endpoints return short-lived read-only **SAS URLs** minted at request time (TTL `IMAGE_SAS_TTL_MINUTES`, default 15 min) instead of the stored blob path — SAS URLs are never persisted. Uploads require `AZURE_STORAGE_ACCOUNT`/`AZURE_STORAGE_CONTAINER` (and `AZURE_STORAGE_ACCOUNT_KEY` for SAS signing; without it uploads/deletes fall back to managed identity but read SAS URLs cannot be minted). When storage is not configured the image endpoints return 503 and legacy external `product_image_uri` values keep working unchanged.
- Mock payments are deterministic and offline by design; no payment provider is integrated.
- CORS currently allows any origin (`CorsLayer::allow_origin(Any)`) — tighten before production.
