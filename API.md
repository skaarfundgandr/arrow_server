# Arrow Server API Documentation

**Base URL:** `http://127.0.0.1:3000/api/v1`

Machine-readable specification: [openapi.yaml](openapi.yaml).

## Authentication Model

* Bearer JWT (`Authorization: Bearer <token>`) issued by `POST /auth/login` or `POST /auth/register`.
* `GET /auth/refresh` rotates an existing token.
* **Admin bootstrap:** on first server start the admin account is created from environment variables (`ADMIN_USERNAME` / `ADMIN_PASSWORD`, see README) and assigned a role with the `ADMIN` permission. This is idempotent and requires no manual SQL.
* **Registration** always assigns the `CUSTOMER` role; registering with a username equal to `ADMIN_USERNAME` returns **409 Conflict**.
* Endpoints are grouped below by who may call them. "JWT" means any valid token; "Admin" means a token whose role carries the `ADMIN` permission; "Public" means no token at all. A missing/invalid/expired token on a JWT-protected route returns **401 Unauthorized**.

### Authorization matrix

| Endpoint | Public | Any JWT | Self (JWT) | Admin |
|---|:---:|:---:|:---:|:---:|
| `GET /auth/refresh` | | ✔ | | |
| `GET /users`, `GET /users/{id}`, `GET /users/search` | | ✔ | | |
| `POST /users/create`, `POST /users/{id}`, `DELETE /users/{id}` | | | | ✔ |
| `GET/POST/PATCH/DELETE /roles...` (all) | | | | ✔ |
| `GET /products`, `GET /products/{id}` | ✔ | | | |
| `POST /products`, `PUT /products/{id}`, `DELETE /products/{id}` | | ✔ (WRITE/DELETE permission) | | |
| `GET /categories`, `GET /categories/{name}/products` | ✔ | | | |
| `POST /categories`, `PUT /categories/{id}`, `DELETE /categories/{id}`, `POST /categories/product[/remove]` | | ✔ (WRITE permission) | | |
| `POST /auth/register`, `POST /orders`, `GET /qr/visit` | ✔ | | | |
| `GET /orders` (+`?status=`), `GET /orders/role/{role_name}`, `POST /orders/{id}`, `DELETE /orders/{id}` | | | | ✔ |
| `GET /orders/{id}` | ✔* | ✔ (owner) | | ✔ |
| `POST /orders/{id}/pay` | ✔* | | | ✔ |
| `POST /orders/{id}/cancel` | | ✔ (owner) | | ✔ |
| `GET /orders/user/{username}` | | | ✔ | ✔ |
| `GET /qr/ordering` | | | | ✔ |

\* via a valid signed `order_url` query parameter (see [Signed order links](#signed-order-links-order_url)); without it the route falls through to the other columns.

---

## Auth

### Login
Authenticate a user and receive a JWT token.

* **URL:** `/auth/login`
* **Method:** `POST`
* **Auth Required:** No
* **Body:**
    ```json
    { "username": "admin", "password": "password123" }
    ```
* **Response 200** — `LoginResponse`
    ```json
    { "token": "eyJhbGciOiJIUzI1Ni...", "message": "Login successful" }
    ```
* **Errors:** 401 invalid credentials · 404 unknown user · 500

### Register
Register a new customer. The username is unique; **a username equal to `ADMIN_USERNAME` is reserved (409)**. The new user is automatically assigned the `CUSTOMER` role and receives a token immediately.

* **URL:** `/auth/register`
* **Method:** `POST`
* **Auth Required:** No
* **Body:**
    ```json
    { "username": "newcustomer", "password": "password123" }
    ```
* **Response 201** — `LoginResponse` (`"User created and logged in"`)
* **Errors:** 409 reserved username · 500

### Refresh Token
Rotate the current JWT.

* **URL:** `/auth/refresh`
* **Method:** `GET`
* **Auth Required:** Yes (Bearer Token)
* **Response 200** — `LoginResponse`
* **Errors:** 401 · 404 (account no longer exists)

---

## Users

### Get All Users
Returns all users. `user_id` is only included for admins.

* **URL:** `/users`
* **Method:** `GET`
* **Auth Required:** Yes (Bearer Token)
* **Response 200** — `Vec<UserDTO>`
    ```json
    [
      {
        "user_id": 1,
        "username": "admin",
        "role": { "role_id": 1, "name": "ADMIN", "permissions": ["READ","WRITE","DELETE","ADMIN"], "description": null },
        "created_at": "20/12/2025",
        "updated_at": "20/12/2025"
      }
    ]
    ```

### Create User (Admin)
* **URL:** `/users/create`
* **Method:** `POST`
* **Auth Required:** Yes (Admin)
* **Body:** `NewUserDTO` `{ "username": "...", "password": "..." }`
* **Response 201** `"User created"` · **Errors:** 401, 403, 500

### Get User by ID
* **URL:** `/users/{id}`
* **Method:** `GET`
* **Auth Required:** Yes (Bearer Token)
* **Response 200** — `UserDTO` · **Errors:** 401, 404

### Search User by Name
* **URL:** `/users/search?username=...`
* **Method:** `GET`
* **Auth Required:** Yes (Bearer Token)
* **Query Params:** `username` (required)
* **Response 200** — `UserDTO` · **Errors:** 400 (missing param), 401, 404

### Edit User (Admin)
* **URL:** `/users/{id}`
* **Method:** `POST`
* **Auth Required:** Yes (Admin)
* **Body:** `UpdateUserDTO` (all optional)
    ```json
    { "username": "updated_name", "password": "new_password" }
    ```
* **Response 200** `"User updated"` · **Errors:** 401, 403, 404

### Delete User (Admin)
* **URL:** `/users/{id}`
* **Method:** `DELETE`
* **Auth Required:** Yes (Admin)
* **Response 200** `"User deleted"` · **Errors:** 401, 403, 404

---

## Roles

All role endpoints are **Admin only** (401 without a token, 403 without the ADMIN permission). Roles are global definitions; permissions live in a MySQL `SET` column on `roles` (values: `READ`, `WRITE`, `DELETE`, `ADMIN`). Each user has exactly one role.

### Get All Roles
* **URL:** `/roles`
* **Method:** `GET`
* **Response 200** — `Vec<RoleDTO>` (each with `permissions: [READ, WRITE, ...]`)

### Create Role
* **URL:** `/roles/create`
* **Method:** `POST`
* **Body:** `NewRoleDTO`
    ```json
    { "name": "Manager", "description": "Store manager" }
    ```
* **Response 201** `"Role created"` — the new role has no permissions until set.

### Update Role
* **URL:** `/roles/update/{id}`
* **Method:** `POST`
* **Body:** `UpdateRoleDTO` `{ "name": "...", "description": "..." }` (optional)
* **Response 200** `"Role updated"` · 404 unknown role

### Delete Role
* **URL:** `/roles/{id}`
* **Method:** `DELETE`
* **Response 200** `"Role deleted"` · 404 unknown role

### Assign Role to User
* **URL:** `/roles/assign`
* **Method:** `POST`
* **Body:**
    ```json
    { "username": "target_user", "role_name": "Manager" }
    ```
* **Response 201** `"Role assigned to user"` · 404 unknown user/role

### Add Permission to Role
* **URL:** `/roles/add_permission`
* **Method:** `POST`
* **Body:**
    ```json
    { "role_name": "Manager", "permission": "WRITE" }
    ```
    (`permission` ∈ `READ, WRITE, DELETE, ADMIN`)
* **Response 200** `"Permission added"` · 400 invalid permission

### Set Permission (Overwrite)
* **URL:** `/roles/{id}/set_permission`
* **Method:** `POST`
* **Body:** `SetPermissionDTO` `{ "permission": "READ" }`
* **Response 200** `"Permission set"` · 400 invalid permission · 404 unknown role

### Set Permission by Role Name (Overwrite)
* **URL:** `/roles/set_permission/{role_name}`
* **Method:** `POST`
* **Body:** `SetPermissionDTO` `{ "permission": "READ" }`
* **Response 200** `"Permission set"` · 400 invalid permission · 404 unknown role

### Remove Permission (Reset to Read)
* **URL:** `/roles/{id}/delete_permission`
* **Method:** `PATCH`
* **Response 200** `"Permissions reset to READ (Default)"` · 404 unknown role

---

## Products

### Get All Products (public)
* **URL:** `/products`
* **Method:** `GET`
* **Auth Required:** No
* **Response 200** — `Vec<ProductResponse>`
    ```json
    [
      {
        "product_id": 1,
        "name": "Classic Burger",
        "description": "Beef patty, lettuce, tomato, house sauce",
        "price": "9.99",
        "product_image_uri": "/img/burgers/classic.png",
        "categories": null
      }
    ]
    ```

### Get Product by ID (public)
* **URL:** `/products/{id}`
* **Method:** `GET`
* **Auth Required:** No
* **Response 200** — `ProductResponse` · **Errors:** 404

### Create Product
* **URL:** `/products`
* **Method:** `POST`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Body:** `CreateProductRequest`
    ```json
    {
      "name": "Classic Burger",
      "description": "Beef burger",
      "price": "9.99",
      "product_image_uri": "/img/burger.png",
      "categories": ["Burgers"]
    }
    ```
* **Response 201** `"Product created"` · **Errors:** 401, 403, 409 (name already exists)

### Update Product
* **URL:** `/products/{id}`
* **Method:** `PUT`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Body:** `UpdateProductRequest` (all optional, incl. `categories`)
* **Response 200** `"Product updated"` · **Errors:** 401, 403, 404

### Delete Product
* **URL:** `/products/{id}`
* **Method:** `DELETE`
* **Auth Required:** Yes (DELETE permission or Admin)
* **Response 200** `"Product deleted"` · **Errors:** 401, 403, 404

---

## Categories

### Get All Categories (public)
* **URL:** `/categories`
* **Method:** `GET`
* **Auth Required:** No
* **Response 200** — `Vec<CategoryResponse>`. Public responses omit `category_id` and timestamps (keys absent from the JSON, not `null`):
    ```json
    [
      { "name": "Burgers", "description": "Hand-made burgers" }
    ]
    ```

### Get Products by Category (public)
* **URL:** `/categories/{category_name}/products`
* **Method:** `GET`
* **Auth Required:** No
* **Response 200** — `Vec<ProductResponse>` · **Errors:** 404 (unknown category)

### Create Category
* **URL:** `/categories`
* **Method:** `POST`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Body:** `CreateCategoryRequest` `{ "name": "Food", "description": "Edible items" }`
* **Response 201** `"Category added successfully"` · **Errors:** 401, 403

### Edit Category
* **URL:** `/categories/{id}`
* **Method:** `PUT`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Body:** `UpdateCategoryRequest` (optional)
* **Response 201** `"Category edited successfully"` · **Errors:** 401, 403

### Delete Category
* **URL:** `/categories/{id}`
* **Method:** `DELETE`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Response 200** `"Category deleted successfully"` · **Errors:** 401, 403

### Add Product to Category
* **URL:** `/categories/product`
* **Method:** `POST`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Body:** `AssignCategoryRequest`
    ```json
    { "category": "Burgers", "product": "Classic Burger" }
    ```
* **Response 201** `"Product assigned to category successfully"` · **Errors:** 401, 403, 404, 500

### Remove Product from Category
* **URL:** `/categories/product/remove`
* **Method:** `POST`
* **Auth Required:** Yes (WRITE permission or Admin)
* **Body:** `AssignCategoryRequest` (as above)
* **Response 200** `"Product removed from category successfully"` · **Errors:** 401, 403, 404, 500

---

## Orders

Order statuses (capitalized): `Pending`, `Accepted`, `Ready`, `Completed`, `Cancelled`. `payment_status` ∈ `unpaid`, `paid`, `failed`.

### Get All Orders (Admin)
* **URL:** `/orders`
* **Method:** `GET`
* **Auth Required:** Yes (Admin)
* **Query Params:** `status` (optional) — one of `Pending, Accepted, Ready, Completed, Cancelled`; unknown/invalid values match nothing and return an empty list.
* **Response 200** — `Vec<OrderResponse>`
    ```json
    [
      {
        "order_id": 1,
        "user_id": null,
        "products": [
          {
            "product": { "product_id": 1, "name": "Classic Burger", "description": "...", "price": "9.99", "product_image_uri": null, "categories": null },
            "quantity": 2,
            "unit_price": "9.99",
            "line_total": "19.98"
          }
        ],
        "total_amount": "19.98",
        "status": "Pending",
        "payment_status": "unpaid",
        "created_at": "2026-08-07 12:00:00",
        "updated_at": "2026-08-07 12:00:00"
      }
    ]
    ```
* **Errors:** 401, 403

### Create Order (public)
Creates an order. **No JWT → guest order with `user_id: null`; valid JWT → order attributed to that user; invalid/expired JWT → 401.** Prices and line totals are read from the database, never from the client.

* **URL:** `/orders`
* **Method:** `POST`
* **Auth Required:** No (optional Bearer Token)
* **Body:** `CreateOrderRequest`
    ```json
    { "products": [ { "product_id": 1, "quantity": 2 }, { "product_id": 2, "quantity": 1 } ] }
    ```
* **Response 201** — `CreateOrderResponse`
    ```json
    {
      "order": {
        "order_id": 1,
        "user_id": null,
        "products": [ { "product": { "product_id": 1, "name": "Classic Burger", "description": "...", "price": "9.99", "product_image_uri": null, "categories": null }, "quantity": 2, "unit_price": "9.99", "line_total": "19.98" } ],
        "total_amount": "19.98",
        "status": "Pending",
        "payment_status": "unpaid",
        "created_at": "2026-08-07 12:00:00",
        "updated_at": "2026-08-07 12:00:00"
      },
      "order_url": "http://localhost:3000/api/v1/orders/1?exp=1770000000&sig=3f2a9c..."
    }
    ```
* **Errors:** 400 (unknown product / empty payload) · 401 (invalid token) · 500

### Get Order by ID
Access is granted to: **Admin**, the **JWT owner** of the order, or anyone holding a valid **signed `order_url`** (no JWT required).

* **URL:** `/orders/{id}?exp={unix}&sig={hex}`
* **Method:** `GET`
* **Auth Required:** No (optional Bearer Token, see access rules)
* **Response 200** — `OrderResponse` · **Errors:** 400 (tampered `sig`), 401 (invalid token), 403 (not authorized, missing/invalid `exp`+`sig`), 404, 410 (expired link)

### Update Order Status (Admin / kitchen)
* **URL:** `/orders/{id}`
* **Method:** `POST`
* **Auth Required:** Yes (Admin)
* **Body:** `UpdateOrderStatusRequest`
    ```json
    { "status": "Ready" }
    ```
    Case-insensitive; valid values: `Pending`, `Accepted`, `Ready`, `Completed`, `Cancelled`.
* **Response 200** `"Order status updated"` · **Errors:** 400 (missing/invalid status), 401, 403, 404

### Cancel Order
Access: **JWT owner** or **Admin**. Guest orders (`user_id: null`) can only be cancelled by an Admin.

* **URL:** `/orders/{id}/cancel`
* **Method:** `POST`
* **Auth Required:** Yes (owner or Admin)
* **Response 200** `"Order cancelled"` · **Errors:** 401, 403 (not owner/admin), 404

### Pay Order (mock)
Access: **Admin** or anyone holding a valid signed `order_url` (the JWT owner's token alone does NOT grant payment).

* **URL:** `/orders/{id}/pay?exp={unix}&sig={hex}`
* **Method:** `POST`
* **Auth Required:** No (optional Bearer Token, see access rules)
* **Response 200** — `PayOrderResponse`
    ```json
    { "order_id": 1, "payment_status": "paid", "message": "Payment successful" }
    ```
    Payment succeeds unless `total_amount > MAX_PAYMENT_AMOUNT` (default `1000.00`), in which case the body reports `payment_status: "failed"` with message `"Payment failed: amount exceeds the maximum allowed"` (still HTTP 200).
* **Errors:** 400 (tampered `sig`), 401, 403 (no valid link/token), 404, 409 (`"Order already paid"` — `payment_status` is not `unpaid`/`failed`), 410 (expired link)

### Get User Orders
Access: **self** (JWT owner of the username) or **Admin**.

* **URL:** `/orders/user/{username}`
* **Method:** `GET`
* **Auth Required:** Yes (self or Admin)
* **Response 200** — `Vec<OrderResponse>` · **Errors:** 401, 403, 404 (unknown user)

### Get Orders by Role (Admin)
* **URL:** `/orders/role/{role_name}`
* **Method:** `GET`
* **Auth Required:** Yes (Admin)
* **Response 200** — `Vec<OrderResponse>` · **Errors:** 401, 403

### Delete Order (Admin)
* **URL:** `/orders/{id}`
* **Method:** `DELETE`
* **Auth Required:** Yes (Admin)
* **Response 200** `"Order deleted"` · **Errors:** 401, 403, 404

---

## QR

### Get Ordering QR (Admin)
* **URL:** `/qr/ordering`
* **Method:** `GET`
* **Auth Required:** Yes (Admin)
* **Response 200** — body is an **SVG QR code** (`Content-Type: image/svg+xml`) encoding `{API_BASE_URL}/api/v1/qr/visit`. **Errors:** 401, 403

### Visit Redirect (public)
* **URL:** `/qr/visit`
* **Method:** `GET`
* **Auth Required:** No
* **Response 302 Found** with `Location: ORDERING_BASE_URL` (default `{API_BASE_URL}/api/v1/products`).

---

## Signed Order Links (`order_url`)

Every `POST /orders` response includes `order_url`:

```
{API_BASE_URL}/api/v1/orders/{id}?exp={unix}&sig={hex}
```

* `sig` = lowercase hex of **HMAC-SHA256** over the string `order_id={id}&exp={exp}`, keyed with `QR_SIGNING_SECRET` (required env var).
* `exp` = Unix timestamp, `now + ORDER_LINK_EXPIRATION_MINUTES × 60` (default 1440 min / 24 h).
* The link is the guest's receipt: it grants `GET /orders/{id}` and `POST /orders/{id}/pay` without an account.
* Failure modes: missing/partial params → 403 · wrong/tampered `sig` → **400** · `exp` in the past → **410 Gone**.

## Health Check

`GET /api` (outside the `/api/v1` prefix) returns `Arrow Server API is running!` — used to confirm the process is up.

## Common Error Responses

All errors are plain-text bodies with the appropriate status code: 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 410 Gone, 500 Internal Server Error.
