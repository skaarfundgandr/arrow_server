#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]
use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::order_controller::{
    cancel_order, create_order, delete_order, get_all_orders, get_order_by_id, get_orders_by_role,
    get_user_orders_by_name, update_order_status,
};
use arrow_server_lib::api::response::{CreateOrderResponse, OrderResponse};
use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions};
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::security::jwt::JwtService;
use arrow_server_lib::utils::order_url::sign_order_url;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use bigdecimal::BigDecimal;
use diesel::result;
use diesel_async::RunQueryDsl;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
    use arrow_server_lib::data::models::schema::orders::dsl::orders;
    use arrow_server_lib::data::models::schema::products::dsl::products;
    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
    use arrow_server_lib::data::models::schema::roles::dsl::roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_test_user(username: &str, password: &str) -> i32 {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = auth.hash_password(password).await.expect("Hashing failed");

    let test_user = NewUser {
        username,
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id
}

async fn create_user_with_role(
    username: &str,
    password: &str,
    role_name: &str,
    permission: RolePermissions,
) -> (i32, String) {
    let user_id = create_test_user(username, password).await;

    let role_repo = RoleRepo::new();
    let user_role_repo = UserRoleRepo::new();
    let jwt_service = JwtService::new();

    let new_role = NewRole {
        name: role_name,
        description: Some("Test Role"),
    };
    role_repo
        .add(new_role)
        .await
        .expect("Failed to create role");

    let role = role_repo
        .get_by_name(role_name)
        .await
        .expect("Query failed")
        .expect("Role not found");
    
    user_role_repo.add_user_role(user_id, role.role_id).await.expect("Failed to assign role");

    role_repo
        .set_permissions(role.role_id, permission)
        .await
        .expect("Failed to set permission");

    let user_dto = UserDTO {
        user_id: Some(user_id),
        username: username.to_string(),
        role: None,
        created_at: None,
        updated_at: None,
    };
    let token = jwt_service
        .generate_token(user_dto)
        .await
        .expect("Failed to generate token");

    (user_id, token)
}

async fn create_test_product(name: &str, price: BigDecimal) -> i32 {
    let repo = ProductRepo::new();
    let product = NewProduct {
        name,
        product_image_uri: None,
        description: Some("Test Description"),
        price,
    };
    repo.add(product).await.expect("Failed to add product");
    repo.get_by_name(name)
        .await
        .expect("Failed to get product")
        .expect("Product not found")
        .product_id
}

fn app() -> Router {
    Router::new()
        .route("/orders", get(get_all_orders))
        .route("/orders", post(create_order))
        .route("/orders/{id}", get(get_order_by_id))
        .route("/orders/{id}", post(update_order_status))
        .route("/orders/{id}", axum::routing::delete(delete_order))
        .route("/orders/{id}/cancel", post(cancel_order))
        .route("/orders/user/{username}", get(get_user_orders_by_name))
        .route("/orders/role/{role_name}", get(get_orders_by_role))
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_success() {
    setup().await.expect("Setup failed");
    let (user_id, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 2
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    assert!(response.order_url.contains("/api/v1/orders/"));
    // Authenticated order is attributed to the JWT subject
    assert_eq!(response.order.user_id, Some(user_id));
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_public_guest() {
    setup().await.expect("Setup failed");
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // No Authorization header -> guest order
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 2
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    assert!(response.order.user_id.is_none());
    assert!(response.order_url.contains("/api/v1/orders/"));
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_invalid_token_unauthorized() {
    setup().await.expect("Setup failed");
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", "Bearer invalid.token.here")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_orders_success() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order first
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 2
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Now get orders with an admin
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(orders.len(), 1);
    
    // Check order contents
    assert_eq!(orders[0].products.len(), 1);
    assert_eq!(orders[0].products[0].quantity, 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_response_per_item_quantities() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid1 = create_test_product("Product 1", BigDecimal::from(10)).await;
    let pid2 = create_test_product("Product 2", BigDecimal::from(25)).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid1,
                                "quantity": 2
                            },
                            {
                                "product_id": pid2,
                                "quantity": 3
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order = response.order;

    assert_eq!(order.products.len(), 2);
    assert_eq!(order.products[0].product.product_id, pid1);
    assert_eq!(order.products[0].quantity, 2);
    assert_eq!(order.products[0].unit_price, BigDecimal::from(10));
    assert_eq!(order.products[0].line_total, BigDecimal::from(20));
    assert_eq!(order.products[1].product.product_id, pid2);
    assert_eq!(order.products[1].quantity, 3);
    assert_eq!(order.products[1].unit_price, BigDecimal::from(25));
    assert_eq!(order.products[1].line_total, BigDecimal::from(75));
    assert_eq!(order.total_amount, BigDecimal::from(95));

    // No flat top-level quantity field anymore
    let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(raw["order"].get("quantity").is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_order_owner_success() {
    setup().await.expect("Setup failed");
    let (owner_id, token) =
        create_user_with_role("owner", "pass", "OWNER", RolePermissions::Write).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(created.order.user_id, Some(owner_id));
    let order_id = created.order.order_id;

    // Owner cancels own pending order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/cancel", order_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify status changed to Cancelled (owner can still read own order)
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let order: OrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(order.status, Some("Cancelled".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_order_non_owner_forbidden() {
    setup().await.expect("Setup failed");
    let (_, owner_token) =
        create_user_with_role("owner", "pass", "OWNER", RolePermissions::Write).await;
    let (_, other_token) =
        create_user_with_role("other", "pass", "OTHER", RolePermissions::Write).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", owner_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Non-owner non-admin tries to cancel
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/cancel", order_id))
                .header("Authorization", format!("Bearer {}", other_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_order_admin_success() {
    setup().await.expect("Setup failed");
    let (_, owner_token) =
        create_user_with_role("owner", "pass", "OWNER", RolePermissions::Write).await;
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", owner_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Admin cancels anyone's order
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/cancel", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_order_guest_forbidden_for_non_admin() {
    setup().await.expect("Setup failed");
    let (_, reader_token) =
        create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Guest creates an order (null user_id)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Non-admin cannot cancel a guest order via JWT
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/cancel", order_id))
                .header("Authorization", format!("Bearer {}", reader_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_order_not_found() {
    setup().await.expect("Setup failed");
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders/99999/cancel")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_order_admin_success() {
    setup().await.expect("Setup failed");
    let (_, owner_token) =
        create_user_with_role("owner", "pass", "OWNER", RolePermissions::Write).await;
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", owner_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Admin deletes the order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Order is gone
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_order_non_admin_forbidden() {
    setup().await.expect("Setup failed");
    let (_, owner_token) =
        create_user_with_role("owner", "pass", "OWNER", RolePermissions::Write).await;
    let (_, writer_token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order as owner
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", owner_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Non-admin cannot delete
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", writer_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_order_not_found() {
    setup().await.expect("Setup failed");
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/orders/99999")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_status_query() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create two orders
    for _ in 0..2 {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orders")
                    .header("Authorization", format!("Bearer {}", token))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "products": [
                                {
                                    "product_id": pid,
                                    "quantity": 1
                                }
                            ]
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Both orders are Pending
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders?status=Pending")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(orders.len(), 2);
    assert!(orders.iter().all(|o| o.status == Some("Pending".to_string())));

    // Complete one order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders?status=Pending")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    let order_id = orders[0].order_id;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({ "status": "Completed" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // One Pending, one Completed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders?status=Pending")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(orders.len(), 1);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders?status=Completed")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(orders.len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_invalid_status_empty() {
    setup().await.expect("Setup failed");
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    // Unknown status matches no orders -> empty list
    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders?status=BogusStatus")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert!(orders.is_empty());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_orders_non_admin_forbidden() {
    setup().await.expect("Setup failed");
    let (_, reader_token) =
        create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", reader_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_orders_by_name() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Create order for "writer"
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 2
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get orders for "writer"
    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders/user/writer")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].products.len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order_status_success() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // 1. Create Order
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Get the created order (admin only)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    let order_id = orders[0].order_id;

    // 2. Update Status (admin only)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "status": "Accepted"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // 3. Verify Update as the owner
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let order: OrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(order.status, Some("Accepted".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order_status_not_found() {
    setup().await.expect("Setup failed");
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders/99999")
                .header("Authorization", format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "status": "Accepted"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order_status_invalid_status() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // 1. Create Order
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Fetch ID (admin only)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    let order_id = orders[0].order_id;

    // 2. Try Update with invalid status
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "status": "InvalidStatus"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order_status_forbidden() {
    setup().await.expect("Setup failed");
    // Non-admin cannot update status
    let (_, token) = create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    // Need a writer to create the order first
    let (_, writer_token) =
        create_user_with_role("writer", "pass2", "WRITER", RolePermissions::Write).await;
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    // 1. Create Order
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", writer_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Fetch ID (admin only)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    let order_id = orders[0].order_id;

    // 2. Reader tries to update status
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", order_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "status": "Accepted"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_via_order_url() {
    setup().await.expect("Setup failed");
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Guest creates an order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Fetch via signed order_url without any auth
    // (strip the API base so it matches the test router)
    let order_path = created.order_url.split("/api/v1").last().unwrap().to_string();
    let response = app
        .oneshot(
            Request::builder()
                .uri(order_path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let order: OrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(order.order_id, order_id);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_tampered_order_url() {
    setup().await.expect("Setup failed");
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Guest creates an order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Tamper with the signature
    let now = chrono::Utc::now().timestamp() as u64;
    let url = format!(
        "/orders/{}?exp={}&sig=deadbeef",
        order_id, now + 3600
    );

    let response = app
        .oneshot(
            Request::builder().uri(url).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_expired_order_url() {
    setup().await.expect("Setup failed");
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Guest creates an order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // Valid signature over an already-expired timestamp
    let past_exp = chrono::Utc::now().timestamp() as u64 - 60;
    let sig = sign_order_url(order_id, past_exp).unwrap();
    let url = format!(
        "/orders/{}?exp={}&sig={}",
        order_id, past_exp, sig
    );

    let response = app
        .oneshot(
            Request::builder().uri(url).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_by_id_unauthorized() {
    setup().await.expect("Setup failed");
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    // Guest creates an order
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": pid,
                                "quantity": 1
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    // No auth, no order_url
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{}", order_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_role_admin_only() {
    setup().await.expect("Setup failed");
    let (_, admin_token) =
        create_user_with_role("adminuser", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/orders/role/ADMIN")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Non-admin is denied
    let (_, reader_token) =
        create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders/role/ADMIN")
                .header("Authorization", format!("Bearer {}", reader_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_orders_other_user_forbidden() {
    setup().await.expect("Setup failed");
    let (_, _token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let (_, other_token) =
        create_user_with_role("other", "pass", "WRITER2", RolePermissions::Write).await;

    let app = app();

    // Non-admin user tries to view another user's orders
    let response = app
        .oneshot(
            Request::builder()
                .uri("/orders/user/writer")
                .header("Authorization", format!("Bearer {}", other_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}