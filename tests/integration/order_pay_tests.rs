use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::order_controller::{
    cancel_order, create_order, get_user_orders_by_name, pay_order,
};
use arrow_server_lib::api::response::{CreateOrderResponse, PayOrderResponse};
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions};
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::security::jwt::{AccessClaims, JwtService};
use arrow_server_lib::utils::order_url::sign_order_url;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use crate::common::{create_product_with_price, uniq};

async fn create_user_with_role(
    username: &str,
    password: &str,
    role_name: &str,
    permission: RolePermissions,
) -> (i32, String) {
    let auth = AuthService::new();
    let user_repo = UserRepo::new();
    let hashed = auth.hash_password(password).await.expect("Hashing failed");
    let new_user = NewUser {
        username,
        password_hash: &hashed,
    };
    user_repo.add(new_user).await.expect("Failed to add user");
    let user_id = user_repo
        .get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id;

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

    user_role_repo
        .add_user_role(user_id, role.role_id)
        .await
        .expect("Failed to assign role");

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

async fn create_guest_order(app: &Router, pid: i32, quantity: i32) -> i32 {
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
                                "quantity": quantity
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
    created.order.order_id
}

async fn create_order_with_quantity(pid: i32, quantity: i32) -> axum::response::Response {
    app()
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
                                "quantity": quantity
                            }
                        ]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn app() -> Router {
    Router::new()
        .route("/orders", post(create_order))
        .route("/orders/{id}/pay", post(pay_order))
        .route("/orders/{id}/cancel", post(cancel_order))
        .route("/orders/user/{username}", get(get_user_orders_by_name))
}

#[tokio::test]
async fn test_pay_order_success_admin() {
    let (_, admin_token) = create_user_with_role(
        &uniq("adminuser"),
        "pass",
        &uniq("ADMIN"),
        RolePermissions::Admin,
    )
    .await;
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 2).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/pay", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let pay: PayOrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pay.order_id, order_id);
    assert_eq!(pay.payment_status, "paid");
    assert_eq!(pay.message, "Payment successful");
}

#[tokio::test]
async fn test_pay_order_fails_over_max_amount() {
    let (_, admin_token) = create_user_with_role(
        &uniq("adminuser"),
        "pass",
        &uniq("ADMIN"),
        RolePermissions::Admin,
    )
    .await;
    let pid = create_product_with_price(&uniq("pay_product"), "1500")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/pay", order_id))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let pay: PayOrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pay.payment_status, "failed");
    assert_eq!(
        pay.message,
        "Payment failed: amount exceeds the maximum allowed"
    );
}

#[tokio::test]
async fn test_pay_order_not_found() {
    let (_, admin_token) = create_user_with_role(
        &uniq("adminuser"),
        "pass",
        &uniq("ADMIN"),
        RolePermissions::Admin,
    )
    .await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/pay", i32::MAX - 80))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_pay_order_via_valid_order_url() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let exp = chrono::Utc::now().timestamp() as u64 + 3600;
    let sig = sign_order_url(order_id, exp).unwrap();
    let url = format!("/orders/{}/pay?exp={}&sig={}", order_id, exp, sig);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let pay: PayOrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pay.payment_status, "paid");
}

#[tokio::test]
async fn test_pay_order_forbidden_without_link() {
    let (_, reader_token) = create_user_with_role(
        &uniq("reader"),
        "pass",
        &uniq("READER"),
        RolePermissions::Read,
    )
    .await;
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/pay", order_id))
                .header("Authorization", format!("Bearer {}", reader_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_pay_order_already_paid_conflict() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let exp = chrono::Utc::now().timestamp() as u64 + 3600;
    let sig = sign_order_url(order_id, exp).unwrap();
    let url = format!("/orders/{}/pay?exp={}&sig={}", order_id, exp, sig);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_create_order_zero_quantity_bad_request() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let response = create_order_with_quantity(pid, 0).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_order_negative_quantity_bad_request() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let response = create_order_with_quantity(pid, -1).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_pay_order_exact_max_amount_paid() {
    let pid = create_product_with_price(&uniq("pay_product"), "1000.00")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let exp = chrono::Utc::now().timestamp() as u64 + 3600;
    let sig = sign_order_url(order_id, exp).unwrap();
    let url = format!("/orders/{}/pay?exp={}&sig={}", order_id, exp, sig);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let pay: PayOrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(pay.payment_status, "paid");
}

#[tokio::test]
async fn test_pay_order_tampered_signature_bad_request() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let exp = chrono::Utc::now().timestamp() as u64 + 3600;
    let url = format!("/orders/{}/pay?exp={}&sig=deadbeef", order_id, exp);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_pay_order_expired_url_gone() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

    let past_exp = chrono::Utc::now().timestamp() as u64 - 60;
    let sig = sign_order_url(order_id, past_exp).unwrap();
    let url = format!("/orders/{}/pay?exp={}&sig={}", order_id, past_exp, sig);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn test_cancel_guest_order_by_admin() {
    let (_, admin_token) = create_user_with_role(
        &uniq("adminuser"),
        "pass",
        &uniq("ADMIN"),
        RolePermissions::Admin,
    )
    .await;
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();
    let order_id = create_guest_order(&app, pid, 1).await;

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
async fn test_cancel_own_order_read_only_owner_success() {
    let (_, owner_token) = create_user_with_role(
        &uniq("readowner"),
        "pass",
        &uniq("READOWNER"),
        RolePermissions::Read,
    )
    .await;
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();

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
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/cancel", order_id))
                .header("Authorization", format!("Bearer {}", owner_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_own_orders_read_only_success() {
    let username = uniq("readviewer");
    let (_, owner_token) = create_user_with_role(
        &username,
        "pass",
        &uniq("READVIEWER"),
        RolePermissions::Read,
    )
    .await;
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let app = app();

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
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let created: CreateOrderResponse = serde_json::from_slice(&body).unwrap();
    let order_id = created.order.order_id;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/orders/user/{}", username))
                .header("Authorization", format!("Bearer {}", owner_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<arrow_server_lib::api::response::OrderResponse> =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].order_id, order_id);
}

#[tokio::test]
async fn test_create_order_token_of_deleted_user_unauthorized() {
    let pid = create_product_with_price(&uniq("pay_product"), "10")
        .await
        .product_id;

    let now = chrono::Utc::now().timestamp() as usize;
    let claims = AccessClaims {
        sub: i32::MAX as usize - 81,
        iat: now,
        exp: now + 3600,
        roles: None,
    };
    let token = JwtService::new()
        .encode_claims(&claims)
        .await
        .expect("Failed to craft token");

    let response = app()
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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
