use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::order_controller::{
    cancel_order, create_order, delete_order, get_all_orders, get_order_by_id, get_orders_by_role,
    get_user_orders_by_name, update_order_status,
};
use arrow_server_lib::api::response::{CreateOrderResponse, OrderResponse};
use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::security::jwt::JwtService;
use arrow_server_lib::utils::order_url::sign_order_url;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, post};
use bigdecimal::BigDecimal;
use http_body_util::BodyExt;
use serde_json::json;
use std::str::FromStr;
use tower::ServiceExt;

use crate::common::{
    create_order as make_order, create_product, create_product_with_price, create_user_with_role,
    uniq,
};

async fn create_token_user(
    username: &str,
    role_name: &str,
    permission: RolePermissions,
) -> (i32, String) {
    let (user, role) = create_user_with_role(username, role_name).await;
    RoleRepo::new()
        .set_permissions(role.role_id, permission)
        .await
        .expect("Failed to set permission");

    let user_dto = UserDTO {
        user_id: Some(user.user_id),
        username: user.username,
        role: None,
        created_at: None,
        updated_at: None,
    };
    let token = JwtService::new()
        .generate_token(user_dto)
        .await
        .expect("Failed to generate token");
    (user.user_id, token)
}

fn app() -> Router {
    Router::new()
        .route("/orders", get(get_all_orders))
        .route("/orders", post(create_order))
        .route("/orders/{id}", get(get_order_by_id))
        .route("/orders/{id}", post(update_order_status))
        .route("/orders/{id}", delete(delete_order))
        .route("/orders/{id}/cancel", post(cancel_order))
        .route("/orders/user/{username}", get(get_user_orders_by_name))
        .route("/orders/role/{role_name}", get(get_orders_by_role))
}

#[tokio::test]
async fn test_create_order_success() {
    let (user_id, token) = create_token_user(
        &uniq("order-writer"),
        &uniq("writer-role"),
        RolePermissions::Write,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;

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
                                "product_id": product.product_id,
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
    assert_eq!(response.order.user_id, Some(user_id));
}

#[tokio::test]
async fn test_create_order_public_guest() {
    let product = create_product(&uniq("ProductOne")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": product.product_id,
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
async fn test_create_order_invalid_token_unauthorized() {
    let product = create_product(&uniq("ProductOne")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orders")
                .header("Authorization", "Bearer not-a-valid-token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "products": [
                            {
                                "product_id": product.product_id,
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
async fn test_get_all_orders_success() {
    let (writer_id, _) = create_token_user(
        &uniq("order-writer"),
        &uniq("writer-role"),
        RolePermissions::Write,
    )
    .await;
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;
    let order = make_order(writer_id, product.product_id, "20.00", "Pending").await;

    let response = app()
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
    let found = orders
        .iter()
        .find(|o| o.order_id == order.order_id)
        .expect("Order not found in list");
    assert_eq!(found.products.len(), 1);
    assert_eq!(found.products[0].quantity, 1);
}

#[tokio::test]
async fn test_response_per_item_quantities() {
    let (_, token) = create_token_user(
        &uniq("order-writer"),
        &uniq("writer-role"),
        RolePermissions::Write,
    )
    .await;
    let pid1 = create_product_with_price(&uniq("ProductOne"), "10.00").await;
    let pid2 = create_product_with_price(&uniq("ProductTwo"), "25.00").await;

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
                                "product_id": pid1.product_id,
                                "quantity": 2
                            },
                            {
                                "product_id": pid2.product_id,
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
    assert_eq!(order.products[0].product.product_id, pid1.product_id);
    assert_eq!(order.products[0].quantity, 2);
    assert_eq!(
        order.products[0].unit_price,
        BigDecimal::from_str("10.00").unwrap()
    );
    assert_eq!(
        order.products[0].line_total,
        BigDecimal::from_str("20.00").unwrap()
    );
    assert_eq!(order.products[1].product.product_id, pid2.product_id);
    assert_eq!(order.products[1].quantity, 3);
    assert_eq!(
        order.products[1].unit_price,
        BigDecimal::from_str("25.00").unwrap()
    );
    assert_eq!(
        order.products[1].line_total,
        BigDecimal::from_str("75.00").unwrap()
    );
    assert_eq!(order.total_amount, BigDecimal::from_str("95.00").unwrap());

    let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(raw["order"].get("quantity").is_none());
}

#[tokio::test]
async fn test_cancel_order_owner_success() {
    let (owner_id, token) = create_token_user(
        &uniq("order-owner"),
        &uniq("owner-role"),
        RolePermissions::Write,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;

    let app = app();

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
                                "product_id": product.product_id,
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
async fn test_cancel_order_admin_success() {
    let (_, owner_token) = create_token_user(
        &uniq("order-owner"),
        &uniq("owner-role"),
        RolePermissions::Write,
    )
    .await;
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;

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
                                "product_id": product.product_id,
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
async fn test_cancel_order_not_found() {
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}/cancel", i32::MAX - 300))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_order_admin_success() {
    let (_, owner_token) = create_token_user(
        &uniq("order-owner"),
        &uniq("owner-role"),
        RolePermissions::Write,
    )
    .await;
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;

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
                                "product_id": product.product_id,
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
async fn test_delete_order_not_found() {
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/orders/{}", i32::MAX - 301))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_orders_by_status_query() {
    let (writer_id, _) = create_token_user(
        &uniq("order-writer"),
        &uniq("writer-role"),
        RolePermissions::Write,
    )
    .await;
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;
    let order_a = make_order(writer_id, product.product_id, "10.00", "Pending").await;
    let order_b = make_order(writer_id, product.product_id, "20.00", "Pending").await;

    let app = app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", order_a.order_id))
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
    let ids: Vec<i32> = orders.iter().map(|o| o.order_id).collect();
    assert!(ids.contains(&order_b.order_id));
    assert!(!ids.contains(&order_a.order_id));

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
    assert!(orders.iter().any(|o| o.order_id == order_a.order_id));
}

#[tokio::test]
async fn test_get_orders_by_invalid_status_empty() {
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;

    let response = app()
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
async fn test_get_all_orders_non_admin_forbidden() {
    let (_, reader_token) = create_token_user(
        &uniq("order-reader"),
        &uniq("reader-role"),
        RolePermissions::Read,
    )
    .await;

    let response = app()
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
async fn test_get_user_orders_by_name() {
    let username = uniq("order-writer");
    let (user_id, token) =
        create_token_user(&username, &uniq("writer-role"), RolePermissions::Write).await;
    let product = create_product(&uniq("ProductOne")).await;
    let order = make_order(user_id, product.product_id, "20.00", "Pending").await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/orders/user/{}", username))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert!(orders.iter().any(|o| o.order_id == order.order_id));
}

#[tokio::test]
async fn test_update_order_status_success() {
    let (writer_id, writer_token) = create_token_user(
        &uniq("order-writer"),
        &uniq("writer-role"),
        RolePermissions::Write,
    )
    .await;
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;
    let product = create_product(&uniq("ProductOne")).await;
    let order = make_order(writer_id, product.product_id, "10.00", "Pending").await;

    let response = app()
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", order.order_id))
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

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/orders/{}", order.order_id))
                .header("Authorization", format!("Bearer {}", writer_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let order_resp: OrderResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(order_resp.status, Some("Accepted".to_string()));
}

#[tokio::test]
async fn test_update_order_status_not_found() {
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", i32::MAX - 302))
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
async fn test_update_order_status_invalid_status() {
    let (_, admin_token) = create_token_user(
        &uniq("order-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/orders/{}", i32::MAX - 303))
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
async fn test_get_order_via_order_url() {
    let product = create_product(&uniq("ProductOne")).await;

    let app = app();

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
                                "product_id": product.product_id,
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

    let order_path = created
        .order_url
        .split("/api/v1")
        .last()
        .unwrap()
        .to_string();
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
async fn test_get_order_tampered_order_url() {
    let product = create_product(&uniq("ProductOne")).await;

    let app = app();

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
                                "product_id": product.product_id,
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

    let now = chrono::Utc::now().timestamp() as u64;
    let url = format!("/orders/{}?exp={}&sig=deadbeef", order_id, now + 3600);

    let response = app
        .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_order_expired_order_url() {
    let product = create_product(&uniq("ProductOne")).await;

    let app = app();

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
                                "product_id": product.product_id,
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

    let past_exp = chrono::Utc::now().timestamp() as u64 - 60;
    let sig = sign_order_url(order_id, past_exp).unwrap();
    let url = format!("/orders/{}?exp={}&sig={}", order_id, past_exp, sig);

    let response = app
        .oneshot(Request::builder().uri(url).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn test_get_order_by_id_unauthorized() {
    let product = create_product(&uniq("ProductOne")).await;

    let app = app();

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
                                "product_id": product.product_id,
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
async fn test_get_orders_by_role_admin_only() {
    let admin_role = uniq("admin-role");
    let (admin_id, admin_token) =
        create_token_user(&uniq("order-admin"), &admin_role, RolePermissions::Admin).await;
    let product = create_product(&uniq("ProductOne")).await;
    let order = make_order(admin_id, product.product_id, "10.00", "Pending").await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/orders/role/{}", admin_role))
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let orders: Vec<OrderResponse> = serde_json::from_slice(&body).unwrap();
    assert!(orders.iter().any(|o| o.order_id == order.order_id));
}
