use arrow_server_lib::api::controllers::category_controller::{
    add_category, add_product_to_category, delete_category, edit_category, get_categories,
    get_products_by_category, remove_product_from_category,
};
use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::response::{CategoryResponse, ProductResponse};
use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::security::jwt::JwtService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, post, put};
use http_body_util::BodyExt;
use serde_json::json;

use tower::ServiceExt;

use crate::common::{
    assign_product_to_category, create_category, create_product, create_user_with_role, uniq,
};

async fn create_token_user(role_name: &str, permission: RolePermissions) -> String {
    let (user, role) = create_user_with_role(&uniq("cat-user"), role_name).await;
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
    JwtService::new()
        .generate_token(user_dto)
        .await
        .expect("Failed to generate token")
}

fn app() -> Router {
    Router::new()
        .route("/categories", get(get_categories))
        .route("/categories", post(add_category))
        .route("/categories/{id}", put(edit_category))
        .route("/categories/{id}", delete(delete_category))
        .route("/categories/product", post(add_product_to_category))
        .route(
            "/categories/product/remove",
            post(remove_product_from_category),
        )
        .route(
            "/categories/{category_name}/products",
            get(get_products_by_category),
        )
}

#[tokio::test]
async fn test_get_categories_success() {
    let token = create_token_user(&uniq("cat-reader"), RolePermissions::Read).await;
    let electronics = create_category(&uniq("Electronics")).await;
    let books = create_category(&uniq("Books")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/categories")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let categories: Vec<CategoryResponse> = serde_json::from_slice(&body).unwrap();
    let names: Vec<String> = categories.iter().map(|c| c.name.clone()).collect();
    assert!(names.contains(&electronics.name));
    assert!(names.contains(&books.name));
}

#[tokio::test]
async fn test_add_category_success() {
    let token = create_token_user(&uniq("cat-writer"), RolePermissions::Write).await;
    let name = uniq("NewCategory");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/categories")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": name,
                        "description": "Description"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let category = CategoryRepo::new()
        .get_by_name(&name)
        .await
        .expect("Query failed")
        .expect("Category not found");
    assert_eq!(category.name, name);
}

#[tokio::test]
async fn test_edit_category_success() {
    let token = create_token_user(&uniq("cat-writer"), RolePermissions::Write).await;
    let category = create_category(&uniq("OldCategory")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/categories/{}", category.category_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "New Name"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_delete_category_success() {
    let token = create_token_user(&uniq("cat-writer"), RolePermissions::Write).await;
    let category = create_category(&uniq("ToDelete")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/categories/{}", category.category_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_add_product_to_category_success() {
    let token = create_token_user(&uniq("cat-writer"), RolePermissions::Write).await;
    let category = create_category(&uniq("Electronics")).await;
    let product = create_product(&uniq("Laptop")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/categories/product")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "category": category.name,
                        "product": product.name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_remove_product_from_category_success() {
    let token = create_token_user(&uniq("cat-writer"), RolePermissions::Write).await;
    let category = create_category(&uniq("Electronics")).await;
    let product = create_product(&uniq("Laptop")).await;
    assign_product_to_category(product.product_id, category.category_id).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/categories/product/remove")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "category": category.name,
                        "product": product.name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_products_by_category_name_success() {
    let token = create_token_user(&uniq("cat-reader"), RolePermissions::Read).await;
    let category = create_category(&uniq("Electronics")).await;
    let product = create_product(&uniq("Laptop")).await;
    assign_product_to_category(product.product_id, category.category_id).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/categories/{}/products", category.name))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let products: Vec<ProductResponse> = serde_json::from_slice(&body).unwrap();
    assert!(products.iter().any(|p| p.name == product.name));
}

#[tokio::test]
async fn test_get_categories_public_no_auth() {
    let electronics = create_category(&uniq("Electronics")).await;
    let books = create_category(&uniq("Books")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/categories")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let categories: Vec<CategoryResponse> = serde_json::from_slice(&body).unwrap();
    let names: Vec<String> = categories.iter().map(|c| c.name.clone()).collect();
    assert!(names.contains(&electronics.name));
    assert!(names.contains(&books.name));
}

#[tokio::test]
async fn test_get_products_by_category_public_no_auth() {
    let category = create_category(&uniq("Electronics")).await;
    let product = create_product(&uniq("Laptop")).await;
    assign_product_to_category(product.product_id, category.category_id).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/categories/{}/products", category.name))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let products: Vec<ProductResponse> = serde_json::from_slice(&body).unwrap();
    assert!(products.iter().any(|p| p.name == product.name));
}

#[tokio::test]
async fn test_get_products_by_category_name_not_found() {
    let token = create_token_user(&uniq("cat-reader"), RolePermissions::Read).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/categories/{}/products", uniq("missing")))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
