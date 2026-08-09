use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::product_controller::{
    create_product, delete_product, delete_product_image, get_all_products, get_product_by_id,
    update_product, upload_product_image,
};
use arrow_server_lib::api::response::ProductResponse;
use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::jwt::JwtService;
use arrow_server_lib::services::blob_storage_service::BlobStore;
use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, patch, post};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;

use tower::ServiceExt;

use crate::common::{
    create_category, create_product as make_product, create_user_with_role, png_bytes, uniq,
    StubBlobStore,
};

async fn create_token_user(role_name: &str, permission: RolePermissions) -> String {
    let (user, role) = create_user_with_role(&uniq("prod-user"), role_name).await;
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
        .route("/products", get(get_all_products))
        .route("/products", post(create_product))
        .route("/products/{id}", get(get_product_by_id))
        .route("/products/{id}", patch(update_product))
        .route("/products/{id}", delete(delete_product))
}

fn app_with_blob_store(store: Arc<dyn BlobStore>) -> Router {
    Router::new()
        .route("/products", get(get_all_products))
        .route("/products", post(create_product))
        .route("/products/{id}", get(get_product_by_id))
        .route("/products/{id}", patch(update_product))
        .route("/products/{id}", delete(delete_product))
        .route("/products/{id}/image", post(upload_product_image))
        .route("/products/{id}/image", delete(delete_product_image))
        .layer(Extension(store))
}

#[tokio::test]
async fn test_get_all_products_success() {
    let token = create_token_user(&uniq("prod-reader"), RolePermissions::Read).await;
    let product1 = make_product(&uniq("ProductOne")).await;
    let product2 = make_product(&uniq("ProductTwo")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/products")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let products: Vec<ProductResponse> = serde_json::from_slice(&body).unwrap();
    let names: Vec<String> = products.iter().map(|p| p.name.clone()).collect();
    assert!(names.contains(&product1.name));
    assert!(names.contains(&product2.name));
}

#[tokio::test]
async fn test_create_product_success() {
    let token = create_token_user(&uniq("prod-writer"), RolePermissions::Write).await;
    let name = uniq("NewProduct");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/products")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": name,
                        "description": "A new product",
                        "price": 15.50,
                        "product_image_uri": "http://example.com/image.png"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let product = ProductRepo::new()
        .get_by_name(&name)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert_eq!(product.name, name);
}

#[tokio::test]
async fn test_get_product_by_id_success() {
    let token = create_token_user(&uniq("prod-reader"), RolePermissions::Read).await;
    let product = make_product(&uniq("ProductOne")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/products/{}", product.product_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let product_resp: ProductResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(product_resp.name, product.name);
}

#[tokio::test]
async fn test_update_product_success() {
    let token = create_token_user(&uniq("prod-writer"), RolePermissions::Write).await;
    let product = make_product(&uniq("OldProduct")).await;
    let new_name = uniq("NewProduct");

    let response = app()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/products/{}", product.product_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": new_name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let updated = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert_eq!(updated.name, new_name);
}

#[tokio::test]
async fn test_delete_product_success() {
    let token = create_token_user(&uniq("prod-deleter"), RolePermissions::Delete).await;
    let product = make_product(&uniq("ToDelete")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/products/{}", product.product_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let deleted = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed");
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_create_product_with_categories() {
    let token = create_token_user(&uniq("prod-writer"), RolePermissions::Write).await;
    let cat1 = create_category(&uniq("Cat1")).await;
    let cat2 = create_category(&uniq("Cat2")).await;
    let name = uniq("ProductWithCats");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/products")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": name,
                        "description": "A new product",
                        "price": 15.50,
                        "product_image_uri": "http://example.com/image.png",
                        "categories": [cat1.name, cat2.name]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let product = ProductRepo::new()
        .get_by_name(&name)
        .await
        .unwrap()
        .unwrap();

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/products/{}", product.product_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let product_resp: ProductResponse = serde_json::from_slice(&body).unwrap();

    assert!(product_resp.categories.is_some());
    let cats = product_resp.categories.unwrap();
    assert_eq!(cats.len(), 2);
    let cat_names: Vec<String> = cats.into_iter().map(|c| c.name).collect();
    assert!(cat_names.contains(&cat1.name));
    assert!(cat_names.contains(&cat2.name));
}

#[tokio::test]
async fn test_get_all_products_public_no_auth() {
    let product1 = make_product(&uniq("ProductOne")).await;
    let product2 = make_product(&uniq("ProductTwo")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/products")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let products: Vec<ProductResponse> = serde_json::from_slice(&body).unwrap();
    let names: Vec<String> = products.iter().map(|p| p.name.clone()).collect();
    assert!(names.contains(&product1.name));
    assert!(names.contains(&product2.name));
}

#[tokio::test]
async fn test_get_product_by_id_public_no_auth() {
    let product = make_product(&uniq("ProductOne")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/products/{}", product.product_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let product_resp: ProductResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(product_resp.name, product.name);
}

#[tokio::test]
async fn test_upload_product_image_requires_auth() {
    let product = make_product(&uniq("NoAuthImageProduct")).await;
    let store: Arc<dyn BlobStore> = Arc::new(StubBlobStore::new());

    let response = app_with_blob_store(store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/products/{}/image", product.product_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_delete_product_image_requires_auth() {
    let product = make_product(&uniq("NoAuthImageDelete")).await;
    let store: Arc<dyn BlobStore> = Arc::new(StubBlobStore::new());

    let response = app_with_blob_store(store)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/products/{}/image", product.product_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_upload_product_image_success() {
    let token = create_token_user(&uniq("prod-img-writer"), RolePermissions::Write).await;
    let product = make_product(&uniq("ImageUploadProduct")).await;
    let store: Arc<dyn BlobStore> = Arc::new(StubBlobStore::new());

    let boundary = "arrow-boundary-12345";
    let png = png_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"img.png\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(&png);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let response = app_with_blob_store(store)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/products/{}/image", product.product_id))
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", format!("multipart/form-data; boundary={}", boundary))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert!(stored.product_image_uri.is_some(), "Blob path should be stored");
    assert!(stored
        .product_image_uri
        .unwrap()
        .starts_with("products/"));
}

#[tokio::test]
async fn test_delete_product_image_success() {
    let token = create_token_user(&uniq("prod-img-admin"), RolePermissions::Admin).await;
    let product = make_product(&uniq("ImageDeleteProduct")).await;
    let store: Arc<dyn BlobStore> = Arc::new(StubBlobStore::new());
    let app = app_with_blob_store(store.clone());

    let boundary = "arrow-boundary-67890";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"img.png\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(&png_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let upload = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/products/{}/image", product.product_id))
                .header("Authorization", format!("Bearer {}", token.clone()))
                .header("content-type", format!("multipart/form-data; boundary={}", boundary))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/products/{}/image", product.product_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert!(
        stored.product_image_uri.is_none(),
        "Image column should be nulled"
    );
}
