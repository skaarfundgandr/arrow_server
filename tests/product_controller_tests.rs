use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::product_controller::{
    create_product, delete_product, get_all_products, get_product_by_id, update_product,
};
use arrow_server_lib::api::response::ProductResponse;
use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::categories::NewCategory;
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions};
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::security::jwt::JwtService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, patch, post};
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

    use arrow_server_lib::data::models::schema::categories::dsl::categories;
    use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
    use arrow_server_lib::data::models::schema::orders::dsl::orders;
    use arrow_server_lib::data::models::schema::product_categories::dsl::product_categories;
    use arrow_server_lib::data::models::schema::products::dsl::products;
    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
    use arrow_server_lib::data::models::schema::roles::dsl::roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(product_categories)
        .execute(&mut conn)
        .await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(categories).execute(&mut conn).await?;
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

async fn create_test_category(name: &str) -> i32 {
    let repo = CategoryRepo::new();
    let category = NewCategory {
        name,
        description: Some("Test Category"),
    };
    repo.add(category).await.expect("Failed to add category");
    repo.get_by_name(name)
        .await
        .expect("Failed to get category")
        .expect("Category not found")
        .category_id
}

fn app() -> Router {
    Router::new()
        .route("/products", get(get_all_products))
        .route("/products", post(create_product))
        .route("/products/{id}", get(get_product_by_id))
        .route("/products/{id}", patch(update_product))
        .route("/products/{id}", delete(delete_product))
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_products_success() {
    setup().await.expect("Setup failed");
    let (_, token) = create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    let _ = create_test_product("Product 1", BigDecimal::from(10)).await;
    let _ = create_test_product("Product 2", BigDecimal::from(20)).await;

    let app = app();

    let response = app
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
    assert_eq!(products.len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_product_success() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/products")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "New Product",
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
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_product_forbidden() {
    setup().await.expect("Setup failed");
    let (_, token) = create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/products")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "New Product",
                        "price": 15.50
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
async fn test_get_product_by_id_success() {
    setup().await.expect("Setup failed");
    let (_, token) = create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    let pid = create_test_product("Product 1", BigDecimal::from(10)).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/products/{}", pid))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let product: ProductResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(product.name, "Product 1");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_success() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid = create_test_product("Old Name", BigDecimal::from(10)).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/products/{}", pid))
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

    assert_eq!(response.status(), StatusCode::OK);

    // Verify update
    let repo = ProductRepo::new();
    let product = repo.get_by_id(pid).await.unwrap().unwrap();
    assert_eq!(product.name, "New Name");
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_product_success() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("deleter", "pass", "DELETER", RolePermissions::Delete).await;
    let pid = create_test_product("To Delete", BigDecimal::from(10)).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/products/{}", pid))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify deletion
    let repo = ProductRepo::new();
    let product = repo.get_by_id(pid).await.unwrap();
    assert!(product.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_product_with_categories() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let _ = create_test_category("Cat1").await;
    let _ = create_test_category("Cat2").await;

    let app_router = app();

    let response = app_router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/products")
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "Product With Cats",
                        "description": "A new product",
                        "price": 15.50,
                        "product_image_uri": "http://example.com/image.png",
                        "categories": ["Cat1", "Cat2"]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify categories
    let repo = ProductRepo::new();
    let product = repo
        .get_by_name("Product With Cats")
        .await
        .unwrap()
        .unwrap();

    // We can fetch via endpoint to see if categories are returned
    let app_router2 = app();
    let response = app_router2
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
    assert!(cat_names.contains(&"Cat1".to_string()));
    assert!(cat_names.contains(&"Cat2".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_categories() {
    setup().await.expect("Setup failed");
    let (_, token) =
        create_user_with_role("writer", "pass", "WRITER", RolePermissions::Write).await;
    let pid = create_test_product("Product Update", BigDecimal::from(10)).await;
    let _ = create_test_category("CatA").await;
    let _ = create_test_category("CatB").await;

    // First update to add categories
    let app_router = app();
    let response = app_router
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/products/{}", pid))
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "categories": ["CatA", "CatB"]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify
    let app_router2 = app();
    let response = app_router2
        .oneshot(
            Request::builder()
                .uri(format!("/products/{}", pid))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let product_resp: ProductResponse = serde_json::from_slice(&body).unwrap();
    let cats = product_resp.categories.unwrap();
    assert_eq!(cats.len(), 2);

    // Second update to change categories (remove CatB)
    let app_router3 = app();
    let response = app_router3
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/products/{}", pid))
                .header("Authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "categories": ["CatA"]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify again
    let app_router4 = app();
    let response = app_router4
        .oneshot(
            Request::builder()
                .uri(format!("/products/{}", pid))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let product_resp: ProductResponse = serde_json::from_slice(&body).unwrap();
    let cats = product_resp.categories.unwrap();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0].name, "CatA");
}