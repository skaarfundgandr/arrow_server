use arrow_server_lib::api::controllers::category_controller::{
    add_category, add_product_to_category, delete_category, edit_category, get_categories,
    get_products_by_category, remove_product_from_category,
};
use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::response::ProductResponse;
use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::categories::NewCategory;
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::user_roles::{NewUserRole, RolePermissions};
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::security::jwt::JwtService;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::Router;
use bigdecimal::BigDecimal;
use diesel::result;
use diesel_async::RunQueryDsl;
use http_body_util::BodyExt;

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
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(product_categories).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(categories).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
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

    let role_repo = UserRoleRepo::new();
    let jwt_service = JwtService::new();

    let new_role = NewUserRole {
        user_id,
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

async fn assign_product_to_category(product_id: i32, category_id: i32) {
    use arrow_server_lib::data::models::product_category::NewProductCategory;
    let repo = ProductCategoryRepo::new();
    let item = NewProductCategory {
        product_id: &product_id,
        category_id: &category_id,
    };
    repo.add(item).await.expect("Failed to assign");
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
#[serial_test::serial]
async fn test_get_products_by_category_name_success() {
    setup().await.expect("Setup failed");
    let (_, token) = create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    
    let cat_id = create_test_category("Electronics").await;
    let prod_id = create_test_product("Laptop", BigDecimal::from(1000)).await;
    assign_product_to_category(prod_id, cat_id).await;

    let app_router = app();

    let response = app_router
        .oneshot(
            Request::builder()
                .uri("/categories/Electronics/products")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let products: Vec<ProductResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(products.len(), 1);
    assert_eq!(products[0].name, "Laptop");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_products_by_category_name_not_found() {
    setup().await.expect("Setup failed");
    let (_, token) = create_user_with_role("reader", "pass", "READER", RolePermissions::Read).await;
    
    let app_router = app();

    let response = app_router
        .oneshot(
            Request::builder()
                .uri("/categories/NonExistent/products")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
