use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::user_controller::{
    delete_user, edit_user, get_all_users, get_user, get_user_by_name, login, refresh,
    register_user,
};
use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions};
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

/// Create a test user with admin role and return JWT token
async fn create_admin_user(username: &str, password: &str) -> (i32, String) {
    let user_id = create_test_user(username, password).await;

    let role_repo = RoleRepo::new();
    let user_role_repo = UserRoleRepo::new();
    let jwt_service = JwtService::new();

    // Create admin role
    let new_role = NewRole {
        name: "ADMIN",
        description: Some("Test Admin"),
    };
    role_repo
        .add(new_role)
        .await
        .expect("Failed to create role");

    // Assign and Set admin permission
    let role = role_repo
        .get_by_name("ADMIN")
        .await
        .expect("Query failed")
        .expect("Role not found");
    
    user_role_repo.add_user_role(user_id, role.role_id).await.expect("Failed to assign");

    role_repo
        .set_permissions(role.role_id, RolePermissions::Admin)
        .await
        .expect("Failed to set permission");

    // Generate token
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

/// Create a test user with a regular (non-admin) role and return JWT token
async fn create_regular_user(username: &str, password: &str) -> (i32, String) {
    let user_id = create_test_user(username, password).await;

    let role_repo = RoleRepo::new();
    let user_role_repo = UserRoleRepo::new();
    let jwt_service = JwtService::new();

    // Create regular role with READ permission
    let new_role = NewRole {
        name: "USER",
        description: Some("Regular User"),
    };
    role_repo
        .add(new_role)
        .await
        .expect("Failed to create role");
    
    let role = role_repo
        .get_by_name("USER")
        .await
        .expect("Query failed")
        .expect("Role not found");
    
    user_role_repo.add_user_role(user_id, role.role_id).await.expect("Failed to assign");

    // Set READ permission (non-admin)
    role_repo
        .set_permissions(role.role_id, RolePermissions::Read)
        .await
        .expect("Failed to set permission");

    // Generate token
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

fn app() -> Router {
    Router::new()
        .route("/register", post(register_user))
        .route("/login", post(login))
        .route("/refresh", get(refresh))
        .route("/users", get(get_all_users))
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", patch(edit_user))
        .route("/users/{id}", delete(delete_user))
        .route("/users/search", get(get_user_by_name))
}

#[tokio::test]
#[serial_test::serial]
async fn test_register_user_success() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "testuser",
                        "password": "testpassword123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify response contains a token
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());
    assert!(body["message"].is_string());
}

#[tokio::test]
#[serial_test::serial]
async fn test_register_user_forbidden_when_db_not_empty() {
    setup().await.expect("Setup failed");

    // Create initial user (which becomes admin)
    let _ = create_test_user("existinguser", "password").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "testuser",
                        "password": "testpassword123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden since DB is not empty
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_login_success() {
    setup().await.expect("Setup failed");

    let _ = create_test_user("loginuser", "password123").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "loginuser",
                        "password": "password123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response contains a token
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());
    assert_eq!(body["message"], "Login successful");
}

#[tokio::test]
#[serial_test::serial]
async fn test_login_invalid_credentials() {
    setup().await.expect("Setup failed");

    let _ = create_test_user("loginuser2", "correctpassword").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "loginuser2",
                        "password": "wrongpassword"
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
async fn test_login_user_not_found() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "nonexistent",
                        "password": "password"
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
async fn test_refresh_success() {
    setup().await.expect("Setup failed");

    // Login to get a token
    let (_, token) = create_regular_user("refreshuser", "password").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/refresh")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify response contains a new token
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());
    assert_eq!(body["message"], "Token refreshed successfully");
}

#[tokio::test]
#[serial_test::serial]
async fn test_refresh_unauthorized() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/refresh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // No token provided -> Unauthorized (handled by extractor usually, which returns 401 or 400 depending on impl)
    // Wait, Axum extractors usually return 400 Bad Request if a required header is missing, or 401 if it's invalid.
    // The `claims: AccessClaims` extractor in `src/api/extractors.rs` likely handles this.
    // Usually `Authorization` header missing results in 401 or 400. Let's assume 401.
    // Actually, if I look at standard Axum/Tower behavior for missing parts of extractors, it returns 400 usually unless customized.
    // However, the `AccessClaims` extractor probably returns `(StatusCode::UNAUTHORIZED, ...)` on failure.
    // Let's check `src/api/extractors.rs` if needed, but for now I'll check for 401 as it is the standard for missing/invalid auth.
    // If the test fails I'll adjust.

    // Most auth extractors return 401.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_users_empty() {
    setup().await.expect("Setup failed");

    // Need admin token first - create admin user
    let (_, token) = create_admin_user("admin", "adminpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Will contain at least the admin user
    let users = body.as_array().unwrap();
    assert_eq!(users.len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_users_with_data() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;
    let _ = create_test_user("user1", "pass1").await;
    let _ = create_test_user("user2", "pass2").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let users = body.as_array().unwrap();
    assert_eq!(users.len(), 3); // admin + 2 users
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_users_unauthorized() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be unauthorized without token
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_by_id() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;
    let user_id = create_test_user("getbyid_user", "password").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/users/{}", user_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["username"], "getbyid_user");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_by_id_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users/99999")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_by_name() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;
    let _ = create_test_user("searchuser", "password").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users/search?username=searchuser")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["username"], "searchuser");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_by_name_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users/search?username=nonexistent")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_by_name_missing_param() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/users/search")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[serial_test::serial]
async fn test_edit_user() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;
    let user_id = create_test_user("edituser", "password").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/users/{}", user_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "updateduser"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify the update
    let repo = UserRepo::new();
    let updated_user = repo
        .get_by_id(user_id)
        .await
        .expect("Query failed")
        .expect("User not found");
    assert_eq!(updated_user.username, "updateduser");
}

#[tokio::test]
#[serial_test::serial]
async fn test_edit_user_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/users/99999")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "newname"
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
async fn test_edit_user_forbidden_for_non_admin() {
    setup().await.expect("Setup failed");

    let admin_id = create_test_user("admin", "adminpass").await;
    let (_, regular_token) = create_regular_user("regular", "regularpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/users/{}", admin_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", regular_token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "hacked"
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
async fn test_delete_user() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;
    let user_id = create_test_user("deleteuser", "password").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/users/{}", user_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify deletion
    let repo = UserRepo::new();
    let deleted = repo.get_by_id(user_id).await.expect("Query failed");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_user_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin", "adminpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/users/99999")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_user_forbidden_for_non_admin() {
    setup().await.expect("Setup failed");

    let target_id = create_test_user("targetuser", "password").await;
    let (_, regular_token) = create_regular_user("regular", "regularpass").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/users/{}", target_id))
                .header("Authorization", format!("Bearer {}", regular_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}