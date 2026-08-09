use arrow_server_lib::api::config::Config;
use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::user_controller::{
    delete_user, edit_user, get_all_users, get_user, get_user_by_name, login, refresh,
    register_user,
};
use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::security::jwt::JwtService;
use arrow_server_lib::services::user_service::UserService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, patch, post};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use crate::common::{create_user_with_role, ensure_customer_role, uniq};

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

async fn generate_token_for(user_id: i32, username: &str) -> String {
    let user_dto = UserDTO {
        user_id: Some(user_id),
        username: username.to_string(),
        role: None,
        created_at: None,
        updated_at: None,
    };
    JwtService::new()
        .generate_token(user_dto)
        .await
        .expect("Failed to generate token")
}

async fn create_admin_user(username: &str) -> (i32, String) {
    let user_id = create_test_user(username, "adminpass").await;
    let (_, role) = create_user_with_role(&uniq("user-admin"), &uniq("admin-role")).await;
    RoleRepo::new()
        .set_permissions(role.role_id, RolePermissions::Admin)
        .await
        .expect("Failed to set permission");
    UserRoleRepo::new()
        .add_user_role(user_id, role.role_id)
        .await
        .expect("Failed to assign role");
    let token = generate_token_for(user_id, username).await;
    (user_id, token)
}

async fn create_regular_user(username: &str) -> (i32, String) {
    let user_id = create_test_user(username, "regularpass").await;
    let (_, role) = create_user_with_role(&uniq("user-regular"), &uniq("regular-role")).await;
    RoleRepo::new()
        .set_permissions(role.role_id, RolePermissions::Read)
        .await
        .expect("Failed to set permission");
    UserRoleRepo::new()
        .add_user_role(user_id, role.role_id)
        .await
        .expect("Failed to assign role");
    let token = generate_token_for(user_id, username).await;
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
async fn test_register_user_success() {
    ensure_customer_role().await;
    let username = uniq("testuser");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": username,
                        "password": "testpassword123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());
    assert!(body["message"].is_string());
}

#[tokio::test]
async fn test_register_user_assigns_customer_role() {
    ensure_customer_role().await;
    let username = uniq("customer1");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": username,
                        "password": "testpassword123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let repo = UserRepo::new();
    let user = repo
        .get_by_username(&username)
        .await
        .expect("Query failed")
        .expect("User not found");
    let roles = UserRoleRepo::new()
        .get_roles_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "CUSTOMER");
    assert!(roles[0].has_permission(RolePermissions::Write));
    assert!(!roles[0].has_permission(RolePermissions::Admin));
}

#[tokio::test]
#[serial_test::serial(admin_seed)]
async fn test_register_admin_username_conflict() {
    let admin_username = Config::get().unwrap().admin_username.clone();

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": admin_username,
                        "password": "testpassword123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
#[serial_test::serial(admin_seed)]
async fn test_seed_admin_from_env_idempotent() {
    let user_service = UserService::new();
    user_service
        .seed_admin_from_env()
        .await
        .expect("Seeding failed");
    user_service
        .seed_admin_from_env()
        .await
        .expect("Second seeding failed");

    let repo = UserRepo::new();
    let users = repo.get_all().await.expect("Query failed").unwrap();
    let admin_users: Vec<_> = users
        .iter()
        .filter(|u| u.username == Config::get().unwrap().admin_username)
        .collect();
    assert_eq!(admin_users.len(), 1);

    let admin = admin_users[0];
    let roles = UserRoleRepo::new()
        .get_roles_by_user_id(admin.user_id)
        .await
        .expect("Failed to get roles");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "ADMIN");
    assert!(roles[0].has_permission(RolePermissions::Admin));
    assert!(roles[0].has_permission(RolePermissions::Read));
    assert!(roles[0].has_permission(RolePermissions::Write));
    assert!(roles[0].has_permission(RolePermissions::Delete));
}

#[tokio::test]
#[serial_test::serial(admin_seed)]
async fn test_login_env_admin_credentials() {
    UserService::new()
        .seed_admin_from_env()
        .await
        .expect("Seeding failed");

    let config = Config::get().unwrap();

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": config.admin_username,
                        "password": config.admin_password
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());

    let user = UserRepo::new()
        .get_by_username(&config.admin_username)
        .await
        .expect("Query failed")
        .expect("Admin user not found");
    let roles = UserRoleRepo::new()
        .get_roles_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "ADMIN");
}

#[tokio::test]
async fn test_login_success() {
    let username = uniq("loginuser");
    let _ = create_test_user(&username, "password123").await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": username,
                        "password": "password123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());
    assert_eq!(body["message"], "Login successful");
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let username = uniq("loginuser2");
    let _ = create_test_user(&username, "correctpassword").await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": username,
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
async fn test_login_user_not_found() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": uniq("missinguser"),
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
async fn test_refresh_success() {
    let username = uniq("refreshuser");
    let (_, token) = create_regular_user(&username).await;

    let response = app()
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

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["token"].is_string());
    assert_eq!(body["message"], "Token refreshed successfully");
}

#[tokio::test]
async fn test_get_all_users_with_data() {
    let (_, token) = create_admin_user(&uniq("admin")).await;
    let user1 = uniq("user1");
    let user2 = uniq("user2");
    let _ = create_test_user(&user1, "pass1").await;
    let _ = create_test_user(&user2, "pass2").await;

    let response = app()
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
    let usernames: Vec<String> = users
        .iter()
        .filter_map(|u| u.get("username").and_then(|n| n.as_str()).map(String::from))
        .collect();
    assert!(usernames.contains(&user1));
    assert!(usernames.contains(&user2));
}

#[tokio::test]
async fn test_get_all_users_unauthorized() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_user_by_id() {
    let (_, token) = create_admin_user(&uniq("admin")).await;
    let username = uniq("getbyid_user");
    let user_id = create_test_user(&username, "password").await;

    let response = app()
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
    assert_eq!(body["username"], username);
}

#[tokio::test]
async fn test_get_user_by_id_not_found() {
    let (_, token) = create_admin_user(&uniq("admin")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/users/{}", i32::MAX - 200))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_user_by_name() {
    let (_, token) = create_admin_user(&uniq("admin")).await;
    let username = uniq("searchuser");
    let _ = create_test_user(&username, "password").await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/users/search?username={}", username))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["username"], username);
}

#[tokio::test]
async fn test_get_user_by_name_not_found() {
    let (_, token) = create_admin_user(&uniq("admin")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/users/search?username={}", uniq("missing")))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_user_by_name_missing_param() {
    let (_, token) = create_admin_user(&uniq("admin")).await;

    let response = app()
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
async fn test_edit_user() {
    let (_, token) = create_admin_user(&uniq("admin")).await;
    let user_id = create_test_user(&uniq("edituser"), "password").await;
    let new_name = uniq("updateduser");

    let response = app()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/users/{}", user_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": new_name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let repo = UserRepo::new();
    let updated_user = repo
        .get_by_id(user_id)
        .await
        .expect("Query failed")
        .expect("User not found");
    assert_eq!(updated_user.username, new_name);
}

#[tokio::test]
async fn test_edit_user_not_found() {
    let (_, token) = create_admin_user(&uniq("admin")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/users/{}", i32::MAX - 201))
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
async fn test_edit_user_forbidden_for_non_admin() {
    let admin_id = create_test_user(&uniq("admin"), "adminpass").await;
    let (_, regular_token) = create_regular_user(&uniq("regular")).await;

    let response = app()
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
async fn test_delete_user() {
    let (_, token) = create_admin_user(&uniq("admin")).await;
    let user_id = create_test_user(&uniq("deleteuser"), "password").await;

    let response = app()
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

    let repo = UserRepo::new();
    let deleted = repo.get_by_id(user_id).await.expect("Query failed");
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let (_, token) = create_admin_user(&uniq("admin")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/users/{}", i32::MAX - 202))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
