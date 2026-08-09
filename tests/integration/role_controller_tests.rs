use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::role_controller::{
    assign_role_to_user, create_role, delete_role, get_all_roles, get_role_by_name,
    remove_permission, set_permission, update_role,
};
use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::jwt::JwtService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, patch, post};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

use crate::common::{create_role as make_role, create_user, create_user_with_role, uniq};

async fn create_token_user(username: &str, role_name: &str, permission: RolePermissions) -> String {
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
    JwtService::new()
        .generate_token(user_dto)
        .await
        .expect("Failed to generate token")
}

async fn create_admin_token() -> String {
    create_token_user(
        &uniq("role-admin"),
        &uniq("admin-role"),
        RolePermissions::Admin,
    )
    .await
}

async fn create_regular_token() -> String {
    create_token_user(
        &uniq("role-regular"),
        &uniq("regular-role"),
        RolePermissions::Read,
    )
    .await
}

fn app() -> Router {
    Router::new()
        .route("/roles", get(get_all_roles))
        .route("/roles", post(create_role))
        .route("/roles/name/{name}", get(get_role_by_name))
        .route("/roles/{id}", patch(update_role))
        .route("/roles/{id}", delete(delete_role))
        .route("/roles/{id}/permission", post(set_permission))
        .route("/roles/{id}/permission", delete(remove_permission))
        .route("/roles/assign", post(assign_role_to_user))
}

#[tokio::test]
async fn test_get_all_roles_with_data() {
    let token = create_admin_token().await;
    let role1 = make_role(&uniq("admin_role")).await;
    let role2 = make_role(&uniq("user_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/roles")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let roles = body.as_array().unwrap();
    let names: Vec<String> = roles
        .iter()
        .filter_map(|r| r.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    assert!(names.contains(&role1.name));
    assert!(names.contains(&role2.name));
}

#[tokio::test]
async fn test_get_all_roles_unauthorized() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/roles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_all_roles_forbidden_for_non_admin() {
    let token = create_regular_token().await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/roles")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_create_role_success() {
    let token = create_admin_token().await;
    let name = uniq("new_role");

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "ignored",
                        "name": name,
                        "description": "A new test role"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let role = RoleRepo::new()
        .get_by_name(&name)
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(role.name, name);
}

#[tokio::test]
async fn test_get_role_by_name() {
    let token = create_admin_token().await;
    let role = make_role(&uniq("test_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/roles/name/{}", role.name))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["name"], role.name);
}

#[tokio::test]
async fn test_get_role_by_name_not_found() {
    let token = create_admin_token().await;

    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/roles/name/{}", uniq("missing")))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_role() {
    let token = create_admin_token().await;
    let role = make_role(&uniq("update_test_role")).await;
    let new_name = uniq("updated_role_name");

    let response = app()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/roles/{}", role.role_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": new_name,
                        "description": "Updated description"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let updated = RoleRepo::new()
        .get_by_id(role.role_id)
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(updated.name, new_name);
    assert_eq!(updated.description, Some("Updated description".to_string()));
}

#[tokio::test]
async fn test_update_role_not_found() {
    let token = create_admin_token().await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/roles/{}", i32::MAX - 100))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "new_name"
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
async fn test_delete_role() {
    let token = create_admin_token().await;
    let role = make_role(&uniq("delete_test_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/roles/{}", role.role_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let deleted = RoleRepo::new()
        .get_by_id(role.role_id)
        .await
        .expect("Query failed");
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_delete_role_not_found() {
    let token = create_admin_token().await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/roles/{}", i32::MAX - 101))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_set_permission() {
    let token = create_admin_token().await;
    let role = make_role(&uniq("perm_test_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/roles/{}/permission", role.role_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "permission": "ADMIN"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let updated = RoleRepo::new()
        .get_by_id(role.role_id)
        .await
        .expect("Query failed")
        .expect("Role not found");
    let perm = updated.get_permissions().expect("No permissions");
    assert_eq!(perm.as_str(), "ADMIN");
}

#[tokio::test]
async fn test_set_permission_invalid() {
    let token = create_admin_token().await;
    let role = make_role(&uniq("invalid_perm_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/roles/{}/permission", role.role_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "permission": "INVALID_PERMISSION"
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
async fn test_set_permission_role_not_found() {
    let token = create_admin_token().await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/roles/{}/permission", i32::MAX - 102))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "permission": "READ"
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
async fn test_assign_role_to_user() {
    let token = create_admin_token().await;
    let username = uniq("assign_user");
    let user = create_user(&username).await;
    let role = make_role(&uniq("assigned_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/assign")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": username,
                        "role_name": role.name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let roles = UserRoleRepo::new()
        .get_roles_by_user_id(user.user_id)
        .await
        .expect("Query failed");
    assert!(roles.iter().any(|r| r.name == role.name));
}

#[tokio::test]
async fn test_assign_role_user_not_found() {
    let token = create_admin_token().await;
    let role = make_role(&uniq("some_role")).await;

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/assign")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": uniq("missing_user"),
                        "role_name": role.name
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
