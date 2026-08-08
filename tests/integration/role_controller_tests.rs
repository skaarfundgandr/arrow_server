use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::controllers::role_controller::{
    assign_role_to_user, create_role, delete_role, get_all_roles, get_role_by_name,
    remove_permission, set_permission, update_role,
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

async fn create_test_user(username: &str) -> i32 {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = auth
        .hash_password("testpass")
        .await
        .expect("Hashing failed");

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

/// Create an admin user and return their token
async fn create_admin_user(username: &str) -> (i32, String) {
    let user_id = create_test_user(username).await;

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

    // Get the role to have ID
    let role = role_repo.get_by_name("ADMIN").await.unwrap().unwrap();

    // Assign to user
    user_role_repo.add_user_role(user_id, role.role_id).await.expect("Failed to assign");

    // Set admin permission
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

/// Create a regular (non-admin) user and return their token
async fn create_regular_user(username: &str) -> (i32, String) {
    let user_id = create_test_user(username).await;

    let role_repo = RoleRepo::new();
    let user_role_repo = UserRoleRepo::new();
    let jwt_service = JwtService::new();

    // Create regular role with READ permission
    let role_name = format!("{}_role", username);
    let new_role = NewRole {
        name: &role_name,
        description: Some("Regular User"),
    };
    role_repo
        .add(new_role)
        .await
        .expect("Failed to create role");
    
    let role = role_repo.get_by_name(&role_name).await.unwrap().unwrap();
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

async fn create_test_role(name: &str) -> i32 {
    let repo = RoleRepo::new();

    let new_role = NewRole {
        name,
        description: Some("Test role"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    repo.get_by_name(name)
        .await
        .expect("Failed to get role")
        .expect("Role not found")
        .role_id
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
#[serial_test::serial]
async fn test_get_all_roles_empty() {
    setup().await.expect("Setup failed");

    // Create admin user to get token
    let (_, token) = create_admin_user("admin").await;

    let app = app();

    let response = app
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
    // Will contain the admin role
    let roles = body.as_array().unwrap();
    assert_eq!(roles.len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_roles_with_data() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let _ = create_test_role("admin_role").await;
    let _ = create_test_role("user_role").await;

    let app = app();

    let response = app
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
    assert_eq!(roles.len(), 3); // ADMIN role + 2 test roles
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_roles_unauthorized() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
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
#[serial_test::serial]
async fn test_get_all_roles_forbidden_for_non_admin() {
    setup().await.expect("Setup failed");

    let (_, token) = create_regular_user("regular").await;

    let app = app();

    let response = app
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
#[serial_test::serial]
async fn test_create_role_success() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    // user creation for role is no longer needed/relevant for create_role

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "ignored", // Field present in DTO but ignored
                        "name": "new_role",
                        "description": "A new test role"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify creation
    let repo = RoleRepo::new();
    let role = repo
        .get_by_name("new_role")
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(role.name, "new_role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let _ = create_test_role("test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles/name/test_role")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["name"], "test_role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/roles/name/nonexistent")
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
async fn test_update_role() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let role_id = create_test_role("update_test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/roles/{}", role_id))
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "name": "updated_role_name",
                        "description": "Updated description"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify update
    let repo = RoleRepo::new();
    let role = repo
        .get_by_id(role_id)
        .await
        .expect("Query failed")
        .expect("Role not found");
    assert_eq!(role.name, "updated_role_name");
    assert_eq!(role.description, Some("Updated description".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_role_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/roles/99999")
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
#[serial_test::serial]
async fn test_delete_role() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let role_id = create_test_role("delete_test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/roles/{}", role_id))
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify deletion
    let repo = RoleRepo::new();
    let deleted = repo.get_by_id(role_id).await.expect("Query failed");
    assert!(deleted.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_role_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/roles/99999")
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
async fn test_set_permission() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let role_id = create_test_role("perm_test_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/roles/{}/permission", role_id))
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

    // Verify permission set
    let repo = RoleRepo::new();
    let role = repo
        .get_by_id(role_id)
        .await
        .expect("Query failed")
        .expect("Role not found");
    let perm = role.get_permissions().expect("No permissions");
    assert_eq!(perm.as_str(), "ADMIN");
}

#[tokio::test]
#[serial_test::serial]
async fn test_set_permission_invalid() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let role_id = create_test_role("invalid_perm_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/roles/{}/permission", role_id))
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
#[serial_test::serial]
async fn test_set_permission_role_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/99999/permission")
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
#[serial_test::serial]
async fn test_assign_role_to_user() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let user_id = create_test_user("assign_user").await;
    let _ = create_test_role("assigned_role").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/assign")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "assign_user",
                        "role_name": "assigned_role"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify role was assigned
    let repo = UserRoleRepo::new();
    let roles = repo
        .get_roles_by_user_id(user_id)
        .await
        .expect("Query failed");
    
    let has_role = roles.iter().any(|r| r.name == "assigned_role");
    assert!(has_role);
}

#[tokio::test]
#[serial_test::serial]
async fn test_assign_role_user_not_found() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/roles/assign")
                .header("content-type", "application/json")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "username": "nonexistent_user",
                        "role_name": "some_role"
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
async fn test_set_all_permission_types() {
    setup().await.expect("Setup failed");

    let (_, token) = create_admin_user("admin").await;
    let role_id = create_test_role("all_perms_role").await;

    let repo = RoleRepo::new();

    for perm in ["READ", "WRITE", "DELETE", "ADMIN"] {
        let app = app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/roles/{}/permission", role_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "permission": perm
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Failed to set {} permission",
            perm
        );

        let role = repo
            .get_by_id(role_id)
            .await
            .expect("Query failed")
            .expect("Role not found");
        assert_eq!(role.get_permissions().unwrap().as_str(), perm);
    }
}