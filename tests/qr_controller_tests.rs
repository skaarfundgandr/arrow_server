use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::routes::qr_routes;
use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions};
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::security::jwt::JwtService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
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

    use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
    use arrow_server_lib::data::models::schema::orders::dsl::orders;
    use arrow_server_lib::data::models::schema::products::dsl::products;
    use arrow_server_lib::data::models::schema::roles::dsl::roles;
    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_user_with_role(
    username: &str,
    password: &str,
    role_name: &str,
    permission: RolePermissions,
) -> String {
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
    jwt_service
        .generate_token(user_dto)
        .await
        .expect("Failed to generate token")
}

fn app() -> Router {
    qr_routes::routes()
}

#[tokio::test]
#[serial_test::serial]
async fn test_ordering_qr_forbidden_for_non_admin() {
    setup().await.expect("Setup failed");
    let reader_token =
        create_user_with_role("qrreader", "pass", "READER", RolePermissions::Read).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ordering")
                .header("Authorization", format!("Bearer {}", reader_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[serial_test::serial]
async fn test_ordering_qr_returns_svg_for_admin() {
    setup().await.expect("Setup failed");
    let admin_token =
        create_user_with_role("qradmin", "pass", "ADMIN", RolePermissions::Admin).await;

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/ordering")
                .header("Authorization", format!("Bearer {}", admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("Missing content-type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("image/svg+xml"),
        "Unexpected content-type: {}",
        content_type
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let svg = String::from_utf8(body.to_vec()).expect("SVG body is not valid UTF-8");
    assert!(svg.contains("<svg"), "Body is not an SVG: {}", svg);
}

#[tokio::test]
#[serial_test::serial]
async fn test_visit_redirects_to_ordering_base_url() {
    setup().await.expect("Setup failed");

    let app = app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/visit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get("location")
        .expect("Missing location header")
        .to_str()
        .unwrap();
    let expected = std::env::var("ORDERING_BASE_URL").expect("ORDERING_BASE_URL must be set");
    assert_eq!(location, expected);
}
