use arrow_server_lib::api::controllers::dto::user_dto::UserDTO;
use arrow_server_lib::api::routes::qr_routes;
use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::security::jwt::JwtService;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::common::{create_user_with_role, uniq};

async fn create_token_user(role_name: &str, permission: RolePermissions) -> String {
    let (user, role) = create_user_with_role(&uniq("qr-user"), role_name).await;
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
    qr_routes::routes()
}

#[tokio::test]
async fn test_ordering_qr_forbidden_for_non_admin() {
    let reader_token =
        create_token_user(&uniq("qr-reader"), RolePermissions::Read).await;

    let response = app()
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
async fn test_ordering_qr_returns_svg_for_admin() {
    let admin_token =
        create_token_user(&uniq("qr-admin"), RolePermissions::Admin).await;

    let response = app()
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
async fn test_visit_redirects_to_ordering_base_url() {
    let response = app()
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
