use arrow_server_lib::api::server::cors_layer_for_origins;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
use tower::ServiceExt;

fn app(origins: &[String]) -> Router {
    Router::new()
        .route("/", get(|| async { StatusCode::OK }))
        .layer(cors_layer_for_origins(origins).unwrap())
}

fn assert_vary_contains_origin(response: &Response) {
    let vary = response.headers().get("vary").unwrap().to_str().unwrap();
    assert!(
        vary.split(',')
            .any(|entry| entry.trim().eq_ignore_ascii_case("origin"))
    );
}

#[tokio::test]
async fn wildcard_get_allows_any_origin_without_vary() {
    let response = app(&["*".to_string()])
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .header("Origin", "http://browser.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "*"
    );
    assert!(response.headers().get("vary").is_none());
}

#[tokio::test]
async fn wildcard_preflight_allows_requested_method_without_vary() {
    let response = app(&["*".to_string()])
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/")
                .header("Origin", "http://browser.example")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "*"
    );
    assert!(
        response
            .headers()
            .get("access-control-allow-methods")
            .is_some()
    );
    assert!(response.headers().get("vary").is_none());
}

#[tokio::test]
async fn configured_origin_get_allows_matching_origin() {
    let response = app(&["http://allowed.example".to_string()])
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .header("Origin", "http://allowed.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "http://allowed.example"
    );
    assert_vary_contains_origin(&response);
}

#[tokio::test]
async fn configured_origin_get_omits_header_for_non_matching_origin() {
    let response = app(&["http://allowed.example".to_string()])
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .header("Origin", "http://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test]
async fn configured_origin_preflight_allows_requested_method() {
    let response = app(&["http://allowed.example".to_string()])
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/")
                .header("Origin", "http://allowed.example")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("access-control-allow-methods")
            .is_some()
    );
    assert_vary_contains_origin(&response);
}
