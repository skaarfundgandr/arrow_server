use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::GlobalKeyExtractor;

#[tokio::test]
async fn governor_rejects_requests_after_burst() {
    let config = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(2)
        .key_extractor(GlobalKeyExtractor)
        .finish()
        .unwrap();
    let app = Router::new()
        .route("/", get(|| async { StatusCode::OK }))
        .layer(GovernorLayer::new(config));

    let mut statuses = Vec::new();
    for _ in 0..10 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        statuses.push(response.status());
    }

    assert_eq!(statuses[0], StatusCode::OK);
    assert_eq!(statuses[1], StatusCode::OK);
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
}
