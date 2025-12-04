use crate::api::routes::auth_routes;
use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Router, middleware};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

// TODO: Rework API implementation use https://github.com/sheroz/axum-rest-api-sample as reference
pub async fn start() {
    let cors_layer = CorsLayer::new().allow_origin(Any);
    let router = Router::new()
        .route("/api", get(|| async { "Arrow Server API is running!" }))
        .nest("/api/v1/auth", auth_routes::routes())
        .with_state::<()>(())
        .layer(cors_layer)
        .layer(middleware::from_fn(logging_middleware));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .await
        .expect("Failed to bind to address");

    tracing::info!("Listening on 127.0.0.1:3000");

    axum::serve(listener, router)
        .await
        .expect("Failed to start the server");
}

#[tracing::instrument(level = tracing::Level::TRACE, name = "axum", skip_all, fields(method=request.method().to_string(), uri=request.uri().to_string()))]
pub async fn logging_middleware(request: Request<Body>, next: Next) -> Response {
    tracing::trace!(
        "received a {} request to {}",
        request.method(),
        request.uri()
    );
    next.run(request).await
}
