use crate::api::routes::{
    auth_routes, category_routes, order_routes, product_routes, role_routes, user_routes,
};
use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::{Router, middleware};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

pub async fn start() {
    let cors_layer = CorsLayer::new().allow_origin(Any);
    let router = Router::new()
        .route("/api", get(|| async { "Arrow Server API is running!" }))
        .nest("/api/v1/auth", auth_routes::routes())
        .nest("/api/v1/users", user_routes::routes())
        .nest("/api/v1/roles", role_routes::routes())
        .nest("/api/v1/products", product_routes::routes())
        .nest("/api/v1/categories", category_routes::routes())
        .nest("/api/v1/orders", order_routes::routes())
        .with_state::<()>(())
        .layer(cors_layer)
        .layer(middleware::from_fn(logging_middleware));

    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 3000)))
        .await
        .expect("Failed to bind to address");

    tracing::info!("Listening on port 3000");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
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

pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install terminate signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutting down gracefully...");
}
