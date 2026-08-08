use crate::api::config::Config;
use crate::api::routes::{
    auth_routes, category_routes, order_routes, product_routes, qr_routes, role_routes,
    user_routes,
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

#[derive(Debug)]
pub enum ServerError {
    Bind(std::io::Error),
    Serve(std::io::Error),
    Config(crate::api::config::ConfigError),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Bind(e) => write!(f, "Failed to bind to address: {}", e),
            ServerError::Serve(e) => write!(f, "Server failed: {}", e),
            ServerError::Config(e) => write!(f, "Configuration error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

pub async fn start() -> Result<(), ServerError> {
    Config::get().map_err(ServerError::Config)?;

    let user_service = crate::services::user_service::UserService::new();
    if let Err(e) = user_service.seed_admin_from_env().await {
        tracing::warn!("Failed to seed admin user from environment: {}", e);
    }

    let cors_layer = CorsLayer::new().allow_origin(Any);
    let router = Router::new()
        .route("/api", get(|| async { "Arrow Server API is running!" }))
        .nest("/api/v1/auth", auth_routes::routes())
        .nest("/api/v1/users", user_routes::routes())
        .nest("/api/v1/roles", role_routes::routes())
        .nest("/api/v1/products", product_routes::routes())
        .nest("/api/v1/categories", category_routes::routes())
        .nest("/api/v1/orders", order_routes::routes())
        .nest("/api/v1/qr", qr_routes::routes())
        .with_state::<()>(())
        .layer(cors_layer)
        .layer(middleware::from_fn(logging_middleware));

    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 3000)))
        .await
        .map_err(ServerError::Bind)?;

    tracing::info!("Listening on port 3000");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(ServerError::Serve)
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
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to install CTRL+C signal handler: {}", e);
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                tracing::error!("Failed to install terminate signal handler: {}", e);
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutting down gracefully...");
}
