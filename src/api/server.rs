use crate::api::config::Config;
use crate::api::routes::{
    auth_routes, category_routes, order_routes, product_routes, qr_routes, role_routes, user_routes,
};
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::get;
use axum::{Router, middleware};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tower_http::cors::{Any, CorsLayer};

const AUTH_LIMIT_PER_SECOND: u64 = 2;
const AUTH_LIMIT_BURST: u32 = 5;
const ORDER_LIMIT_PER_SECOND: u64 = 6;
const ORDER_LIMIT_BURST: u32 = 10;
const LIMITER_RETAIN_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum ServerError {
    Bind(std::io::Error),
    Serve(std::io::Error),
    Config(crate::api::config::ConfigError),
    Database(crate::data::database::DatabaseError),
    RateLimit(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Bind(e) => write!(f, "Failed to bind to address: {}", e),
            ServerError::Serve(e) => write!(f, "Server failed: {}", e),
            ServerError::Config(e) => write!(f, "Configuration error: {}", e),
            ServerError::Database(e) => write!(f, "Database unavailable at startup: {}", e),
            ServerError::RateLimit(msg) => write!(f, "Rate limit configuration error: {}", msg),
        }
    }
}

impl std::error::Error for ServerError {}

pub async fn start() -> Result<(), ServerError> {
    let config = Config::get().map_err(ServerError::Config)?;

    let database = crate::data::database::Database::new().await;
    database
        .get_connection()
        .await
        .map_err(ServerError::Database)
        .map(drop)?;

    let auth_config = GovernorConfigBuilder::default()
        .per_second(AUTH_LIMIT_PER_SECOND)
        .burst_size(AUTH_LIMIT_BURST)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .ok_or_else(|| ServerError::RateLimit("invalid auth limiter configuration".to_string()))?;
    let order_config = GovernorConfigBuilder::default()
        .per_second(ORDER_LIMIT_PER_SECOND)
        .burst_size(ORDER_LIMIT_BURST)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .ok_or_else(|| ServerError::RateLimit("invalid order limiter configuration".to_string()))?;

    let auth_limiter = auth_config.limiter().clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LIMITER_RETAIN_INTERVAL).await;
            auth_limiter.retain_recent();
        }
    });
    let order_limiter = order_config.limiter().clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LIMITER_RETAIN_INTERVAL).await;
            order_limiter.retain_recent();
        }
    });

    let user_service = crate::services::user_service::UserService::new();
    if let Err(e) = user_service.seed_admin_from_env().await {
        tracing::warn!("Failed to seed admin user from environment: {}", e);
    }

    let cors_layer = build_cors_layer(config)?;
    let router = Router::new()
        .route("/api", get(|| async { "Arrow Server API is running!" }))
        .nest(
            "/api/v1/auth",
            auth_routes::routes().layer(GovernorLayer::new(auth_config)),
        )
        .nest("/api/v1/users", user_routes::routes())
        .nest("/api/v1/roles", role_routes::routes())
        .nest("/api/v1/products", product_routes::routes())
        .nest("/api/v1/categories", category_routes::routes())
        .nest(
            "/api/v1/orders",
            order_routes::routes().layer(GovernorLayer::new(order_config)),
        )
        .nest("/api/v1/qr", qr_routes::routes())
        .with_state::<()>(())
        .layer(cors_layer)
        .layer(middleware::from_fn(logging_middleware));

    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 3000)))
        .await
        .map_err(ServerError::Bind)?;

    tracing::info!("Listening on port 3000");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(ServerError::Serve)
}

fn build_cors_layer(config: &Config) -> Result<CorsLayer, ServerError> {
    cors_layer_for_origins(&config.cors_allowed_origins)
}

pub fn cors_layer_for_origins(origins: &[String]) -> Result<CorsLayer, ServerError> {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .max_age(Duration::from_secs(600));

    if origins.iter().any(|origin| origin == "*") {
        return Ok(cors.allow_origin(Any));
    }

    let origins = origins
        .iter()
        .map(|origin| {
            origin.parse::<HeaderValue>().map_err(|error| {
                ServerError::Config(crate::api::config::ConfigError::InvalidVar {
                    name: "CORS_ALLOWED_ORIGINS".to_string(),
                    reason: format!("invalid origin {origin:?}: {error}"),
                })
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(cors.allow_origin(origins))
}

#[tracing::instrument(level = tracing::Level::TRACE, name = "axum", skip_all, fields(method=request.method().to_string(), uri=request.uri().path().to_string()))]
pub async fn logging_middleware(request: Request<Body>, next: Next) -> Response {
    tracing::trace!(
        "received a {} request to {}",
        request.method(),
        request.uri().path()
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
