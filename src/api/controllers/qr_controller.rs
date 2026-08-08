use crate::api::config::Config;
use crate::security::jwt::AccessClaims;
use crate::services::order_service::OrderService;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use qrcode::QrCode;
use qrcode::render::svg;

/// GET /qr/ordering (Admin only)
/// Returns an SVG QR code encoding the public ordering visit URL.
pub async fn ordering_qr(claims: AccessClaims) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    let mut is_admin = false;
    for role_id in roles {
        match service.is_admin(role_id as i32).await {
            Ok(true) => {
                is_admin = true;
                break;
            }
            Ok(false) => continue,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    if !is_admin {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let config = Config::default();
    let visit_url = format!("{}/api/v1/qr/visit", config.api_base_url);

    let code = match QrCode::new(visit_url.as_bytes()) {
        Ok(code) => code,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "QR generation failed").into_response();
        }
    };
    let svg = code.render::<svg::Color>().build();

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/svg+xml")],
        svg,
    )
        .into_response()
}

/// GET /qr/visit (public)
/// Redirects the visitor to the ordering frontend.
pub async fn visit() -> impl IntoResponse {
    let config = Config::default();
    (
        StatusCode::FOUND,
        [(header::LOCATION, config.ordering_base_url)],
    )
        .into_response()
}
