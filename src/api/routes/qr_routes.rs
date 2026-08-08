use crate::api::controllers::qr_controller;
use axum::Router;
use axum::routing::get;

pub fn routes() -> Router {
    Router::new()
        .route("/ordering", get(qr_controller::ordering_qr))
        .route("/visit", get(qr_controller::visit))
}
