use crate::api::controllers::user_controller::{login, refresh, register_user};
use axum::Router;
use axum::routing::{get, post};

pub fn routes() -> Router<()> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register_user))
        .route("/refresh", get(refresh))
}
