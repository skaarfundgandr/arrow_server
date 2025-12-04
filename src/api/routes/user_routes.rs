use axum::Router;
use axum::routing::{delete, get, post};
use crate::api::controllers::user_controller;
use crate::api::controllers::user_controller::{delete_user, edit_user, get_user_by_name};

pub fn routes() -> Router<()> {
    Router::new()
        .route("/", get(user_controller::get_all_users))
        .route("/{id}", get(user_controller::get_user))
        .route("/search", get(get_user_by_name))
        .route("/{id}", post(edit_user))
        .route("/{id}", delete(delete_user))
}