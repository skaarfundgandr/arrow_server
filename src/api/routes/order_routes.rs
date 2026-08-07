use crate::api::controllers::order_controller;
use axum::Router;
use axum::routing::{get, post};

pub fn routes() -> Router {
    Router::new()
        .route("/", get(order_controller::get_all_orders))
        .route("/", post(order_controller::create_order))
        .route("/{id}", get(order_controller::get_order_by_id))
        .route("/{id}", post(order_controller::update_order_status))
        .route("/{id}/pay", post(order_controller::pay_order))
        .route(
            "/user/{username}",
            get(order_controller::get_user_orders_by_name),
        )
        .route(
            "/role/{role_name}",
            get(order_controller::get_orders_by_role),
        )
}
