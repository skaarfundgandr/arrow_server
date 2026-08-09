use crate::api::controllers::product_controller;
use axum::Router;
use axum::routing::{delete, get, post, put};

pub fn routes() -> Router {
    Router::new()
        .route("/", get(product_controller::get_all_products))
        .route("/", post(product_controller::create_product))
        .route("/{id}", get(product_controller::get_product_by_id))
        .route("/{id}", put(product_controller::update_product))
        .route("/{id}", delete(product_controller::delete_product))
        .route("/{id}/image", post(product_controller::upload_product_image))
        .route("/{id}/image", delete(product_controller::delete_product_image))
}
