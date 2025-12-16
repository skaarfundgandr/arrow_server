use crate::api::controllers::category_controller;
use axum::Router;
use axum::routing::{delete, get, post, put};

pub fn routes() -> Router {
    Router::new()
        .route("/", get(category_controller::get_categories))
        .route("/", post(category_controller::add_category))
        .route("/{id}", put(category_controller::edit_category))
        .route("/{id}", delete(category_controller::delete_category))
        .route("/product", post(category_controller::add_product_to_category))
        .route("/product/remove", post(category_controller::remove_product_from_category))
        .route("/{category_name}/products", get(category_controller::get_products_by_category))
}
