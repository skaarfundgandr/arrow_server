use crate::api::request::{CreateProductRequest, UpdateProductRequest};
use crate::api::response::ProductResponse;
use crate::security::jwt::AccessClaims;
use crate::services::errors::ProductServiceError;
use crate::services::product_category_service::ProductCategoryService;
use crate::services::product_service::ProductService;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

// NOTE: Only write/delete operations require authentication. Reads are public.
/// Get all products (public)
pub async fn get_all_products() -> impl IntoResponse {
    let service = ProductService::new();

    match service.get_all_products_public().await {
        Ok(products) => {
            let response: Vec<ProductResponse> = products.unwrap_or_default();
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}

/// Get product by ID (public)
pub async fn get_product_by_id(Path(product_id): Path<i32>) -> impl IntoResponse {
    let service = ProductService::new();

    match service.get_product_by_id_public(product_id).await {
        Ok(Some(product)) => (StatusCode::OK, Json(product)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Product not found").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}

/// Create a new product
pub async fn create_product(
    claims: AccessClaims,
    Json(payload): Json<CreateProductRequest>,
) -> impl IntoResponse {
    let service = ProductService::new();
    let product_category_service = ProductCategoryService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service
            .create_product(
                &payload.name,
                payload.description.as_deref(),
                payload.price.clone(),
                payload.product_image_uri.as_deref(),
                role_id as i32,
            )
            .await
        {
            Ok(_) => {
                return if product_category_service
                    .add_product_to_categories(
                        role_id as i32,
                        &payload.name,
                        payload.categories.unwrap_or_default(),
                    )
                    .await
                    .is_ok()
                {
                    (StatusCode::CREATED, "Product created").into_response()
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to assign categories to product",
                    )
                        .into_response()
                };
            }
            Err(ProductServiceError::PermissionDenied) => continue,
            Err(ProductServiceError::ProductAlreadyExists) => {
                return (StatusCode::CONFLICT, "Product already exists").into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to create product",
                )
                    .into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Update a product
pub async fn update_product(
    claims: AccessClaims,
    Path(product_id): Path<i32>,
    Json(payload): Json<UpdateProductRequest>,
) -> impl IntoResponse {
    let service = ProductService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        let has_product_updates = payload.name.is_some()
            || payload.description.is_some()
            || payload.price.is_some()
            || payload.product_image_uri.is_some();

        let update_result = if has_product_updates {
            service
                .update_product(
                    product_id,
                    payload.name.as_deref(),
                    payload.description.as_deref(),
                    payload.price.clone(),
                    payload.product_image_uri.as_deref(),
                    role_id as i32,
                )
                .await
        } else {
            Ok(())
        };

        match update_result {
            Ok(_) => {
                return if let Some(categories) = payload.categories {
                    let product_category_service = ProductCategoryService::new();

                    let name = if let Some(n) = payload.name {
                        n
                    } else {
                        match service.get_product_by_id(product_id, role_id as i32).await {
                            Ok(Some(p)) => p.name,
                            _ => {
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to retrieve product details",
                                )
                                    .into_response();
                            }
                        }
                    };

                    if product_category_service
                        .update_product_categories(role_id as i32, &name, categories)
                        .await
                        .is_ok()
                    {
                        (StatusCode::OK, "Product updated").into_response()
                    } else {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to update product categories",
                        )
                            .into_response()
                    }
                } else {
                    (StatusCode::OK, "Product updated").into_response()
                };
            }
            Err(ProductServiceError::PermissionDenied) => continue,
            Err(ProductServiceError::ProductNotFound) => {
                return (StatusCode::NOT_FOUND, "Product not found").into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to update product",
                )
                    .into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Delete a product
pub async fn delete_product(
    claims: AccessClaims,
    Path(product_id): Path<i32>,
) -> impl IntoResponse {
    let service = ProductService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.delete_product(product_id, role_id as i32).await {
            Ok(_) => return (StatusCode::OK, "Product deleted").into_response(),
            Err(ProductServiceError::PermissionDenied) => continue,
            Err(ProductServiceError::ProductNotFound) => {
                return (StatusCode::NOT_FOUND, "Product not found").into_response();
            }
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to delete product",
                )
                    .into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}
