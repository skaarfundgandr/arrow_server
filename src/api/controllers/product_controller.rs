use crate::api::request::{CreateProductRequest, UpdateProductRequest};
use crate::api::response::ProductResponse;
use crate::security::jwt::AccessClaims;
use crate::services::errors::ProductServiceError;
use crate::services::product_service::ProductService;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

// NOTE: All routes except get_all should only be accessible by admin users.
/// Get all products
pub async fn get_all_products(claims: AccessClaims) -> impl IntoResponse {
    let service = ProductService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_all_products(role_id as i32).await {
            Ok(products) => {
                let response: Vec<ProductResponse> = products
                    .unwrap_or_default()
                    .into_iter()
                    .map(ProductResponse::from)
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(ProductServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Get product by ID
pub async fn get_product_by_id(
    claims: AccessClaims,
    Path(product_id): Path<i32>,
) -> impl IntoResponse {
    let service = ProductService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_product_by_id(product_id, role_id as i32).await {
            Ok(Some(product)) => {
                return (StatusCode::OK, Json(ProductResponse::from(product))).into_response();
            }
            Ok(None) => return (StatusCode::NOT_FOUND, "Product not found").into_response(),
            Err(ProductServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Create a new product
pub async fn create_product(
    claims: AccessClaims,
    Json(payload): Json<CreateProductRequest>,
) -> impl IntoResponse {
    let service = ProductService::new();
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
            Ok(_) => return (StatusCode::CREATED, "Product created").into_response(),
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
        match service
            .update_product(
                product_id,
                payload.name.as_deref(),
                payload.description.as_deref(),
                payload.price.clone(),
                payload.product_image_uri.as_deref(),
                role_id as i32,
            )
            .await
        {
            Ok(_) => return (StatusCode::OK, "Product updated").into_response(),
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
