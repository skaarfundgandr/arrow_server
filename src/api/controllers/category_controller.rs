use crate::api::request::{AssignCategoryRequest, CreateCategoryRequest, UpdateCategoryRequest};
use crate::data::repos::implementors::category_repo::CategoryRepo;
use crate::security::jwt::AccessClaims;
use crate::services::errors::ProductCategoryServiceError;
use crate::services::product_category_service::ProductCategoryService;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn get_categories() -> impl IntoResponse {
    let service = ProductCategoryService::new();

    match service.get_categories_public().await {
        Ok(categories) => {
            let response = categories.unwrap_or_default();
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}

pub async fn add_category(
    claims: AccessClaims,
    Json(payload): Json<CreateCategoryRequest>,
) -> impl IntoResponse {
    let service = ProductCategoryService::new();

    if claims.roles.is_none() {
        tracing::error!("Roles is None");
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role in claims.roles.unwrap() {
        // Clone payload because we might iterate
        match service.add_category(role as i32, payload.clone()).await {
            Ok(_) => {
                tracing::info!("Added category {}", payload.name);
                return (StatusCode::CREATED, "Category added successfully").into_response();
            }
            Err(ProductCategoryServiceError::PermissionDenied) => continue,
            Err(_) => {
                tracing::error!("Failed to add category {}", payload.name);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

pub async fn edit_category(
    claims: AccessClaims,
    Path(category_id): Path<i32>,
    Json(payload): Json<UpdateCategoryRequest>,
) -> impl IntoResponse {
    let service = ProductCategoryService::new();

    if claims.roles.is_none() {
        tracing::error!("Roles is none");
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role in claims.roles.unwrap() {
        match service
            .edit_category(role as i32, category_id, payload.clone())
            .await
        {
            Ok(_) => {
                tracing::info!("Edited category {}", category_id);
                return (StatusCode::CREATED, "Category edited successfully").into_response();
            }
            Err(ProductCategoryServiceError::PermissionDenied) => continue,
            Err(_) => {
                tracing::error!("Failed to edit category {}", category_id);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

pub async fn add_product_to_category(
    claims: AccessClaims,
    Json(payload): Json<AssignCategoryRequest>,
) -> impl IntoResponse {
    let service = ProductCategoryService::new();

    if claims.roles.is_none() {
        tracing::error!("Roles is none");
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role in claims.roles.unwrap() {
        match service
            .add_product_to_category(role as i32, payload.clone())
            .await
        {
            Ok(_) => {
                tracing::info!(
                    "Assigned product {} to category {}",
                    payload.product,
                    payload.category
                );
                return (
                    StatusCode::CREATED,
                    "Product assigned to category successfully",
                )
                    .into_response();
            }
            Err(ProductCategoryServiceError::PermissionDenied) => continue,
            Err(_) => {
                tracing::error!(
                    "Failed to assign product {} to category {}",
                    payload.product,
                    payload.category
                );
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

pub async fn delete_category(
    claims: AccessClaims,
    Path(category_id): Path<i32>,
) -> impl IntoResponse {
    let service = ProductCategoryService::new();

    if claims.roles.is_none() {
        tracing::error!("Roles is none");
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role in claims.roles.unwrap() {
        match service.delete_category(role as i32, category_id).await {
            Ok(_) => {
                tracing::info!("Deleted category {}", category_id);
                return (StatusCode::OK, "Category deleted successfully").into_response();
            }
            Err(ProductCategoryServiceError::PermissionDenied) => continue,
            Err(_) => {
                tracing::error!("Failed to delete category {}", category_id);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

pub async fn remove_product_from_category(
    claims: AccessClaims,
    Json(payload): Json<AssignCategoryRequest>,
) -> impl IntoResponse {
    let service = ProductCategoryService::new();

    if claims.roles.is_none() {
        tracing::error!("Roles is none");
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role in claims.roles.unwrap() {
        match service
            .remove_product_from_category(role as i32, &payload.category, &payload.product)
            .await
        {
            Ok(_) => {
                tracing::info!(
                    "Removed product {} from category {}",
                    payload.product,
                    payload.category
                );
                return (StatusCode::OK, "Product removed from category successfully")
                    .into_response();
            }
            Err(ProductCategoryServiceError::PermissionDenied) => continue,
            Err(_) => {
                tracing::error!(
                    "Failed to remove product {} from category {}",
                    payload.product,
                    payload.category
                );
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

pub async fn get_products_by_category(Path(category_name): Path<String>) -> impl IntoResponse {
    let service = ProductCategoryService::new();
    let category_repo = CategoryRepo::new();

    let category_id = match category_repo.get_by_name(&category_name).await {
        Ok(Some(category)) => category.category_id,
        Ok(None) => {
            tracing::error!("Category {} not found", category_name);
            return (StatusCode::NOT_FOUND, "Category not found").into_response();
        }
        Err(_) => {
            tracing::error!("Failed to get category {}", category_name);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    match service.get_products_by_category_public(category_id).await {
        Ok(products) => (StatusCode::OK, Json(products)).into_response(),
        Err(_) => {
            tracing::error!("Failed to get products for category {}", category_id);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        }
    }
}
