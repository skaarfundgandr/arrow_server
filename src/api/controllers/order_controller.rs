use crate::api::request::{CreateOrderRequest, UpdateOrderStatusRequest};
use crate::api::response::OrderResponse;
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::traits::repository::Repository;
use crate::security::jwt::AccessClaims;
use crate::services::errors::OrderServiceError;
use crate::services::order_service::{OrderService, OrderStatus};
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::str::FromStr;

/// Get orders by role
pub async fn get_orders_by_role(
    claims: AccessClaims,
    Path(role_name): Path<String>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_orders_by_role(&role_name, role_id as i32).await {
            Ok(orders) => {
                let response: Vec<OrderResponse> = orders
                    .unwrap_or_default()
                    .into_iter()
                    .map(OrderResponse::from)
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Get all orders
pub async fn get_all_orders(claims: AccessClaims) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_all_orders(role_id as i32).await {
            Ok(orders) => {
                let response: Vec<OrderResponse> = orders
                    .unwrap_or_default()
                    .into_iter()
                    .map(OrderResponse::from)
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Get order by ID
pub async fn get_order_by_id(claims: AccessClaims, Path(order_id): Path<i32>) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    for role_id in roles {
        match service.get_order_by_id(order_id, role_id as i32).await {
            Ok(Some(order_data)) => {
                return (StatusCode::OK, Json(OrderResponse::from(order_data))).into_response();
            }
            Ok(None) => return (StatusCode::NOT_FOUND, "Order not found").into_response(),
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Create a new order
pub async fn create_order(
    claims: AccessClaims,
    Json(payload): Json<CreateOrderRequest>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let user_repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    let user_id = match user_repo.get_by_id(claims.sub as i32).await {
        Ok(Some(user)) => user.user_id,
        Ok(None) => return (StatusCode::BAD_REQUEST, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    let valid_role_id = roles.into_iter().next();

    let role_id = match valid_role_id {
        Some(id) => id as i32,
        None => return (StatusCode::FORBIDDEN, "Permission denied").into_response(),
    };

    let items: Vec<(i32, i32)> = payload.products.into_iter()
        .map(|item| (item.product_id, item.quantity))
        .collect();

    match service
        .create_order(user_id, role_id, items)
        .await
    {
        Ok(_) => (StatusCode::CREATED, "Order created").into_response(),
        Err(OrderServiceError::PermissionDenied) => {
            (StatusCode::FORBIDDEN, "Permission denied").into_response()
        }
        Err(OrderServiceError::OrderCreationFailed) => {
             (StatusCode::BAD_REQUEST, "Failed to create order (check products)").into_response()
        }
        Err(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create order").into_response()
        }
    }
}

/// Get orders by username
pub async fn get_user_orders_by_name(
    claims: AccessClaims,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let user_repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    // Lookup User
    let target_user_id = match user_repo.get_by_username(&username).await {
        Ok(Some(user)) => user.user_id,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    for role_id in roles {
        match service
            .get_user_orders(target_user_id, role_id as i32)
            .await
        {
            Ok(orders) => {
                let response: Vec<OrderResponse> = orders
                    .unwrap_or_default()
                    .into_iter()
                    .map(OrderResponse::from)
                    .collect();
                return (StatusCode::OK, Json(response)).into_response();
            }
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Updates the status of an order
/// # Arguments
/// * `claims` - AccessClaims extracted from JWT
/// * `order_id` - ID of the order to update taken from the URL path
/// * `payload` - UpdateOrderStatusRequest containing the new status
/// # Returns
/// * `impl IntoResponse` - HTTP response indicating success or failure
pub async fn update_order_status(
    claims: AccessClaims,
    Path(order_id): Path<i32>,
    Json(payload): Json<UpdateOrderStatusRequest>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    if roles.is_empty() {
        return (StatusCode::FORBIDDEN, "Permission denied").into_response();
    }

    let status = match payload.status {
        Some(s) => {
            if OrderStatus::from_str(&s).is_err() {
                return (StatusCode::BAD_REQUEST, "Invalid status value").into_response();
            }
            match OrderStatus::from_str(&s) {
                Ok(val) => val,
                Err(_) => return (StatusCode::BAD_REQUEST, "Invalid status value").into_response(),
            }
        }
        None => return (StatusCode::BAD_REQUEST, "Status is required").into_response(),
    };

    for role_id in roles {
        match service
            .update_order_status(order_id, status, role_id as i32)
            .await
        {
            Ok(_) => {
                return (StatusCode::OK, "Order status updated").into_response();
            }
            Err(OrderServiceError::PermissionDenied) => continue,
            Err(OrderServiceError::OrderNotFound) => {
                return (StatusCode::NOT_FOUND, "Order not found").into_response();
            }
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        }
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}