use crate::api::extractors::OptionalAccessClaims;
use crate::api::request::{CreateOrderRequest, UpdateOrderStatusRequest};
use crate::api::response::{CreateOrderResponse, OrderResponse, PayOrderResponse};
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::traits::repository::Repository;
use crate::security::jwt::AccessClaims;
use crate::services::errors::OrderServiceError;
use crate::services::order_service::{OrderService, OrderStatus};
use crate::utils::order_url::{self, OrderUrlError};
use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Deserialize;
use std::str::FromStr;

/// Query parameters for public order access via the signed order_url
#[derive(Deserialize)]
pub struct OrderUrlQuery {
    pub exp: Option<u64>,
    pub sig: Option<String>,
}

/// Query parameters for listing orders
#[derive(Deserialize)]
pub struct OrderListQuery {
    pub status: Option<String>,
}

/// Get orders by role (Admin only)
pub async fn get_orders_by_role(
    claims: AccessClaims,
    Path(role_name): Path<String>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    for role_id in roles {
        match service.is_admin(role_id as i32).await {
            Ok(true) => {
                return match service.get_orders_by_role(&role_name, role_id as i32).await {
                    Ok(orders) => {
                        let response: Vec<OrderResponse> = orders
                            .unwrap_or_default()
                            .into_iter()
                            .map(OrderResponse::from)
                            .collect();
                        (StatusCode::OK, Json(response)).into_response()
                    }
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
                };
            }
            Ok(false) => continue,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Admin permission required").into_response()
}

/// Get all orders (Admin only). When `?status=` is present, only orders
/// with that status are returned; unknown/invalid statuses match nothing
/// and yield an empty list.
pub async fn get_all_orders(
    claims: AccessClaims,
    Query(params): Query<OrderListQuery>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    let status_filter: Option<Option<OrderStatus>> =
        params.status.map(|s| OrderStatus::from_str(&s).ok());

    for role_id in roles {
        match service.is_admin(role_id as i32).await {
            Ok(true) => {
                let result = match status_filter {
                    Some(Some(status)) => {
                        service.get_orders_by_status(status, role_id as i32).await
                    }
                    // Invalid status: matches no orders -> empty list
                    Some(None) => Ok(None),
                    None => service.get_all_orders(role_id as i32).await,
                };
                return match result {
                    Ok(orders) => {
                        let response: Vec<OrderResponse> = orders
                            .unwrap_or_default()
                            .into_iter()
                            .map(OrderResponse::from)
                            .collect();
                        (StatusCode::OK, Json(response)).into_response()
                    }
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
                };
            }
            Ok(false) => continue,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Admin permission required").into_response()
}

/// Get order by ID.
/// Access is granted to: ADMIN, the JWT owner of the order, or anyone holding
/// a valid signed order_url (exp + sig query params, no JWT required).
pub async fn get_order_by_id(
    OptionalAccessClaims(claims): OptionalAccessClaims,
    Query(params): Query<OrderUrlQuery>,
    Path(order_id): Path<i32>,
) -> impl IntoResponse {
    let service = OrderService::new();

    let order_data = match service.get_order_by_id_public(order_id).await {
        Ok(Some(data)) => data,
        Ok(None) => return (StatusCode::NOT_FOUND, "Order not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    let is_owner = claims
        .as_ref()
        .map(|c| Some(c.sub as i32) == order_data.0.user_id)
        .unwrap_or(false);

    let mut is_admin = false;
    if let Some(claims) = &claims {
        let roles = claims.roles.clone().unwrap_or_default();
        for role_id in roles {
            match service.is_admin(role_id as i32).await {
                Ok(true) => {
                    is_admin = true;
                    break;
                }
                Ok(false) => continue,
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
                }
            }
        }
    }

    if is_admin || is_owner {
        return (StatusCode::OK, Json(OrderResponse::from(order_data))).into_response();
    }

    // Fall back to the signed order_url
    match (params.exp, params.sig) {
        (Some(exp), Some(sig)) => match order_url::verify_order_url(order_id, exp, &sig) {
            Ok(()) => (StatusCode::OK, Json(OrderResponse::from(order_data))).into_response(),
            Err(OrderUrlError::InvalidSignature) => {
                (StatusCode::BAD_REQUEST, "Invalid order url").into_response()
            }
            Err(OrderUrlError::Expired) => (StatusCode::GONE, "Order url expired").into_response(),
            Err(OrderUrlError::Config) | Err(OrderUrlError::SigningKey) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Order url unavailable").into_response()
            }
        },
        _ => (StatusCode::FORBIDDEN, "Permission denied").into_response(),
    }
}

/// Processes a mock payment for an order.
/// Access is granted to an ADMIN (JWT) or to anyone holding a valid signed
/// order_url (exp + sig query params, no JWT required).
pub async fn pay_order(
    OptionalAccessClaims(claims): OptionalAccessClaims,
    Query(params): Query<OrderUrlQuery>,
    Path(order_id): Path<i32>,
) -> impl IntoResponse {
    let service = OrderService::new();

    let mut is_admin = false;
    if let Some(claims) = &claims {
        let roles = claims.roles.clone().unwrap_or_default();
        for role_id in roles {
            match service.is_admin(role_id as i32).await {
                Ok(true) => {
                    is_admin = true;
                    break;
                }
                Ok(false) => continue,
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
                }
            }
        }
    }

    if !is_admin {
        match (params.exp, params.sig) {
            (Some(exp), Some(sig)) => match order_url::verify_order_url(order_id, exp, &sig) {
                Ok(()) => {}
                Err(OrderUrlError::InvalidSignature) => {
                    return (StatusCode::BAD_REQUEST, "Invalid order url").into_response();
                }
                Err(OrderUrlError::Expired) => {
                    return (StatusCode::GONE, "Order url expired").into_response();
                }
                Err(OrderUrlError::Config) | Err(OrderUrlError::SigningKey) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Order url unavailable")
                        .into_response();
                }
            },
            _ => return (StatusCode::FORBIDDEN, "Permission denied").into_response(),
        }
    }

    match service.pay_order(order_id).await {
        Ok((payment_status, message)) => (
            StatusCode::OK,
            Json(PayOrderResponse {
                order_id,
                payment_status,
                message,
            }),
        )
            .into_response(),
        Err(OrderServiceError::OrderNotFound) => {
            (StatusCode::NOT_FOUND, "Order not found").into_response()
        }
        Err(OrderServiceError::PaymentConflict) => {
            (StatusCode::CONFLICT, "Order already paid").into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    }
}

/// Create a new order (public). Authenticated users get the order attributed
/// to their account; guests create orders with a null user_id.
pub async fn create_order(
    OptionalAccessClaims(claims): OptionalAccessClaims,
    Json(payload): Json<CreateOrderRequest>,
) -> impl IntoResponse {
    let service = OrderService::new();

    let user_id = match &claims {
        Some(claims) => {
            let user_repo = UserRepo::new();
            match user_repo.get_by_id(claims.sub as i32).await {
                Ok(Some(_)) => Some(claims.sub as i32),
                Ok(None) => {
                    return (StatusCode::UNAUTHORIZED, "User no longer exists").into_response();
                }
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
                }
            }
        }
        None => None,
    };

    let items: Vec<(i32, i32)> = payload
        .products
        .into_iter()
        .map(|item| (item.product_id, item.quantity))
        .collect();

    let new_id = match service.create_order(user_id, items).await {
        Ok(id) => id,
        Err(OrderServiceError::InvalidOrderItems) => {
            return (StatusCode::BAD_REQUEST, "Invalid item quantity").into_response();
        }
        Err(OrderServiceError::OrderCreationFailed) => {
            return (
                StatusCode::BAD_REQUEST,
                "Failed to create order (check products)",
            )
                .into_response();
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create order").into_response();
        }
    };

    let order_data = match service.get_order_by_id_public(new_id).await {
        Ok(Some(data)) => data,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch created order",
            )
                .into_response();
        }
    };

    let order_url = match order_url::build_order_url(new_id) {
        Ok(url) => url,
        Err(e) => {
            tracing::error!("Failed to build order url: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build order url",
            )
                .into_response();
        }
    };
    let response = CreateOrderResponse {
        order: OrderResponse::from(order_data),
        order_url,
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

/// Get orders by username (self or Admin only)
pub async fn get_user_orders_by_name(
    claims: AccessClaims,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let service = OrderService::new();
    let user_repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();

    // Lookup User
    let target_user_id = match user_repo.get_by_username(&username).await {
        Ok(Some(user)) => user.user_id,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    let is_self = claims.sub as i32 == target_user_id;

    if is_self {
        return match service.get_own_orders(target_user_id).await {
            Ok(orders) => {
                let response: Vec<OrderResponse> = orders
                    .unwrap_or_default()
                    .into_iter()
                    .map(OrderResponse::from)
                    .collect();
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        };
    }

    let mut is_admin = false;
    for role_id in &roles {
        match service.is_admin(*role_id as i32).await {
            Ok(true) => {
                is_admin = true;
                break;
            }
            Ok(false) => continue,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }
    if !is_admin {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

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

/// Cancels an order (status -> Cancelled).
/// Access is granted to the JWT owner of the order or to an ADMIN.
/// Guest orders (null user_id) can only be cancelled by an ADMIN.
/// Unknown order -> 404; non-owner non-admin -> 403.
pub async fn cancel_order(
    OptionalAccessClaims(claims): OptionalAccessClaims,
    Path(order_id): Path<i32>,
) -> impl IntoResponse {
    let service = OrderService::new();

    let order_data = match service.get_order_by_id_public(order_id).await {
        Ok(Some(data)) => data,
        Ok(None) => return (StatusCode::NOT_FOUND, "Order not found").into_response(),
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    let is_owner = claims
        .as_ref()
        .map(|c| Some(c.sub as i32) == order_data.0.user_id)
        .unwrap_or(false);

    let mut is_admin = false;
    let mut admin_role_id = 0;
    if let Some(claims) = &claims {
        let roles = claims.roles.clone().unwrap_or_default();
        for role_id in roles {
            match service.is_admin(role_id as i32).await {
                Ok(true) => {
                    is_admin = true;
                    admin_role_id = role_id as i32;
                    break;
                }
                Ok(false) => continue,
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
                }
            }
        }
    }

    if is_admin {
        return match service.cancel_order(order_id, admin_role_id).await {
            Ok(_) => (StatusCode::OK, "Order cancelled").into_response(),
            Err(OrderServiceError::OrderNotFound) => {
                (StatusCode::NOT_FOUND, "Order not found").into_response()
            }
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        };
    }

    if is_owner {
        return match service.cancel_order_as_owner(order_id).await {
            Ok(_) => (StatusCode::OK, "Order cancelled").into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
        };
    }

    (StatusCode::FORBIDDEN, "Permission denied").into_response()
}

/// Deletes an order (Admin only). Unknown order -> 404; non-admin -> 403.
pub async fn delete_order(claims: AccessClaims, Path(order_id): Path<i32>) -> impl IntoResponse {
    let service = OrderService::new();
    let roles = claims.roles.unwrap_or_default();

    for role_id in roles {
        match service.is_admin(role_id as i32).await {
            Ok(true) => {
                return match service.delete_order(order_id, role_id as i32).await {
                    Ok(_) => (StatusCode::OK, "Order deleted").into_response(),
                    Err(OrderServiceError::OrderNotFound) => {
                        (StatusCode::NOT_FOUND, "Order not found").into_response()
                    }
                    Err(OrderServiceError::OrderDeletionFailed) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete order")
                            .into_response()
                    }
                    Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
                };
            }
            Ok(false) => continue,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Admin permission required").into_response()
}

/// Updates the status of an order (Admin only)
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
        match service.is_admin(role_id as i32).await {
            Ok(true) => match service
                .update_order_status(order_id, status, role_id as i32)
                .await
            {
                Ok(_) => {
                    return (StatusCode::OK, "Order status updated").into_response();
                }
                Err(OrderServiceError::OrderNotFound) => {
                    return (StatusCode::NOT_FOUND, "Order not found").into_response();
                }
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
                }
            },
            Ok(false) => continue,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
            }
        }
    }

    (StatusCode::FORBIDDEN, "Admin permission required").into_response()
}
