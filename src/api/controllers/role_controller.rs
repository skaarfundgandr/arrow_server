use crate::api::controllers::dto::role_dto::{
    AssignRoleDTO, NewRoleDTO, RoleDTO, SetPermissionDTO, UpdateRoleDTO,
};
use crate::data::models::user_roles::{NewUserRole, RolePermissions, UpdateUserRole};
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use crate::security::jwt::AccessClaims;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::str::FromStr;

// Helper to check admin permission
async fn check_is_admin(role_ids: &[usize]) -> bool {
    let repo = UserRoleRepo::new();
    for &id in role_ids {
        if let Ok(Some(role)) = repo.get_by_id(id as i32).await {
            if let Some(perm) = role.get_permissions() {
                if perm == RolePermissions::Admin {
                    return true;
                }
            }
        }
    }
    false
}

/// Get all roles (Admin only)
pub async fn get_all_roles(claims: AccessClaims) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();

    match repo.get_all().await {
        Ok(Some(roles)) => {
            let role_dtos: Vec<RoleDTO> = roles.into_iter().map(RoleDTO::from).collect();
            (StatusCode::OK, Json(role_dtos)).into_response()
        }
        Ok(None) => {
            let empty: Vec<RoleDTO> = Vec::new();
            (StatusCode::OK, Json(empty)).into_response()
        }
        Err(e) => {
            tracing::error!("Error fetching roles: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch roles").into_response()
        }
    }
}

/// Get role by name (Admin only)
pub async fn get_role_by_name(
    claims: AccessClaims,
    Path(role_name): Path<String>
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();

    match repo.get_by_name(&role_name).await {
        Ok(Some(role)) => {
            let role_dto = RoleDTO::from(role);
            (StatusCode::OK, Json(role_dto)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response()
        }
    }
}

/// Create a new role (Admin only)
pub async fn create_role(
    claims: AccessClaims,
    Json(new_role): Json<NewRoleDTO>
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();
    let user_repo = UserRepo::new();

    // Verify user exists by username
    let user_id = match user_repo.get_by_username(&new_role.username).await {
        Ok(Some(u)) => u.user_id,
        Ok(None) => return (StatusCode::BAD_REQUEST, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error checking user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify user").into_response();
        }
    };

    let new_user_role = NewUserRole {
        user_id,
        name: &new_role.name,
        description: new_role.description.as_deref(),
    };

    match repo.add(new_user_role).await {
        Ok(_) => {
            tracing::info!("Role created successfully: {:?}", new_role.name);
            (StatusCode::CREATED, "Role created").into_response()
        }
        Err(e) => {
            tracing::error!("Error creating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create role").into_response()
        }
    }
}

/// Set permission on a role by role ID (Admin only)
pub async fn set_permission(
    claims: AccessClaims,
    Path(role_id): Path<i32>,
    Json(permission_dto): Json<SetPermissionDTO>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    // Parse permission
    let permission = match RolePermissions::from_str(&permission_dto.permission) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid permission. Valid values: READ, WRITE, DELETE, ADMIN",
            )
                .into_response();
        }
    };

    match repo.set_permissions(role_id, permission).await {
        Ok(_) => (StatusCode::OK, "Permission set").into_response(),
        Err(e) => {
            tracing::error!("Error setting permission: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to set permission",
            )
                .into_response()
        }
    }
}

/// Remove permission from a role (sets to NULL) (Admin only)
pub async fn remove_permission(
    claims: AccessClaims,
    Path(role_id): Path<i32>
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    let update_form = UpdateUserRole {
        user_id: None,
        name: None,
        description: None,
    };

    match repo.update(role_id, update_form).await {
        Ok(_) => (
            StatusCode::OK,
            "Permission removal not fully implemented - use set_permission to change",
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Error updating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update role").into_response()
        }
    }
}

/// Delete a role by ID (Admin only)
pub async fn delete_role(
    claims: AccessClaims,
    Path(role_id): Path<i32>
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    match repo.delete(role_id).await {
        Ok(_) => (StatusCode::OK, "Role deleted").into_response(),
        Err(e) => {
            tracing::error!("Error deleting role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete role").into_response()
        }
    }
}

/// Update a role by ID (Admin only)
pub async fn update_role(
    claims: AccessClaims,
    Path(role_id): Path<i32>,
    Json(update_dto): Json<UpdateRoleDTO>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    let update_form = UpdateUserRole::from(&update_dto);

    match repo.update(role_id, update_form).await {
        Ok(_) => (StatusCode::OK, "Role updated").into_response(),
        Err(e) => {
            tracing::error!("Error updating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update role").into_response()
        }
    }
}

/// Assign a role to a user by username and role name (Admin only)
pub async fn assign_role_to_user(
    claims: AccessClaims,
    Json(assign_dto): Json<AssignRoleDTO>
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let user_repo = UserRepo::new();
    let role_repo = UserRoleRepo::new();

    // Get user by username
    let user = match user_repo.get_by_username(&assign_dto.username).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
    };

    match role_repo
        .assign_role_to_user(user.user_id, &assign_dto.role_name)
        .await
    {
        Ok(_) => (StatusCode::CREATED, "Role assigned to user").into_response(),
        Err(e) => {
            tracing::error!("Error assigning role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to assign role").into_response()
        }
    }
}