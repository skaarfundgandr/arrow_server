use crate::api::controllers::dto::role_dto::{
    AssignRoleDTO, NewRoleDTO, RoleDTO, SetPermissionDTO, UpdateRoleDTO,
};
use crate::api::request::AddPermissionRequest;
use crate::data::models::roles::{NewRole, RolePermissions, UpdateRole};
use crate::data::repos::implementors::role_repo::RoleRepo;
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::traits::repository::Repository;
use crate::security::jwt::AccessClaims;
use crate::services::role_service::RoleService;
use axum::Json;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::str::FromStr;

// Helper to check admin permission
async fn check_is_admin(role_ids: &[usize]) -> bool {
    let repo = RoleRepo::new();
    for &id in role_ids {
        if let Ok(Some(role)) = repo.get_by_id(id as i32).await
            && role.has_permission(RolePermissions::Admin)
        {
            return true;
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

    let repo = RoleRepo::new();

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
    Path(role_name): Path<String>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = RoleRepo::new();

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
    Json(new_role): Json<NewRoleDTO>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = RoleRepo::new();

    // Note: 'username' in NewRoleDTO is ignored as roles are now global definitions, not per-user.
    // Assignments happen via assign_role_to_user endpoint.
    let role_to_create = NewRole {
        name: &new_role.name,
        description: new_role.description.as_deref(),
    };

    match repo.add(role_to_create).await {
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

    let repo = RoleRepo::new();

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

/// Set permission on a role by role name (Admin only)
pub async fn set_permission_by_name(
    claims: AccessClaims,
    Path(role_name): Path<String>,
    Json(permission_dto): Json<SetPermissionDTO>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let service = RoleService::new();
    
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

    match service.set_permission_to_role(&role_name, permission).await {
        Ok(_) => (StatusCode::OK, "Permission set").into_response(),
        Err(e) => {
            tracing::error!("Error setting permission: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to set permission",
            )
                .into_response()
        }
    }
}

/// Add permission to a role (Admin only)
pub async fn add_permission(
    claims: AccessClaims,
    Json(request): Json<AddPermissionRequest>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let permission = match RolePermissions::from_str(&request.permission) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid permission. Valid values: READ, WRITE, DELETE, ADMIN",
            )
                .into_response();
        }
    };

    let service = RoleService::new();
    match service
        .add_permission_to_role(&request.role_name, permission)
        .await
    {
        Ok(_) => (StatusCode::OK, "Permission added").into_response(),
        Err(e) => {
            tracing::error!("Error adding permission: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to add permission",
            )
                .into_response()
        }
    }
}

/// Remove permission from a role (sets to NULL or default) (Admin only)
pub async fn remove_permission(
    claims: AccessClaims,
    Path(role_id): Path<i32>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = RoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    // Since we don't have a clear way to remove a single permission from the SET string easily in SQL without complex logic,
    // and the old implementation was "sets to NULL", we will just update permissions to NULL.
    // But the `update` method on repo takes `UpdateRole`, which doesn't expose permissions (excluded from diesel macro).
    // We should use set_permissions with some 'Empty' or just raw SQL.
    // For now, let's just use `set_permissions` to READ (default).
    
    match repo.set_permissions(role_id, RolePermissions::Read).await {
        Ok(_) => (
            StatusCode::OK,
            "Permissions reset to READ (Default)",
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Error updating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update role").into_response()
        }
    }
}

/// Delete a role by ID (Admin only)
pub async fn delete_role(claims: AccessClaims, Path(role_id): Path<i32>) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = RoleRepo::new();

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

    let repo = RoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    let update_form = UpdateRole::from(&update_dto);

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
    Json(assign_dto): Json<AssignRoleDTO>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let user_repo = UserRepo::new();
    let service = RoleService::new();

    // Get user by username
    let user = match user_repo.get_by_username(&assign_dto.username).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
    };

    match service
        .assign_role_to_user(user.user_id, &assign_dto.role_name)
        .await
    {
        Ok(_) => (StatusCode::CREATED, "Role assigned to user").into_response(),
        Err(e) => {
            tracing::error!("Error assigning role: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to assign role").into_response()
        }
    }
}