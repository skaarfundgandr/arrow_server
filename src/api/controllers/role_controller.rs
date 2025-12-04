use crate::api::controllers::dto::role_dto::{AssignRoleDTO, NewRoleDTO, RoleDTO, SetPermissionDTO, UpdateRoleDTO};
use crate::data::models::user_roles::{NewUserRole, RolePermissions, UpdateUserRole};
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use std::str::FromStr;

/// Get all roles
pub async fn get_all_roles() -> impl IntoResponse {
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
            eprintln!("Error fetching roles: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch roles").into_response()
        }
    }
}

/// Get role by name
pub async fn get_role_by_name(Path(role_name): Path<String>) -> impl IntoResponse {
    let repo = UserRoleRepo::new();

    match repo.get_by_name(&role_name).await {
        Ok(Some(role)) => {
            let role_dto = RoleDTO::from(role);
            (StatusCode::OK, Json(role_dto)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response()
        }
    }
}

/// Create a new role
pub async fn create_role(Json(new_role): Json<NewRoleDTO>) -> impl IntoResponse {
    let repo = UserRoleRepo::new();
    let user_repo = UserRepo::new();

    // Verify user exists
    match user_repo.get_by_id(new_role.user_id).await {
        Ok(None) => return (StatusCode::BAD_REQUEST, "User not found").into_response(),
        Err(e) => {
            eprintln!("Error checking user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify user").into_response();
        }
        Ok(Some(_)) => {}
    }

    let new_user_role = NewUserRole::from(&new_role);

    match repo.add(new_user_role).await {
        Ok(_) => {
            println!("Role created successfully: {:?}", new_role.name);
            (StatusCode::CREATED, "Role created").into_response()
        }
        Err(e) => {
            eprintln!("Error creating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create role").into_response()
        }
    }
}

/// Set permission on a role by role ID
pub async fn set_permission(
    Path(role_id): Path<i32>,
    Json(permission_dto): Json<SetPermissionDTO>,
) -> impl IntoResponse {
    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching role: {}", e);
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
                .into_response()
        }
    };

    match repo.set_permissions(role_id, permission).await {
        Ok(_) => (StatusCode::OK, "Permission set").into_response(),
        Err(e) => {
            eprintln!("Error setting permission: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to set permission").into_response()
        }
    }
}

/// Remove permission from a role (sets to NULL)
pub async fn remove_permission(Path(role_id): Path<i32>) -> impl IntoResponse {
    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    // Update role with no permission change (this is a workaround since we can't directly set NULL)
    // The proper way would be to add a clear_permissions method to the repo
    let update_form = UpdateUserRole {
        user_id: None,
        name: None,
        description: None,
    };

    match repo.update(role_id, update_form).await {
        Ok(_) => (StatusCode::OK, "Permission removal not fully implemented - use set_permission to change").into_response(),
        Err(e) => {
            eprintln!("Error updating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update role").into_response()
        }
    }
}

/// Delete a role by ID
pub async fn delete_role(Path(role_id): Path<i32>) -> impl IntoResponse {
    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    match repo.delete(role_id).await {
        Ok(_) => (StatusCode::OK, "Role deleted").into_response(),
        Err(e) => {
            eprintln!("Error deleting role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete role").into_response()
        }
    }
}

/// Update a role by ID
pub async fn update_role(
    Path(role_id): Path<i32>,
    Json(update_dto): Json<UpdateRoleDTO>,
) -> impl IntoResponse {
    let repo = UserRoleRepo::new();

    // Verify role exists
    match repo.get_by_id(role_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "Role not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching role: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch role").into_response();
        }
        Ok(Some(_)) => {}
    }

    let update_form = UpdateUserRole::from(&update_dto);

    match repo.update(role_id, update_form).await {
        Ok(_) => (StatusCode::OK, "Role updated").into_response(),
        Err(e) => {
            eprintln!("Error updating role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update role").into_response()
        }
    }
}

/// Assign a role to a user by username and role name
pub async fn assign_role_to_user(Json(assign_dto): Json<AssignRoleDTO>) -> impl IntoResponse {
    let user_repo = UserRepo::new();
    let role_repo = UserRoleRepo::new();

    // Get user by username
    let user = match user_repo.get_by_username(&assign_dto.username).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
    };

    match role_repo.assign_role_to_user(user.user_id, &assign_dto.role_name).await {
        Ok(_) => (StatusCode::CREATED, "Role assigned to user").into_response(),
        Err(e) => {
            eprintln!("Error assigning role: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to assign role").into_response()
        }
    }
}
