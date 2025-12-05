use crate::api::controllers::dto::login_dto::{LoginDTO, LoginResponse};
use crate::api::controllers::dto::role_dto::RoleDTO;
use crate::api::controllers::dto::user_dto::{NewUserDTO, UpdateUserDTO, UserDTO, UserQueryParams};
use crate::data::models::user::{NewUser, UpdateUser, User};
use crate::data::models::user_roles::{NewUserRole, RolePermissions};
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use crate::security::auth::AuthService;
use crate::security::jwt::{AccessClaims, JwtService};
use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;

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

/// Register a new user
/// Logic:
/// - If DB is empty: Allow registration, make user ADMIN.
/// - If DB not empty: Return 403 (Public registration closed).
pub async fn register_user(Json(new_user): Json<NewUserDTO>) -> impl IntoResponse {
    let auth = AuthService::new();
    let user_repo = UserRepo::new();
    let role_repo = UserRoleRepo::new();
    let jwt_service = JwtService::new();

    // 1. Check if first user
    let is_first_user = match user_repo.get_all().await {
        Ok(Some(users)) => users.is_empty(),
        Ok(None) => true,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response(),
    };

    if !is_first_user {
        return (StatusCode::FORBIDDEN, "Public registration is closed.").into_response();
    }

    let hashed_password = match auth.hash_password(&new_user.password).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Error hashing password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to process password",
            )
                .into_response();
        }
    };

    let user_create_dto = NewUserDTO {
        username: new_user.username.clone(),
        password: hashed_password,
    };

    // 2. Create User
    if let Err(e) = user_repo.add(NewUser::from(&user_create_dto)).await {
        tracing::error!("Error creating user: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user").into_response();
    }

    // 3. Fetch created user
    let user = match user_repo.get_by_username(&new_user.username).await {
        Ok(Some(u)) => u,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "User created but not found").into_response(),
    };

    // 4. Assign Admin Role if first user
    if is_first_user {
        let role_name = "ADMIN";
        let new_role = NewUserRole {
            user_id: user.user_id,
            name: role_name,
            description: Some("System Administrator"),
        };
        
        if let Err(e) = role_repo.add(new_role).await {
            tracing::error!("Failed to create admin role: {}", e);
        } else {
            // Set permissions
            if let Ok(Some(role)) = role_repo.get_by_name(role_name).await {
                let _ = role_repo.set_permissions(role.role_id, RolePermissions::Admin).await;
            }
        }
    }

    // 5. Generate Token
    let user_dto = user_to_dto(&user, true).await; // Include ID for own profile
    match jwt_service.generate_token(user_dto).await {
        Ok(token) => {
            let response = LoginResponse {
                token,
                message: "User created and logged in".to_string(),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        },
        Err(e) => {
            tracing::error!("Error generating token: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "User created but token generation failed").into_response()
        }
    }
}

/// Login user
pub async fn login(Json(login_user): Json<LoginDTO>) -> impl IntoResponse {
    let auth = AuthService::new();
    let repo = UserRepo::new();
    let jwt_service = JwtService::new();

    if let Some(user) = match repo.get_by_username(&login_user.username).await {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
    } {
        match auth
            .verify_password(&login_user.password, &user.password_hash)
            .await
        {
            Ok(true) => {
                let user_dto = user_to_dto(&user, true).await; // Include ID for own profile
                match jwt_service.generate_token(user_dto).await {
                    Ok(token) => {
                        let response = LoginResponse {
                            token,
                            message: "Login successful".to_string(),
                        };
                        (StatusCode::OK, Json(response)).into_response()
                    },
                    Err(e) => {
                        tracing::error!("Error generating token: {:?}", e);
                        (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed").into_response()
                    }
                }
            },
            Ok(false) => (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
            Err(e) => {
                tracing::error!("Error verifying password: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to verify password",
                )
                    .into_response()
            }
        }
    } else {
        (StatusCode::NOT_FOUND, "User not found").into_response()
    }
}

/// Converts a User model to UserDTO, fetching associated role if available
async fn user_to_dto(user: &User, include_id: bool) -> UserDTO {
    let role_repo = UserRoleRepo::new();

    let role = match role_repo.get_by_user_id(user.user_id).await {
        Ok(Some(roles)) if !roles.is_empty() => {
            Some(RoleDTO::from(roles.into_iter().next().unwrap()))
        }
        _ => None,
    };

    UserDTO {
        user_id: if include_id { Some(user.user_id) } else { None },
        username: user.username.clone(),
        role,
        created_at: user.created_at.map(|dt| dt.format("%d/%m/%Y").to_string()),
        updated_at: user.updated_at.map(|dt| dt.format("%d/%m/%Y").to_string()),
    }
}

/// Get all users
pub async fn get_all_users(claims: AccessClaims) -> impl IntoResponse {
    let repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();
    let is_admin = check_is_admin(&roles).await;

    match repo.get_all().await {
        Ok(Some(users)) => {
            let mut user_dtos = Vec::new();
            for user in &users {
                user_dtos.push(user_to_dto(user, is_admin).await);
            }
            (StatusCode::OK, Json(user_dtos)).into_response()
        }
        Ok(None) => {
            let empty: Vec<UserDTO> = Vec::new();
            (StatusCode::OK, Json(empty)).into_response()
        }
        Err(e) => {
            tracing::error!("Error fetching users: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch users").into_response()
        }
    }
}

/// Get user by ID
pub async fn get_user(
    claims: AccessClaims,
    Path(user_id): Path<i32>
) -> impl IntoResponse {
    let repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();
    let is_admin = check_is_admin(&roles).await;

    match repo.get_by_id(user_id).await {
        Ok(Some(user)) => {
            let user_dto = user_to_dto(&user, is_admin).await;
            (StatusCode::OK, Json(user_dto)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response()
        }
    }
}

/// Get user by name using query params
pub async fn get_user_by_name(
    claims: AccessClaims,
    Query(params): Query<UserQueryParams>
) -> impl IntoResponse {
    let repo = UserRepo::new();
    let roles = claims.roles.unwrap_or_default();
    let is_admin = check_is_admin(&roles).await;

    let username = match params.username {
        Some(name) => name,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Username query parameter is required",
            )
                .into_response();
        }
    };

    match repo.get_by_username(&username).await {
        Ok(Some(user)) => {
            let user_dto = user_to_dto(&user, is_admin).await;
            (StatusCode::OK, Json(user_dto)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response()
        }
    }
}

// Admin only route
/// Update user by ID
pub async fn edit_user(
    claims: AccessClaims,
    Path(user_id): Path<i32>,
    Json(update_dto): Json<UpdateUserDTO>,
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRepo::new();
    let auth = AuthService::new();

    // Check if user exists
    match repo.get_by_id(user_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
        Ok(Some(_)) => {}
    }

    // Hash password if provided
    let hashed_password = if let Some(ref password) = update_dto.password {
        match auth.hash_password(password).await {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::error!("Error hashing password: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to process password",
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let update_form = UpdateUser {
        username: update_dto.username.as_deref(),
        password_hash: hashed_password.as_deref(),
    };

    match repo.update(user_id, update_form).await {
        Ok(_) => (StatusCode::OK, "User updated").into_response(),
        Err(e) => {
            tracing::error!("Error updating user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update user").into_response()
        }
    }
}

// Admin only route
/// Delete user by ID
pub async fn delete_user(
    claims: AccessClaims,
    Path(user_id): Path<i32>
) -> impl IntoResponse {
    let roles = claims.roles.unwrap_or_default();
    if !check_is_admin(&roles).await {
        return (StatusCode::FORBIDDEN, "Admin permission required").into_response();
    }

    let repo = UserRepo::new();

    // Check if user exists
    match repo.get_by_id(user_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            tracing::error!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
        Ok(Some(_)) => {}
    }

    match repo.delete(user_id).await {
        Ok(_) => (StatusCode::OK, "User deleted").into_response(),
        Err(e) => {
            tracing::error!("Error deleting user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete user").into_response()
        }
    }
}