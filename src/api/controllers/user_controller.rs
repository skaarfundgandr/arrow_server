use crate::api::controllers::dto::login_dto::LoginDTO;
use crate::api::controllers::dto::role_dto::RoleDTO;
use crate::api::controllers::dto::user_dto::{NewUserDTO, UpdateUserDTO, UserDTO, UserQueryParams};
use crate::data::models::user::{NewUser, UpdateUser, User};
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::auth_service::AuthService;
use axum::extract::{Path, Query};
use axum::Json;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

// TODO: REFACTOR: Create controller trait to reduce code duplication
pub async fn register_user(Json(new_user): Json<NewUserDTO>) -> impl IntoResponse {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed_password = match auth.hash_password(&new_user.password).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to process password",
            )
                .into_response();
        }
    };

    let new_user = NewUserDTO {
        username: new_user.username,
        password: hashed_password,
    };

    match repo.add(NewUser::from(&new_user)).await {
        Ok(_) => {
            println!("User created successfully! {:?}", new_user.username);
            Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::from("User created"))
                .unwrap()
        }
        Err(e) => {
            eprintln!("Error creating user: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to create user"))
                .unwrap()
        }
    }
}

pub async fn login(Json(login_user): Json<LoginDTO>) -> impl IntoResponse {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    if let Some(user) = match repo.get_by_username(&login_user.username).await {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
    } {
        match auth
            .verify_password(&login_user.password, &user.password_hash)
            .await
        {
            Ok(true) => (StatusCode::OK, "Login successful").into_response(),
            Ok(false) => (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
            Err(e) => {
                eprintln!("Error verifying password: {}", e);
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

// TODO(optional): Implement JWT authentication for protected routes
// TODO(optional): Add rate limiting and input validation

/// Converts a User model to UserDTO, fetching associated role if available
async fn user_to_dto(user: &User) -> UserDTO {
    let role_repo = UserRoleRepo::new();
    
    let role = match role_repo.get_by_user_id(user.user_id).await {
        Ok(Some(roles)) if !roles.is_empty() => Some(RoleDTO::from(roles.into_iter().next().unwrap())),
        _ => None,
    };

    UserDTO {
        username: user.username.clone(),
        role,
        created_at: user.created_at.map(|dt| dt.format("%d/%m/%Y").to_string()),
        updated_at: user.updated_at.map(|dt| dt.format("%d/%m/%Y").to_string()),
    }
}

/// Get all users
pub async fn get_all_users() -> impl IntoResponse {
    let repo = UserRepo::new();

    match repo.get_all().await {
        Ok(Some(users)) => {
            let mut user_dtos = Vec::new();
            for user in &users {
                user_dtos.push(user_to_dto(user).await);
            }
            (StatusCode::OK, Json(user_dtos)).into_response()
        }
        Ok(None) => {
            let empty: Vec<UserDTO> = Vec::new();
            (StatusCode::OK, Json(empty)).into_response()
        }
        Err(e) => {
            eprintln!("Error fetching users: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch users").into_response()
        }
    }
}

/// Get user by ID
pub async fn get_user(Path(user_id): Path<i32>) -> impl IntoResponse {
    let repo = UserRepo::new();

    match repo.get_by_id(user_id).await {
        Ok(Some(user)) => {
            let user_dto = user_to_dto(&user).await;
            (StatusCode::OK, Json(user_dto)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response()
        }
    }
}

/// Get user by name using query params
pub async fn get_user_by_name(Query(params): Query<UserQueryParams>) -> impl IntoResponse {
    let repo = UserRepo::new();

    let username = match params.username {
        Some(name) => name,
        None => return (StatusCode::BAD_REQUEST, "Username query parameter is required").into_response(),
    };

    match repo.get_by_username(&username).await {
        Ok(Some(user)) => {
            let user_dto = user_to_dto(&user).await;
            (StatusCode::OK, Json(user_dto)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response()
        }
    }
}

/// Update user by ID
pub async fn edit_user(
    Path(user_id): Path<i32>,
    Json(update_dto): Json<UpdateUserDTO>,
) -> impl IntoResponse {
    let repo = UserRepo::new();
    let auth = AuthService::new();

    // Check if user exists
    match repo.get_by_id(user_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
        Ok(Some(_)) => {}
    }

    // Hash password if provided
    let hashed_password = if let Some(ref password) = update_dto.password {
        match auth.hash_password(password).await {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!("Error hashing password: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to process password").into_response();
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
            eprintln!("Error updating user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to update user").into_response()
        }
    }
}

/// Delete user by ID
pub async fn delete_user(Path(user_id): Path<i32>) -> impl IntoResponse {
    let repo = UserRepo::new();

    // Check if user exists
    match repo.get_by_id(user_id).await {
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found").into_response(),
        Err(e) => {
            eprintln!("Error fetching user: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch user").into_response();
        }
        Ok(Some(_)) => {}
    }

    match repo.delete(user_id).await {
        Ok(_) => (StatusCode::OK, "User deleted").into_response(),
        Err(e) => {
            eprintln!("Error deleting user: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete user").into_response()
        }
    }
}
