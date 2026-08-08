use crate::api::config::Config;
use crate::data::models::roles::{NewRole, Role, RolePermissions};
use crate::data::models::user::NewUser;
use crate::data::repos::implementors::role_repo::RoleRepo;
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use crate::security::auth::AuthService;
use crate::services::errors::UserServiceError;

pub struct UserService;

impl UserService {
    pub fn new() -> Self {
        UserService
    }

    /// Idempotently creates the admin user configured via ADMIN_USERNAME/ADMIN_PASSWORD
    /// and assigns it the ADMIN role (creating the role if missing).
    pub async fn seed_admin_from_env(&self) -> Result<(), UserServiceError> {
        let config = Config::get().map_err(|_| UserServiceError::ConfigError)?;
        let user_repo = UserRepo::new();

        if user_repo
            .get_by_username(&config.admin_username)
            .await
            .map_err(|_| UserServiceError::DatabaseError)?
            .is_some()
        {
            return Ok(());
        }

        let auth = AuthService::new();
        let hashed = auth
            .hash_password(&config.admin_password)
            .await
            .map_err(|_| UserServiceError::HashingError)?;

        let new_user = NewUser {
            username: &config.admin_username,
            password_hash: &hashed,
        };
        if user_repo.add(new_user).await.is_err() {
            // Concurrent seed: another instance may have created the user
            // between our existence check and this insert.
            let existing = user_repo
                .get_by_username(&config.admin_username)
                .await
                .map_err(|_| UserServiceError::DatabaseError)?;
            if existing.is_none() {
                return Err(UserServiceError::UserCreationFailed);
            }
        }

        let user = user_repo
            .get_by_username(&config.admin_username)
            .await
            .map_err(|_| UserServiceError::DatabaseError)?
            .ok_or(UserServiceError::UserNotFound)?;

        let role = self.ensure_role("ADMIN", RolePermissions::Admin).await?;

        if let Err(_e) = UserRoleRepo::new()
            .add_user_role(user.user_id, role.role_id)
            .await
        {
            // The role may already be assigned by a concurrent seed.
            let assigned = UserRoleRepo::new()
                .get_roles_by_user_id(user.user_id)
                .await
                .map_err(|_| UserServiceError::DatabaseError)?;
            if assigned.iter().any(|r| r.role_id == role.role_id) {
                tracing::info!("Admin user '{}' already seeded", config.admin_username);
                return Ok(());
            }
            return Err(UserServiceError::RoleAssignmentFailed);
        }

        tracing::info!("Admin user '{}' seeded", config.admin_username);
        Ok(())
    }

    /// Returns the role with the given name, creating it (and overwriting its
    /// permission set) when it does not exist yet.
    /// Note: set_permissions OVERWRITES the whole permission set, so ADMIN is
    /// seeded with the full permission set (READ, WRITE, DELETE, ADMIN).
    pub async fn ensure_role(
        &self,
        name: &str,
        permission: RolePermissions,
    ) -> Result<Role, UserServiceError> {
        let role_repo = RoleRepo::new();

        if let Some(role) = role_repo
            .get_by_name(name)
            .await
            .map_err(|_| UserServiceError::DatabaseError)?
        {
            return Ok(role);
        }

        let new_role = NewRole {
            name,
            description: None,
        };
        role_repo
            .add(new_role)
            .await
            .map_err(|_| UserServiceError::RoleCreationFailed)?;

        let role = role_repo
            .get_by_name(name)
            .await
            .map_err(|_| UserServiceError::DatabaseError)?
            .ok_or(UserServiceError::RoleCreationFailed)?;

        role_repo
            .set_permissions(role.role_id, permission)
            .await
            .map_err(|_| UserServiceError::RoleCreationFailed)?;

        if permission == RolePermissions::Admin {
            for perm in [
                RolePermissions::Read,
                RolePermissions::Write,
                RolePermissions::Delete,
            ] {
                role_repo
                    .add_permission(role.role_id, perm)
                    .await
                    .map_err(|_| UserServiceError::RoleCreationFailed)?;
            }
        }

        Ok(role)
    }
}

impl Default for UserService {
    fn default() -> Self {
        Self::new()
    }
}
