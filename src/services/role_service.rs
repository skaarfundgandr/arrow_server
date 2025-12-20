use crate::data::models::roles::*;
use crate::data::repos::traits::repository::Repository;
use crate::services::errors::RoleError;

// ROLE MANAGEMENT LOGIC GOES HERE
// Possible permissions: Read, Write, Delete, Admin
// Admin could add other roles and assign permissions
// Write could only modify and add content within their own tables
// Read could only view content
// Delete could remove content but not modify structure
// Each role should have specific permissions associated with it
// Users can not be assigned multiple roles
pub struct RoleService {}

impl RoleService {
    pub fn new() -> Self {
        RoleService {}
    }

    pub async fn check_permission(
        &self,
        role_id: i32,
        required_permission: RolePermissions,
    ) -> Result<bool, RoleError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;

        let repo = RoleRepo::new();
        if let Some(role) = repo
            .get_by_id(role_id)
            .await
            .map_err(|_| RoleError::RoleNotFound)?
        {
            return if let Some(perm_str) = { role.permissions.and_then(|p| p.as_permission()) } {
                Ok(perm_str == required_permission)
            } else {
                Err(RoleError::PermissionDenied)
            };
        }
        Ok(false)
    }

    pub async fn assign_role_to_user(
        &self,
        user_id: i32,
        role_name: &str,
    ) -> Result<(), RoleError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;
        use crate::data::repos::implementors::user_role_repo::UserRoleRepo;

        let role_repo = RoleRepo::new();
        let user_role_repo = UserRoleRepo::new();
        
        let role = role_repo
            .get_by_name(role_name)
            .await
            .map_err(|_| RoleError::RoleNotFound)?;

        if let Some(role) = role {
            user_role_repo.add_user_role(user_id, role.role_id)
                .await
                .map_err(|_| RoleError::RoleAssignmentFailed)?;
            Ok(())
        } else {
            Err(RoleError::RoleNotFound)
        }
    }

    pub async fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
        permissions: RolePermissions,
    ) -> Result<(), RoleError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;

        let repo = RoleRepo::new();
        let new_role = NewRole {
            name,
            description,
        };
        repo.add(new_role)
            .await
            .map_err(|_| RoleError::RoleCreationFailed)?;
        let new_role = match repo
            .get_by_name(name)
            .await
            .map_err(|_| RoleError::RoleNotFound)?
        {
            Some(r) => r,
            None => return Err(RoleError::RoleNotFound),
        };

        repo.set_permissions(new_role.role_id, permissions)
            .await
            .map_err(|_| RoleError::PermissionAssignmentFailed)?;
        Ok(())
    }

    pub async fn set_permission_to_role(
        &self,
        role_name: &str,
        permission: RolePermissions,
    ) -> Result<(), RoleError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;

        let repo = RoleRepo::new();

        let role = match repo
            .get_by_name(role_name)
            .await
            .map_err(|_| RoleError::RoleNotFound)?
        {
            Some(r) => r,
            None => return Err(RoleError::RoleNotFound),
        };

        repo.set_permissions(role.role_id, permission)
            .await
            .map_err(|_| RoleError::PermissionAssignmentFailed)?;
        Ok(())
    }
    pub async fn add_permission_to_role(
        &self,
        role_name: &str,
        permission: RolePermissions,
    ) -> Result<(), RoleError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;

        let repo = RoleRepo::new();
        let role = match repo
            .get_by_name(role_name)
            .await
            .map_err(|_| RoleError::RoleNotFound)?
        {
            Some(r) => r,
            None => return Err(RoleError::RoleNotFound),
        };

        repo.add_permission(role.role_id, permission)
            .await
            .map_err(|_| RoleError::PermissionAssignmentFailed)?;
        Ok(())
    }
}

impl Default for RoleService {
    fn default() -> Self {
        Self::new()
    }
}
