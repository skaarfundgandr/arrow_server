use crate::data::models::categories::{NewCategory, UpdateCategory};
use crate::data::models::product_category::NewProductCategory;
use crate::data::models::user_roles::RolePermissions;
use crate::data::repos::implementors::category_repo::CategoryRepo;
use crate::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::errors::ProductCategoryServiceError;

pub struct ProductCategoryService {}

impl ProductCategoryService {
    pub fn new() -> Self {
        ProductCategoryService {}
    }

    pub async fn add_category(
        &self,
        role_id: i32,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = CategoryRepo::new();

        let new_category = NewCategory { name, description };

        repo.add(new_category)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }

    pub async fn add_product_to_category(
        &self,
        role_id: i32,
        category_id: i32,
        product_id: i32,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = ProductCategoryRepo::new();

        let new_item = NewProductCategory {
            product_id: &product_id,
            category_id: &category_id,
        };

        repo.add(new_item)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }

    pub async fn edit_category(
        &self,
        role_id: i32,
        category_id: i32,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = CategoryRepo::new();

        let updated_category = UpdateCategory { name, description };

        repo.update(category_id, updated_category)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }

    pub async fn delete_category(
        &self,
        role_id: i32,
        category_id: i32,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = CategoryRepo::new();

        repo.delete(category_id)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }
    
    // TODO: Read operations for categories and product-category relationships

    async fn has_permission(
        &self,
        role_id: i32,
        required_permission: RolePermissions,
    ) -> Result<bool, ProductCategoryServiceError> {
        let role_repo = UserRoleRepo::new();
        if let Some(role) = role_repo
            .get_by_id(role_id)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            && let Some(perm) = role.permissions.and_then(|p| p.as_permission())
        {
            return Ok(perm == required_permission);
        }
        Ok(false)
    }
}

impl Default for ProductCategoryService {
    fn default() -> Self {
        Self::new()
    }
}
