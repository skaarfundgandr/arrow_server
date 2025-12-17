use crate::api::response::{CategoryResponse, ProductResponse};
use crate::data::models::product::{NewProduct, UpdateProduct};
use crate::data::models::user_roles::RolePermissions;
use crate::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use crate::data::repos::implementors::product_repo::ProductRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::errors::ProductServiceError;
use bigdecimal::BigDecimal;

pub struct ProductService;

impl ProductService {
    pub fn new() -> Self {
        ProductService
    }

    /// Gets all products (requires READ permission or Admin)
    pub async fn get_all_products(
        &self,
        role_id: i32,
    ) -> Result<Option<Vec<ProductResponse>>, ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();
        let products = repo
            .get_all()
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?;

        match products {
            Some(prods) => {
                let mut responses = Vec::new();
                for p in prods {
                    let mut response = ProductResponse::from(p);
                    response.categories =
                        self.get_categories_for_product(response.product_id).await?;
                    responses.push(response);
                }
                Ok(Some(responses))
            }
            None => Ok(None),
        }
    }

    /// Gets a product by ID (requires READ permission or Admin)
    pub async fn get_product_by_id(
        &self,
        product_id: i32,
        role_id: i32,
    ) -> Result<Option<ProductResponse>, ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();
        let product = repo
            .get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?;

        match product {
            Some(p) => {
                let mut response = ProductResponse::from(p);
                response.categories = self.get_categories_for_product(response.product_id).await?;
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    /// Gets a product by name (requires READ permission or Admin)
    pub async fn get_product_by_name(
        &self,
        name: &str,
        role_id: i32,
    ) -> Result<Option<ProductResponse>, ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();
        let product = repo
            .get_by_name(name)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?;

        match product {
            Some(p) => {
                let mut response = ProductResponse::from(p);
                response.categories = self.get_categories_for_product(response.product_id).await?;
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    async fn get_categories_for_product(
        &self,
        product_id: i32,
    ) -> Result<Option<Vec<CategoryResponse>>, ProductServiceError> {
        let repo = ProductCategoryRepo::new();
        let categories = repo
            .get_categories_by_product_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?;

        Ok(categories.map(|cats| cats.into_iter().map(CategoryResponse::from).collect()))
    }

    /// Creates a new product (requires WRITE permission or Admin)
    pub async fn create_product(
        &self,
        name: &str,
        description: Option<&str>,
        price: BigDecimal,
        image_uri: Option<&str>,
        role_id: i32,
    ) -> Result<(), ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();

        // Check if product with same name already exists
        if repo
            .get_by_name(name)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .is_some()
        {
            return Err(ProductServiceError::ProductAlreadyExists);
        }

        let new_product = NewProduct {
            name,
            product_image_uri: image_uri,
            description,
            price,
        };

        repo.add(new_product)
            .await
            .map_err(|_| ProductServiceError::ProductCreationFailed)
    }

    /// Updates a product (requires WRITE permission or Admin)
    pub async fn update_product(
        &self,
        product_id: i32,
        name: Option<&str>,
        description: Option<&str>,
        price: Option<BigDecimal>,
        image_uri: Option<&str>,
        role_id: i32,
    ) -> Result<(), ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();

        // Verify product exists
        repo.get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .ok_or(ProductServiceError::ProductNotFound)?;

        let update = UpdateProduct {
            name,
            product_image_uri: image_uri,
            description,
            price,
        };

        repo.update(product_id, update)
            .await
            .map_err(|_| ProductServiceError::ProductUpdateFailed)
    }

    /// Deletes a product (requires DELETE permission or Admin)
    pub async fn delete_product(
        &self,
        product_id: i32,
        role_id: i32,
    ) -> Result<(), ProductServiceError> {
        if !self
            .has_permission(role_id, RolePermissions::Delete)
            .await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();

        // Verify product exists
        repo.get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .ok_or(ProductServiceError::ProductNotFound)?;

        repo.delete(product_id)
            .await
            .map_err(|_| ProductServiceError::ProductDeletionFailed)
    }

    /// Updates product image URI (requires WRITE permission or Admin)
    /// This method is intended for use with Azure Blob Storage integration
    pub async fn update_product_image(
        &self,
        product_id: i32,
        image_uri: &str,
        role_id: i32,
    ) -> Result<(), ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();

        // Verify product exists
        repo.get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .ok_or(ProductServiceError::ProductNotFound)?;

        let update = UpdateProduct {
            name: None,
            product_image_uri: Some(image_uri),
            description: None,
            price: None,
        };

        repo.update(product_id, update)
            .await
            .map_err(|_| ProductServiceError::ProductUpdateFailed)
    }

    async fn has_permission(
        &self,
        role_id: i32,
        required_permission: RolePermissions,
    ) -> Result<bool, ProductServiceError> {
        let role_repo = UserRoleRepo::new();
        if let Some(role) = role_repo
            .get_by_id(role_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            && role.get_all_permissions().contains(&required_permission)
        {
            return Ok(true);
        }
        Ok(false)
    }
}

impl Default for ProductService {
    fn default() -> Self {
        Self::new()
    }
}
