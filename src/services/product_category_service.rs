use crate::api::request::{AssignCategoryRequest, CreateCategoryRequest, UpdateCategoryRequest};
use crate::api::response::{CategoryResponse, ProductResponse};
use crate::data::models::categories::{NewCategory, UpdateCategory};
use crate::data::models::product_category::NewProductCategory;
use crate::data::models::roles::RolePermissions;
use crate::data::repos::implementors::category_repo::CategoryRepo;
use crate::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use crate::data::repos::implementors::product_repo::ProductRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::errors::ProductCategoryServiceError;
use diesel::result::{DatabaseErrorKind, Error};

pub struct ProductCategoryService {}

impl ProductCategoryService {
    pub fn new() -> Self {
        ProductCategoryService {}
    }

    pub async fn get_categories(
        &self,
        role_id: i32,
    ) -> Result<Option<Vec<CategoryResponse>>, ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let is_admin = self.has_permission(role_id, RolePermissions::Admin).await?;

        let repo = CategoryRepo::new();

        let categories = repo
            .get_all()
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?;

        let mut res = categories.map(|cats| cats.into_iter().map(|c| c.into()).collect());

        if is_admin {
            Ok(res)
        } else {
            if let Some(categories) = res.as_mut() {
                categories.iter_mut().for_each(|cat| {
                    cat.category_id = None;
                    cat.created_at = None;
                    cat.updated_at = None;
                });
            } else {
                return Ok(Some(vec![]));
            }

            Ok(res)
        }
    }

    pub async fn add_category(
        &self,
        role_id: i32,
        request: CreateCategoryRequest,
    ) -> Result<i32, ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = CategoryRepo::new();

        let new_category = NewCategory::from(&request);

        repo.add(new_category)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?;

        repo.get_by_name(&request.name)
            .await
            .map(|c| match c {
                Some(c) => c.category_id,
                None => -1,
            })
            .and_then(|v| {
                if v == -1 {
                    Err(Error::DatabaseError(
                        DatabaseErrorKind::UnableToSendCommand,
                        Box::new(v.to_string()),
                    ))
                } else {
                    Ok(v)
                }
            })
            .map_err(|_| ProductCategoryServiceError::CategoryNotFound)
    }

    pub async fn add_product_to_category(
        &self,
        role_id: i32,
        request: AssignCategoryRequest,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let product_repo = ProductRepo::new();
        let category_repo = CategoryRepo::new();
        let product_category_repo = ProductCategoryRepo::new();

        let product = product_repo
            .get_by_name(&request.product)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            .ok_or(ProductCategoryServiceError::ProductNotFound)?;

        let category = category_repo
            .get_by_name(&request.category)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            .ok_or(ProductCategoryServiceError::CategoryNotFound)?;

        let new_product_category = NewProductCategory {
            product_id: &product.product_id,
            category_id: &category.category_id,
        };

        product_category_repo
            .add(new_product_category)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }

    pub async fn add_product_to_categories(
        &self,
        role_id: i32,
        product_name: &str,
        category_names: Vec<String>,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let product_repo = ProductRepo::new();
        let category_repo = CategoryRepo::new();
        let product_category_repo = ProductCategoryRepo::new();

        let product = product_repo
            .get_by_name(product_name)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            .ok_or(ProductCategoryServiceError::ProductNotFound)?;

        for category_name in category_names {
            let category = category_repo
                .get_by_name(&category_name)
                .await
                .map_err(|_| ProductCategoryServiceError::DatabaseError)?
                .ok_or(ProductCategoryServiceError::CategoryNotFound)?;

            let new_product_category = NewProductCategory {
                product_id: &product.product_id,
                category_id: &category.category_id,
            };

            product_category_repo
                .add(new_product_category)
                .await
                .map_err(|_| ProductCategoryServiceError::DatabaseError)?;
        }
        Ok(())
    }

    pub async fn remove_product_from_categories(
        &self,
        role_id: i32,
        product_name: &str,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let product_repo = ProductRepo::new();
        let product_category_repo = ProductCategoryRepo::new();

        let product = product_repo
            .get_by_name(product_name)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            .ok_or(ProductCategoryServiceError::ProductNotFound)?;

        product_category_repo
            .delete_by_product_id(product.product_id)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }

    pub async fn update_product_categories(
        &self,
        role_id: i32,
        product_name: &str,
        category_names: Vec<String>,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        self.remove_product_from_categories(role_id, product_name)
            .await?;

        self.add_product_to_categories(role_id, product_name, category_names)
            .await
    }

    pub async fn edit_category(
        &self,
        role_id: i32,
        category_id: i32,
        request: UpdateCategoryRequest,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = CategoryRepo::new();

        let updated_category = UpdateCategory::from(&request);

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

    pub async fn get_products_by_category(
        &self,
        role_id: i32,
        category_id: i32,
    ) -> Result<Option<Vec<ProductResponse>>, ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let repo = ProductCategoryRepo::new();

        let products = repo
            .get_products_by_category_id(category_id)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?;

        Ok(products.map(|prods| prods.into_iter().map(|p| p.into()).collect()))
    }

    pub async fn remove_product_from_category(
        &self,
        role_id: i32,
        category_name: &str,
        product_name: &str,
    ) -> Result<(), ProductCategoryServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            Err(ProductCategoryServiceError::PermissionDenied)?
        }

        let product_repo = ProductRepo::new();
        let category_repo = CategoryRepo::new();
        let product_category_repo = ProductCategoryRepo::new();

        let product = product_repo
            .get_by_name(product_name)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            .ok_or(ProductCategoryServiceError::ProductNotFound)?;

        let category = category_repo
            .get_by_name(category_name)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
            .ok_or(ProductCategoryServiceError::CategoryNotFound)?;

        product_category_repo
            .delete((product.product_id, category.category_id))
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)
    }

    async fn has_permission(
        &self,
        role_id: i32,
        required_permission: RolePermissions,
    ) -> Result<bool, ProductCategoryServiceError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;
        let role_repo = RoleRepo::new();
        if let Some(role) = role_repo
            .get_by_id(role_id)
            .await
            .map_err(|_| ProductCategoryServiceError::DatabaseError)?
        {
            return Ok(role.has_permission(required_permission));
        }
        Ok(false)
    }
}

impl Default for ProductCategoryService {
    fn default() -> Self {
        Self::new()
    }
}
