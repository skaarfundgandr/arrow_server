use crate::api::config::Config;
use crate::api::response::{CategoryResponse, ProductResponse};
use crate::data::models::product::{NewProduct, UpdateProduct};
use crate::data::models::roles::RolePermissions;
use crate::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use crate::data::repos::implementors::product_repo::ProductRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::blob_storage_service::{
    AzureBlobStore, BlobStore, BlobStoreError, is_blob_path,
};
use crate::services::errors::ProductServiceError;
use bigdecimal::BigDecimal;
use once_cell::sync::Lazy;
use std::sync::Arc;

static PRODUCTION_BLOB_STORE: Lazy<Arc<dyn BlobStore>> = Lazy::new(|| {
    Arc::new(AzureBlobStore::try_new().unwrap_or_else(|error| {
        tracing::error!("Failed to initialize Azure Blob Storage: {}", error);
        AzureBlobStore::disabled()
    }))
});

struct ImageType {
    mime: &'static str,
}

fn detect_image_type(bytes: &[u8]) -> Option<ImageType> {
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(ImageType { mime: "image/jpeg" })
    } else if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        Some(ImageType { mime: "image/png" })
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some(ImageType { mime: "image/webp" })
    } else {
        None
    }
}

fn is_whitelisted_mime(mime: &str) -> bool {
    matches!(mime, "image/jpeg" | "image/png" | "image/webp")
}

pub struct ProductService {
    blob_store: Arc<dyn BlobStore>,
}

impl ProductService {
    pub fn new() -> Self {
        Self::with_blob_store(PRODUCTION_BLOB_STORE.clone())
    }

    pub fn with_blob_store(blob_store: Arc<dyn BlobStore>) -> Self {
        ProductService { blob_store }
    }

    /// Gets all products without any permission check (public endpoint)
    pub async fn get_all_products_public(
        &self,
    ) -> Result<Option<Vec<ProductResponse>>, ProductServiceError> {
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
                    response.product_image_uri =
                        self.resolve_product_image(response.product_image_uri).await;
                    responses.push(response);
                }
                Ok(Some(responses))
            }
            None => Ok(None),
        }
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
                    response.product_image_uri =
                        self.resolve_product_image(response.product_image_uri).await;
                    responses.push(response);
                }
                Ok(Some(responses))
            }
            None => Ok(None),
        }
    }

    /// Gets a product by ID without any permission check (public endpoint)
    pub async fn get_product_by_id_public(
        &self,
        product_id: i32,
    ) -> Result<Option<ProductResponse>, ProductServiceError> {
        let repo = ProductRepo::new();
        let product = repo
            .get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?;

        match product {
            Some(p) => {
                let mut response = ProductResponse::from(p);
                response.categories = self.get_categories_for_product(response.product_id).await?;
                response.product_image_uri =
                    self.resolve_product_image(response.product_image_uri).await;
                Ok(Some(response))
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
                response.product_image_uri =
                    self.resolve_product_image(response.product_image_uri).await;
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
                response.product_image_uri =
                    self.resolve_product_image(response.product_image_uri).await;
                Ok(Some(response))
            }
            None => Ok(None),
        }
    }

    async fn resolve_product_image(&self, uri: Option<String>) -> Option<String> {
        let uri = uri?;
        if !is_blob_path(&uri) {
            return Some(uri);
        }
        let ttl_minutes = match Config::get() {
            Ok(config) => config.image_sas_ttl_minutes,
            Err(error) => {
                tracing::warn!("Cannot mint SAS URL for {}: {}", uri, error);
                return Some(uri);
            }
        };
        match self.blob_store.mint_read_url(&uri, ttl_minutes).await {
            Ok(sas_url) => Some(sas_url),
            Err(error) => {
                tracing::warn!("Failed to mint SAS URL for {}: {}", uri, error);
                Some(uri)
            }
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
            product_image_uri: image_uri.map(Some),
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
        let product = repo
            .get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .ok_or(ProductServiceError::ProductNotFound)?;

        repo.delete(product_id)
            .await
            .map_err(|_| ProductServiceError::ProductDeletionFailed)?;

        if let Some(uri) = product.product_image_uri.filter(|uri| is_blob_path(uri))
            && let Err(error) = self.blob_store.delete(&uri).await
        {
            tracing::warn!("Failed to delete product image blob {}: {}", uri, error);
        }

        Ok(())
    }

    /// Uploads a product image (requires WRITE permission or Admin)
    pub async fn upload_product_image(
        &self,
        product_id: i32,
        bytes: &[u8],
        declared_mime: Option<&str>,
        role_id: i32,
    ) -> Result<String, ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();

        let product = repo
            .get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .ok_or(ProductServiceError::ProductNotFound)?;

        let config = Config::get().map_err(|_| ProductServiceError::ConfigError)?;
        if bytes.len() > config.image_max_bytes {
            return Err(ProductServiceError::ImageTooLarge);
        }

        let image_type = detect_image_type(bytes).ok_or(ProductServiceError::InvalidImageType)?;
        if let Some(declared) = declared_mime
            && is_whitelisted_mime(declared)
            && declared != image_type.mime
        {
            return Err(ProductServiceError::InvalidImageType);
        }

        let blob_name = self
            .blob_store
            .upload(bytes, image_type.mime)
            .await
            .map_err(map_blob_store_error)?;

        if let Some(previous) = product
            .product_image_uri
            .as_deref()
            .filter(|uri| is_blob_path(uri))
            && let Err(error) = self.blob_store.delete(previous).await
        {
            tracing::warn!("Failed to delete replaced product image blob {}: {}", previous, error);
        }

        let update = UpdateProduct {
            name: None,
            product_image_uri: Some(Some(&blob_name)),
            description: None,
            price: None,
        };

        if repo.update(product_id, update).await.is_err() {
            if let Err(cleanup_error) = self.blob_store.delete(&blob_name).await {
                tracing::warn!(
                    "Failed to roll back uploaded product image blob {}: {}",
                    blob_name,
                    cleanup_error
                );
            }
            return Err(ProductServiceError::ImageUploadFailed);
        }

        Ok(blob_name)
    }

    /// Deletes a product image (requires ADMIN permission)
    pub async fn delete_product_image(
        &self,
        product_id: i32,
        role_id: i32,
    ) -> Result<(), ProductServiceError> {
        if !self.has_permission(role_id, RolePermissions::Admin).await? {
            return Err(ProductServiceError::PermissionDenied);
        }

        let repo = ProductRepo::new();

        let product = repo
            .get_by_id(product_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
            .ok_or(ProductServiceError::ProductNotFound)?;

        if let Some(blob_name) = product.product_image_uri.filter(|uri| is_blob_path(uri)) {
            match self.blob_store.delete(&blob_name).await {
                Ok(_) => {}
                Err(BlobStoreError::NotConfigured) => {
                    return Err(ProductServiceError::StorageNotConfigured);
                }
                Err(error) => {
                    tracing::warn!("Failed to delete product image blob {}: {}", blob_name, error);
                }
            }
        }

        let update = UpdateProduct {
            name: None,
            product_image_uri: Some(None),
            description: None,
            price: None,
        };

        repo.update(product_id, update)
            .await
            .map_err(|_| ProductServiceError::ImageDeletionFailed)
    }

    async fn has_permission(
        &self,
        role_id: i32,
        required_permission: RolePermissions,
    ) -> Result<bool, ProductServiceError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;
        let role_repo = RoleRepo::new();
        if let Some(role) = role_repo
            .get_by_id(role_id)
            .await
            .map_err(|_| ProductServiceError::DatabaseError)?
        {
            return Ok(role.has_permission(required_permission));
        }
        Ok(false)
    }
}

fn map_blob_store_error(error: BlobStoreError) -> ProductServiceError {
    match error {
        BlobStoreError::NotConfigured => ProductServiceError::StorageNotConfigured,
        BlobStoreError::SasUnavailable => ProductServiceError::StorageNotConfigured,
        other => {
            tracing::error!("Blob storage operation failed: {}", other);
            ProductServiceError::ImageUploadFailed
        }
    }
}

impl Default for ProductService {
    fn default() -> Self {
        Self::new()
    }
}
