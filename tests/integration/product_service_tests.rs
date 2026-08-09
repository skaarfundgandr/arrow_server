use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::services::errors::ProductServiceError;
use arrow_server_lib::services::product_service::ProductService;
use bigdecimal::BigDecimal;
use std::str::FromStr;
use std::sync::Arc;

use crate::common::{
    BlobCall, StubBlobStore, assign_product_to_category, create_category,
    create_role_with_permission, create_user, gif_bytes, jpeg_bytes, png_bytes, uniq, webp_bytes,
};

#[tokio::test]
async fn test_create_product_with_write_permission() {
    let _user_id = create_user(&uniq("product_writer")).await.user_id;
    let role_id = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service
        .create_product(
            &uniq("TestBurger"),
            Some("Delicious burger"),
            BigDecimal::from_str("9.99").unwrap(),
            Some("/images/burger.jpg"),
            role_id,
        )
        .await;

    assert!(
        result.is_ok(),
        "Should create product with WRITE permission"
    );
}

#[tokio::test]
async fn test_create_product_with_admin_permission() {
    let _user_id = create_user(&uniq("product_admin")).await.user_id;
    let role_id = create_role_with_permission(&uniq("prod_admin"), RolePermissions::Admin)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service
        .create_product(
            &uniq("AdminBurger"),
            Some("Admin's burger"),
            BigDecimal::from_str("12.99").unwrap(),
            None,
            role_id,
        )
        .await;

    assert!(
        result.is_ok(),
        "Should create product with ADMIN permission"
    );
}

#[tokio::test]
async fn test_create_product_without_permission() {
    let _user_id = create_user(&uniq("product_reader")).await.user_id;
    let role_id = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service
        .create_product(
            &uniq("ReaderBurger"),
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            role_id,
        )
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not create product with READ permission"
    );
}

#[tokio::test]
async fn test_create_duplicate_product() {
    let _user_id = create_user(&uniq("duplicate_creator")).await.user_id;
    let role_id = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("UniqueBurger");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("8.00").unwrap(),
            None,
            role_id,
        )
        .await
        .expect("Failed to create first product");

    let result = service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("8.00").unwrap(),
            None,
            role_id,
        )
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ProductAlreadyExists),
        "Should not create duplicate product"
    );
}

#[tokio::test]
async fn test_get_all_products_with_read_permission() {
    let _user_id = create_user(&uniq("all_reader")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name1 = uniq("Product1");
    let name2 = uniq("Product2");

    service
        .create_product(
            &name1,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product 1");

    service
        .create_product(
            &name2,
            None,
            BigDecimal::from_str("10.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product 2");

    let products = service
        .get_all_products(read_role)
        .await
        .expect("Failed to get products")
        .expect("No products");

    let names: Vec<&str> = products.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&name1.as_str()));
    assert!(names.contains(&name2.as_str()));
}

#[tokio::test]
async fn test_get_all_products_without_permission() {
    let _user_id = create_user(&uniq("no_perm_viewer")).await.user_id;
    let role_id = create_role_with_permission(&uniq("prod_deleter"), RolePermissions::Delete)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service.get_all_products(role_id).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not get products with DELETE permission only"
    );
}

#[tokio::test]
async fn test_get_product_by_id() {
    let _user_id = create_user(&uniq("id_viewer")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("GetByIdProduct");

    service
        .create_product(
            &name,
            Some("Test description"),
            BigDecimal::from_str("15.50").unwrap(),
            Some("/image.jpg"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get by name")
        .expect("Product not found");

    let fetched = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get by id")
        .expect("Product not found by id");

    assert_eq!(fetched.name, name);
    assert_eq!(fetched.description, Some("Test description".to_string()));
    assert_eq!(fetched.price, BigDecimal::from_str("15.50").unwrap());
}

#[tokio::test]
async fn test_get_product_by_name() {
    let _user_id = create_user(&uniq("name_viewer")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("NamedProduct");

    service
        .create_product(
            &name,
            Some("A named product"),
            BigDecimal::from_str("7.25").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get by name")
        .expect("Product not found");

    assert_eq!(product.name, name);
    assert_eq!(product.description, Some("A named product".to_string()));
}

#[tokio::test]
async fn test_get_product_not_found() {
    let _user_id = create_user(&uniq("not_found_viewer")).await.user_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service.get_product_by_id(i32::MAX - 70, read_role).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    let result = service.get_product_by_name(&uniq("NonExistent"), read_role).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_update_product_with_write_permission() {
    let _user_id = create_user(&uniq("product_updater")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("UpdateableProduct");
    let new_name = uniq("UpdatedProduct");

    service
        .create_product(
            &name,
            Some("Original description"),
            BigDecimal::from_str("10.00").unwrap(),
            Some("/old.jpg"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    service
        .update_product(
            product.product_id,
            Some(&new_name),
            Some("New description"),
            Some(BigDecimal::from_str("15.00").unwrap()),
            Some("/new.jpg"),
            write_role,
        )
        .await
        .expect("Failed to update product");

    let updated = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.description, Some("New description".to_string()));
    assert_eq!(updated.price, BigDecimal::from_str("15.00").unwrap());
    assert_eq!(updated.product_image_uri, Some("/new.jpg".to_string()));
}

#[tokio::test]
async fn test_update_product_partial() {
    let _user_id = create_user(&uniq("partial_updater")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("PartialUpdateProduct");
    let new_name = uniq("NewName");

    service
        .create_product(
            &name,
            Some("Keep this"),
            BigDecimal::from_str("20.00").unwrap(),
            Some("/keep.jpg"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    service
        .update_product(product.product_id, Some(&new_name), None, None, None, write_role)
        .await
        .expect("Failed to update product");

    let updated = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(updated.name, new_name);
    assert_eq!(updated.description, Some("Keep this".to_string()));
    assert_eq!(updated.price, BigDecimal::from_str("20.00").unwrap());
    assert_eq!(updated.product_image_uri, Some("/keep.jpg".to_string()));
}

#[tokio::test]
async fn test_update_product_not_found() {
    let _user_id = create_user(&uniq("update_not_found")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service
        .update_product(
            i32::MAX - 71,
            Some("NewName"),
            None,
            None,
            None,
            write_role,
        )
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ProductNotFound),
        "Should return not found for non-existent product"
    );
}

#[tokio::test]
async fn test_update_product_without_permission() {
    let _user_id = create_user(&uniq("no_perm_updater")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("NoPermProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service
        .update_product(product.product_id, Some("NewName"), None, None, None, read_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not update with READ permission"
    );
}

#[tokio::test]
async fn test_delete_product_with_delete_permission() {
    let _user_id = create_user(&uniq("product_deleter")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let delete_role = create_role_with_permission(&uniq("prod_deleter"), RolePermissions::Delete)
        .await
        .role_id;
    let admin_role = create_role_with_permission(&uniq("prod_admin"), RolePermissions::Admin)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("DeleteableProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, admin_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    service
        .delete_product(product.product_id, delete_role)
        .await
        .expect("Failed to delete product");

    let deleted = service
        .get_product_by_id(product.product_id, admin_role)
        .await
        .expect("Failed to query");

    assert!(deleted.is_none(), "Product should be deleted");
}

#[tokio::test]
async fn test_delete_product_with_admin_permission() {
    let _user_id = create_user(&uniq("admin_deleter")).await.user_id;
    let admin_role = create_role_with_permission(&uniq("prod_admin"), RolePermissions::Admin)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("AdminDeleteProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            admin_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, admin_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    service
        .delete_product(product.product_id, admin_role)
        .await
        .expect("Failed to delete product");

    let deleted = service
        .get_product_by_id(product.product_id, admin_role)
        .await
        .expect("Failed to query");

    assert!(deleted.is_none(), "Product should be deleted");
}

#[tokio::test]
async fn test_delete_product_without_permission() {
    let _user_id = create_user(&uniq("no_delete_perm")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("NoDeleteProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service.delete_product(product.product_id, write_role).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not delete with WRITE permission"
    );

    let result = service.delete_product(product.product_id, read_role).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not delete with READ permission"
    );
}

#[tokio::test]
async fn test_delete_product_not_found() {
    let _user_id = create_user(&uniq("delete_not_found")).await.user_id;
    let delete_role = create_role_with_permission(&uniq("prod_deleter"), RolePermissions::Delete)
        .await
        .role_id;

    let service = ProductService::new();

    let result = service.delete_product(i32::MAX - 72, delete_role).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ProductNotFound),
        "Should return not found"
    );
}

#[tokio::test]
async fn test_upload_product_image() {
    let _user_id = create_user(&uniq("image_updater")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("ImageProduct");

    service
        .create_product(
            &name,
            Some("Product with image"),
            BigDecimal::from_str("10.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert!(product.product_image_uri.is_none());

    let bytes = png_bytes();
    let blob_name = service
        .upload_product_image(product.product_id, &bytes, Some("image/png"), write_role)
        .await
        .expect("Failed to upload image");

    assert!(blob_name.starts_with("products/"));
    assert!(blob_name.ends_with(".png"));

    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert_eq!(stored.product_image_uri, Some(blob_name.clone()));

    let fetched = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");
    assert_eq!(
        fetched.product_image_uri,
        Some(format!(
            "https://stub.blob.core.windows.net/{blob_name}?sig=stub&ttl=15"
        ))
    );

    let calls = stub.calls();
    assert!(matches!(
        &calls[0],
        BlobCall::Upload {
            bytes_len,
            content_type,
        } if *bytes_len == bytes.len() && content_type == "image/png"
    ));
    assert!(matches!(
        &calls[1],
        BlobCall::Mint {
            blob_name: minted,
            ttl_minutes: 15,
        } if *minted == blob_name
    ));
}

#[tokio::test]
async fn test_upload_product_image_with_admin_permission() {
    let _user_id = create_user(&uniq("image_admin")).await.user_id;
    let admin_role = create_role_with_permission(&uniq("prod_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("AdminImageProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            admin_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service
        .upload_product_image(product.product_id, &jpeg_bytes(), Some("image/jpeg"), admin_role)
        .await;

    assert!(result.is_ok(), "ADMIN should be able to upload an image");
    assert!(stub
        .calls()
        .iter()
        .any(|call| matches!(call, BlobCall::Upload { .. })));
}

#[tokio::test]
async fn test_upload_product_image_without_permission() {
    let _user_id = create_user(&uniq("no_image_perm")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("NoImagePermProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service
        .upload_product_image(product.product_id, &png_bytes(), Some("image/png"), read_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not upload image with READ permission"
    );
    assert!(stub.calls().is_empty(), "No blob calls expected");
}

#[tokio::test]
async fn test_upload_product_image_not_found() {
    let _user_id = create_user(&uniq("image_not_found")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let result = service
        .upload_product_image(i32::MAX - 73, &png_bytes(), Some("image/png"), write_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ProductNotFound),
        "Should return not found for non-existent product"
    );
    assert!(stub.calls().is_empty(), "No blob calls expected");
}

#[tokio::test]
async fn test_upload_product_image_too_large() {
    let _user_id = create_user(&uniq("image_oversize")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("OversizeImageProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let mut oversized = png_bytes();
    oversized.resize(2 * 1024 * 1024 + 1, 0);

    let result = service
        .upload_product_image(product.product_id, &oversized, Some("image/png"), write_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ImageTooLarge),
        "Should reject oversized image"
    );
    assert!(stub.calls().is_empty(), "No blob calls expected");
}

#[tokio::test]
async fn test_upload_product_image_invalid_magic_bytes() {
    let _user_id = create_user(&uniq("image_bad_magic")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("BadMagicProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service
        .upload_product_image(product.product_id, &gif_bytes(), Some("image/png"), write_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::InvalidImageType),
        "Should reject non-image bytes declared as png"
    );
    assert!(stub.calls().is_empty(), "No blob calls expected");
}

#[tokio::test]
async fn test_upload_product_image_mime_mismatch() {
    let _user_id = create_user(&uniq("image_mime_mismatch")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("MimeMismatchProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service
        .upload_product_image(product.product_id, &png_bytes(), Some("image/jpeg"), write_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::InvalidImageType),
        "Should reject a declared MIME that contradicts the magic bytes"
    );
    assert!(stub.calls().is_empty(), "No blob calls expected");
}

#[tokio::test]
async fn test_upload_product_image_webp() {
    let _user_id = create_user(&uniq("image_webp")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("WebpProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let blob_name = service
        .upload_product_image(product.product_id, &webp_bytes(), Some("image/webp"), write_role)
        .await
        .expect("Failed to upload webp image");

    assert!(blob_name.starts_with("products/"));
    assert!(stub.calls().contains(&BlobCall::Upload {
        bytes_len: webp_bytes().len(),
        content_type: "image/webp".to_string(),
    }));
    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert_eq!(stored.product_image_uri, Some(blob_name));
}

#[tokio::test]
async fn test_product_with_decimal_precision() {
    let _user_id = create_user(&uniq("precision_tester")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("PreciseProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("123.45").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(product.price, BigDecimal::from_str("123.45").unwrap());
}

#[tokio::test]
async fn test_get_product_with_categories() {
    let _user_id = create_user(&uniq("cat_viewer")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let service = ProductService::new();

    let name = uniq("CatProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("10.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let category_name = uniq("TestCategory");
    let category = create_category(&category_name).await;
    assign_product_to_category(product.product_id, category.category_id).await;

    let fetched = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert!(fetched.categories.is_some());
    let cats = fetched.categories.unwrap();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0].name, category_name);
}

#[tokio::test]
async fn test_upload_product_image_replaces_and_deletes_old_blob() {
    let _user_id = create_user(&uniq("image_replacer")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("ReplaceImageProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let first = service
        .upload_product_image(product.product_id, &png_bytes(), Some("image/png"), write_role)
        .await
        .expect("Failed to upload first image");

    let second = service
        .upload_product_image(product.product_id, &jpeg_bytes(), Some("image/jpeg"), write_role)
        .await
        .expect("Failed to upload second image");

    assert_ne!(first, second);

    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert_eq!(stored.product_image_uri, Some(second));

    let calls = stub.calls();
    let deletes: Vec<&String> = calls
        .iter()
        .filter_map(|call| match call {
            BlobCall::Delete { blob_name } => Some(blob_name),
            _ => None,
        })
        .collect();
    assert_eq!(deletes, vec![&first], "Old blob should be deleted once");
}

#[tokio::test]
async fn test_delete_product_image_admin() {
    let _user_id = create_user(&uniq("image_deleter")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let admin_role = create_role_with_permission(&uniq("prod_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("DeleteImageProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let blob_name = service
        .upload_product_image(product.product_id, &png_bytes(), Some("image/png"), write_role)
        .await
        .expect("Failed to upload image");

    service
        .delete_product_image(product.product_id, admin_role)
        .await
        .expect("Failed to delete image");

    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert!(
        stored.product_image_uri.is_none(),
        "Image column should be nulled"
    );
    assert!(stub.calls().contains(&BlobCall::Delete {
        blob_name: blob_name.clone()
    }));
}

#[tokio::test]
async fn test_delete_product_image_external_uri_skips_blob() {
    let _user_id = create_user(&uniq("image_external")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let admin_role = create_role_with_permission(&uniq("prod_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("ExternalImageProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            Some("https://cdn.example.com/image.png"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    service
        .delete_product_image(product.product_id, admin_role)
        .await
        .expect("Failed to delete image");

    let stored = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed")
        .expect("Product not found");
    assert!(
        stored.product_image_uri.is_none(),
        "Image column should be nulled"
    );
    assert!(
        stub.calls().is_empty(),
        "No blob delete expected for external URL"
    );
}

#[tokio::test]
async fn test_delete_product_image_without_permission() {
    let _user_id = create_user(&uniq("no_image_delete_perm")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("NoImageDeleteProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let result = service
        .delete_product_image(product.product_id, write_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not delete image with WRITE permission"
    );

    let result = service
        .delete_product_image(product.product_id, read_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not delete image with READ permission"
    );
    assert!(stub.calls().is_empty(), "No blob calls expected");
}

#[tokio::test]
async fn test_delete_product_deletes_blob() {
    let _user_id = create_user(&uniq("product_blob_deleter")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let delete_role = create_role_with_permission(&uniq("prod_deleter"), RolePermissions::Delete)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("BlobDeleteProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let blob_name = service
        .upload_product_image(product.product_id, &png_bytes(), Some("image/png"), write_role)
        .await
        .expect("Failed to upload image");

    service
        .delete_product(product.product_id, delete_role)
        .await
        .expect("Failed to delete product");

    let deleted = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed");
    assert!(deleted.is_none(), "Product should be deleted");
    assert!(stub.calls().contains(&BlobCall::Delete {
        blob_name: blob_name.clone()
    }));
}

#[tokio::test]
async fn test_delete_product_ignores_blob_delete_failure() {
    let _user_id = create_user(&uniq("product_blob_fail")).await.user_id;
    let write_role = create_role_with_permission(&uniq("prod_writer"), RolePermissions::Write)
        .await
        .role_id;
    let delete_role = create_role_with_permission(&uniq("prod_deleter"), RolePermissions::Delete)
        .await
        .role_id;
    let read_role = create_role_with_permission(&uniq("prod_reader"), RolePermissions::Read)
        .await
        .role_id;

    let stub = Arc::new(StubBlobStore::new());
    stub.fail_deletes(true);
    let service = ProductService::with_blob_store(stub.clone());

    let name = uniq("BlobFailProduct");

    service
        .create_product(
            &name,
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name(&name, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    service
        .upload_product_image(product.product_id, &png_bytes(), Some("image/png"), write_role)
        .await
        .expect("Failed to upload image");

    let result = service.delete_product(product.product_id, delete_role).await;

    assert!(
        result.is_ok(),
        "Blob delete failure should not fail product deletion"
    );
    let deleted = ProductRepo::new()
        .get_by_id(product.product_id)
        .await
        .expect("Query failed");
    assert!(deleted.is_none(), "Product should be deleted");
}
