use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::categories::NewCategory;
use arrow_server_lib::data::models::product_category::NewProductCategory;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions};
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::services::errors::ProductServiceError;
use arrow_server_lib::services::product_service::ProductService;
use bigdecimal::BigDecimal;
use diesel::result;
use diesel_async::RunQueryDsl;
use std::str::FromStr;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
    use arrow_server_lib::data::models::schema::orders::dsl::orders;
    use arrow_server_lib::data::models::schema::products::dsl::products;
    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;
    use arrow_server_lib::data::models::schema::roles::dsl::roles;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_test_user(username: &str) -> i32 {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = auth
        .hash_password("testpass")
        .await
        .expect("Hashing failed");

    let test_user = NewUser {
        username,
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id
}

async fn create_role_with_permission(_user_id: i32, name: &str, permission: RolePermissions) -> i32 {
    let repo = RoleRepo::new();

    let new_role = NewRole {
        name,
        description: None,
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name(name)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    repo.set_permissions(role.role_id, permission)
        .await
        .expect("Failed to set permissions");

    role.role_id
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_product_with_write_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("product_writer").await;
    let role_id = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;

    let service = ProductService::new();

    let result = service
        .create_product(
            "TestBurger",
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
#[serial_test::serial]
async fn test_create_product_with_admin_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("product_admin").await;
    let role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;

    let service = ProductService::new();

    let result = service
        .create_product(
            "AdminBurger",
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
#[serial_test::serial]
async fn test_create_product_without_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("product_reader").await;
    let role_id = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    let result = service
        .create_product(
            "ReaderBurger",
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
#[serial_test::serial]
async fn test_create_duplicate_product() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("duplicate_creator").await;
    let role_id = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;

    let service = ProductService::new();

    // Create first product
    service
        .create_product(
            "UniqueBurger",
            None,
            BigDecimal::from_str("8.00").unwrap(),
            None,
            role_id,
        )
        .await
        .expect("Failed to create first product");

    // Try to create duplicate
    let result = service
        .create_product(
            "UniqueBurger",
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
#[serial_test::serial]
async fn test_get_all_products_with_read_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("all_reader").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create products
    service
        .create_product(
            "Product1",
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product 1");

    service
        .create_product(
            "Product2",
            None,
            BigDecimal::from_str("10.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product 2");

    // Get all products with read permission
    let products = service
        .get_all_products(read_role)
        .await
        .expect("Failed to get products");

    assert!(products.is_some());
    assert_eq!(products.unwrap().len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_products_without_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("no_perm_viewer").await;
    let role_id = create_role_with_permission(user_id, "deleter", RolePermissions::Delete).await;

    let service = ProductService::new();

    let result = service.get_all_products(role_id).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not get products with DELETE permission only"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_by_id() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("id_viewer").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "GetByIdProduct",
            Some("Test description"),
            BigDecimal::from_str("15.50").unwrap(),
            Some("/image.jpg"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    // Get product by name first to get the ID
    let product = service
        .get_product_by_name("GetByIdProduct", read_role)
        .await
        .expect("Failed to get by name")
        .expect("Product not found");

    // Get by ID
    let fetched = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get by id")
        .expect("Product not found by id");

    assert_eq!(fetched.name, "GetByIdProduct");
    assert_eq!(fetched.description, Some("Test description".to_string()));
    assert_eq!(fetched.price, BigDecimal::from_str("15.50").unwrap());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_by_name() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("name_viewer").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "NamedProduct",
            Some("A named product"),
            BigDecimal::from_str("7.25").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    // Get by name
    let product = service
        .get_product_by_name("NamedProduct", read_role)
        .await
        .expect("Failed to get by name")
        .expect("Product not found");

    assert_eq!(product.name, "NamedProduct");
    assert_eq!(product.description, Some("A named product".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_not_found() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("not_found_viewer").await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    let result = service.get_product_by_id(99999, read_role).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    let result = service.get_product_by_name("NonExistent", read_role).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_with_write_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("product_updater").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "UpdateableProduct",
            Some("Original description"),
            BigDecimal::from_str("10.00").unwrap(),
            Some("/old.jpg"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("UpdateableProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Update product
    service
        .update_product(
            product.product_id,
            Some("UpdatedProduct"),
            Some("New description"),
            Some(BigDecimal::from_str("15.00").unwrap()),
            Some("/new.jpg"),
            write_role,
        )
        .await
        .expect("Failed to update product");

    // Verify update
    let updated = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(updated.name, "UpdatedProduct");
    assert_eq!(updated.description, Some("New description".to_string()));
    assert_eq!(updated.price, BigDecimal::from_str("15.00").unwrap());
    assert_eq!(updated.product_image_uri, Some("/new.jpg".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_partial() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("partial_updater").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "PartialUpdateProduct",
            Some("Keep this"),
            BigDecimal::from_str("20.00").unwrap(),
            Some("/keep.jpg"),
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("PartialUpdateProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Partial update - only change name
    service
        .update_product(
            product.product_id,
            Some("NewName"),
            None,
            None,
            None,
            write_role,
        )
        .await
        .expect("Failed to update product");

    let updated = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(updated.name, "NewName");
    assert_eq!(updated.description, Some("Keep this".to_string()));
    assert_eq!(updated.price, BigDecimal::from_str("20.00").unwrap());
    assert_eq!(updated.product_image_uri, Some("/keep.jpg".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_not_found() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("update_not_found").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;

    let service = ProductService::new();

    let result = service
        .update_product(99999, Some("NewName"), None, None, None, write_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ProductNotFound),
        "Should return not found for non-existent product"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_without_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("no_perm_updater").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "NoPermProduct",
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("NoPermProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Try to update with read permission
    let result = service
        .update_product(
            product.product_id,
            Some("NewName"),
            None,
            None,
            None,
            read_role,
        )
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not update with READ permission"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_product_with_delete_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("product_deleter").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let delete_role =
        create_role_with_permission(user_id, "deleter", RolePermissions::Delete).await;
    let admin_role = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "DeleteableProduct",
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("DeleteableProduct", admin_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Delete product
    service
        .delete_product(product.product_id, delete_role)
        .await
        .expect("Failed to delete product");

    // Verify deleted
    let deleted = service
        .get_product_by_id(product.product_id, admin_role)
        .await
        .expect("Failed to query");

    assert!(deleted.is_none(), "Product should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_product_with_admin_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("admin_deleter").await;
    let admin_role = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "AdminDeleteProduct",
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            admin_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("AdminDeleteProduct", admin_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Delete product
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
#[serial_test::serial]
async fn test_delete_product_without_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("no_delete_perm").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "NoDeleteProduct",
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("NoDeleteProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Try to delete with write permission
    let result = service.delete_product(product.product_id, write_role).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not delete with WRITE permission"
    );

    // Try to delete with read permission
    let result = service.delete_product(product.product_id, read_role).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not delete with READ permission"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_product_not_found() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("delete_not_found").await;
    let delete_role =
        create_role_with_permission(user_id, "deleter", RolePermissions::Delete).await;

    let service = ProductService::new();

    let result = service.delete_product(99999, delete_role).await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::ProductNotFound),
        "Should return not found"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_image() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("image_updater").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product without image
    service
        .create_product(
            "ImageProduct",
            Some("Product with image"),
            BigDecimal::from_str("10.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("ImageProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert!(product.product_image_uri.is_none());

    // Update image
    service
        .update_product_image(
            product.product_id,
            "https://azure.blob/image.jpg",
            write_role,
        )
        .await
        .expect("Failed to update image");

    let updated = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(
        updated.product_image_uri,
        Some("https://azure.blob/image.jpg".to_string())
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_image_without_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("no_image_perm").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "NoImagePermProduct",
            None,
            BigDecimal::from_str("5.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("NoImagePermProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Try to update image with read permission
    let result = service
        .update_product_image(product.product_id, "/image.jpg", read_role)
        .await;

    assert_eq!(
        result.err(),
        Some(ProductServiceError::PermissionDenied),
        "Should not update image with READ permission"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_product_with_decimal_precision() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("precision_tester").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product with precise decimal
    service
        .create_product(
            "PreciseProduct",
            None,
            BigDecimal::from_str("123.45").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("PreciseProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(product.price, BigDecimal::from_str("123.45").unwrap());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_with_categories() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("cat_viewer").await;
    let write_role = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    let service = ProductService::new();

    // Create product
    service
        .create_product(
            "CatProduct",
            None,
            BigDecimal::from_str("10.00").unwrap(),
            None,
            write_role,
        )
        .await
        .expect("Failed to create product");

    let product = service
        .get_product_by_name("CatProduct", read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    // Create Category
    let category_repo = CategoryRepo::new();
    let category = NewCategory {
        name: "TestCategory",
        description: None,
    };
    category_repo
        .add(category)
        .await
        .expect("Failed to add category");
    let category = category_repo
        .get_by_name("TestCategory")
        .await
        .expect("Failed to get")
        .expect("Category not found");

    // Link
    let pc_repo = ProductCategoryRepo::new();
    let link = NewProductCategory {
        product_id: &product.product_id,
        category_id: &category.category_id,
    };
    pc_repo.add(link).await.expect("Failed to link");

    // Fetch product again
    let fetched = service
        .get_product_by_id(product.product_id, read_role)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert!(fetched.categories.is_some());
    let cats = fetched.categories.unwrap();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0].name, "TestCategory");
}