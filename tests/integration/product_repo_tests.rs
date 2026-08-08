use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::product::{NewProduct, UpdateProduct};
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
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

    // Clean up in order due to foreign key constraints
    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_product() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "Burger",
        product_image_uri: Some("/images/burger.jpg"),
        description: Some("Delicious beef burger"),
        price: BigDecimal::from_str("9.99").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name("Burger")
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(product.name, "Burger");
    assert_eq!(
        product.product_image_uri,
        Some("/images/burger.jpg".to_string())
    );
    assert_eq!(
        product.description,
        Some("Delicious beef burger".to_string())
    );
    assert_eq!(product.price, BigDecimal::from_str("9.99").unwrap());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_products_empty() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let products = repo.get_all().await.expect("Failed to get all products");

    assert_eq!(products, None, "Expected no products in the database");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_by_id() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "Pizza",
        product_image_uri: None,
        description: Some("Cheesy pizza"),
        price: BigDecimal::from_str("12.50").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name("Pizza")
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let fetched_product = repo
        .get_by_id(product.product_id)
        .await
        .expect("Failed to get by id")
        .expect("Product not found by id");

    assert_eq!(fetched_product.name, "Pizza");
    assert_eq!(fetched_product.product_id, product.product_id);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_by_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let result = repo.get_by_id(99999).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent product");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_by_name() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "Salad",
        product_image_uri: Some("/images/salad.png"),
        description: Some("Fresh garden salad"),
        price: BigDecimal::from_str("7.25").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let fetched_product = repo
        .get_by_name("Salad")
        .await
        .expect("Failed to get by name")
        .expect("Product not found by name");

    assert_eq!(fetched_product.name, "Salad");
    assert_eq!(fetched_product.price, BigDecimal::from_str("7.25").unwrap());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_product_by_name_not_found() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let result = repo
        .get_by_name("NonExistentProduct")
        .await
        .expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent product name"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "OldProduct",
        product_image_uri: Some("/old.jpg"),
        description: Some("Old description"),
        price: BigDecimal::from_str("5.00").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name("OldProduct")
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let update_form = UpdateProduct {
        name: Some("NewProduct"),
        product_image_uri: Some("/new.jpg"),
        description: Some("New description"),
        price: Some(BigDecimal::from_str("10.00").unwrap()),
    };

    repo.update(product.product_id, update_form)
        .await
        .expect("Failed to update product");

    let updated_product = repo
        .get_by_id(product.product_id)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(updated_product.name, "NewProduct");
    assert_eq!(
        updated_product.product_image_uri,
        Some("/new.jpg".to_string())
    );
    assert_eq!(
        updated_product.description,
        Some("New description".to_string())
    );
    assert_eq!(
        updated_product.price,
        BigDecimal::from_str("10.00").unwrap()
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_product_partial() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "PartialProduct",
        product_image_uri: Some("/keep.jpg"),
        description: Some("Keep this description"),
        price: BigDecimal::from_str("15.00").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name("PartialProduct")
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let update_form = UpdateProduct {
        name: Some("UpdatedPartialProduct"),
        product_image_uri: None,
        description: None,
        price: None,
    };

    repo.update(product.product_id, update_form)
        .await
        .expect("Failed to update product");

    let updated_product = repo
        .get_by_id(product.product_id)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(updated_product.name, "UpdatedPartialProduct");
    assert_eq!(
        updated_product.product_image_uri,
        Some("/keep.jpg".to_string()),
        "Image URI should remain unchanged"
    );
    assert_eq!(
        updated_product.description,
        Some("Keep this description".to_string()),
        "Description should remain unchanged"
    );
    assert_eq!(
        updated_product.price,
        BigDecimal::from_str("15.00").unwrap(),
        "Price should remain unchanged"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_product() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "DeleteProduct",
        product_image_uri: None,
        description: None,
        price: BigDecimal::from_str("1.00").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name("DeleteProduct")
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    repo.delete(product.product_id)
        .await
        .expect("Failed to delete product");

    let deleted_product = repo
        .get_by_id(product.product_id)
        .await
        .expect("Query failed");

    assert!(deleted_product.is_none(), "Product should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_with_products() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    repo.add(NewProduct {
        name: "Product1",
        product_image_uri: None,
        description: None,
        price: BigDecimal::from_str("5.00").unwrap(),
    })
    .await
    .expect("Failed to add product1");

    repo.add(NewProduct {
        name: "Product2",
        product_image_uri: Some("/img2.jpg"),
        description: Some("Second product"),
        price: BigDecimal::from_str("8.50").unwrap(),
    })
    .await
    .expect("Failed to add product2");

    let products = repo
        .get_all()
        .await
        .expect("Failed to get all products")
        .expect("Expected products");

    assert_eq!(products.len(), 2);

    let product_names: Vec<&str> = products.iter().map(|p| p.name.as_str()).collect();
    assert!(product_names.contains(&"Product1"));
    assert!(product_names.contains(&"Product2"));
}

#[tokio::test]
#[serial_test::serial]
async fn test_product_with_decimal_precision() {
    setup().await.expect("Setup failed");

    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "PrecisionProduct",
        product_image_uri: None,
        description: None,
        price: BigDecimal::from_str("123.45").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name("PrecisionProduct")
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(product.price, BigDecimal::from_str("123.45").unwrap());
}
