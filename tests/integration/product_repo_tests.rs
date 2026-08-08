use arrow_server_lib::data::models::product::{NewProduct, UpdateProduct};
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use bigdecimal::BigDecimal;
use std::str::FromStr;

use crate::common::{create_product, uniq};

#[tokio::test]
async fn test_create_product() {
    let repo = ProductRepo::new();
    let name = uniq("Burger");

    let new_product = NewProduct {
        name: &name,
        product_image_uri: Some("/images/burger.jpg"),
        description: Some("Delicious beef burger"),
        price: BigDecimal::from_str("9.99").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name(&name)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(product.name, name);
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
async fn test_get_product_by_id() {
    let repo = ProductRepo::new();
    let name = uniq("Pizza");
    let product = create_product(&name).await;

    let fetched_product = repo
        .get_by_id(product.product_id)
        .await
        .expect("Failed to get by id")
        .expect("Product not found by id");

    assert_eq!(fetched_product.name, name);
    assert_eq!(fetched_product.product_id, product.product_id);
}

#[tokio::test]
async fn test_get_product_by_id_not_found() {
    let repo = ProductRepo::new();

    let result = repo.get_by_id(i32::MAX - 42).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent product");
}

#[tokio::test]
async fn test_get_product_by_name() {
    let repo = ProductRepo::new();
    let name = uniq("Salad");

    let new_product = NewProduct {
        name: &name,
        product_image_uri: Some("/images/salad.png"),
        description: Some("Fresh garden salad"),
        price: BigDecimal::from_str("7.25").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let fetched_product = repo
        .get_by_name(&name)
        .await
        .expect("Failed to get by name")
        .expect("Product not found by name");

    assert_eq!(fetched_product.name, name);
    assert_eq!(fetched_product.price, BigDecimal::from_str("7.25").unwrap());
}

#[tokio::test]
async fn test_get_product_by_name_not_found() {
    let repo = ProductRepo::new();

    let result = repo
        .get_by_name(&uniq("missing"))
        .await
        .expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent product name"
    );
}

#[tokio::test]
async fn test_update_product() {
    let repo = ProductRepo::new();
    let old_name = uniq("OldProduct");
    let new_name = uniq("NewProduct");
    let product = create_product(&old_name).await;

    let update_form = UpdateProduct {
        name: Some(&new_name),
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

    assert_eq!(updated_product.name, new_name);
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
async fn test_update_product_partial() {
    let repo = ProductRepo::new();
    let name = uniq("PartialProduct");
    let new_name = uniq("UpdatedPartialProduct");

    let new_product = NewProduct {
        name: &name,
        product_image_uri: Some("/keep.jpg"),
        description: Some("Keep this description"),
        price: BigDecimal::from_str("15.00").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name(&name)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let update_form = UpdateProduct {
        name: Some(&new_name),
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

    assert_eq!(updated_product.name, new_name);
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
async fn test_delete_product() {
    let repo = ProductRepo::new();
    let name = uniq("DeleteProduct");
    let product = create_product(&name).await;

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
async fn test_get_all_with_products() {
    let repo = ProductRepo::new();
    let product1 = create_product(&uniq("Product1")).await;
    let product2 = create_product(&uniq("Product2")).await;

    let products = repo
        .get_all()
        .await
        .expect("Failed to get all products")
        .expect("Expected products");

    let product_ids: Vec<i32> = products.iter().map(|p| p.product_id).collect();
    assert!(product_ids.contains(&product1.product_id));
    assert!(product_ids.contains(&product2.product_id));
}

#[tokio::test]
async fn test_product_with_decimal_precision() {
    let repo = ProductRepo::new();
    let name = uniq("PrecisionProduct");

    let new_product = NewProduct {
        name: &name,
        product_image_uri: None,
        description: None,
        price: BigDecimal::from_str("123.45").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    let product = repo
        .get_by_name(&name)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    assert_eq!(product.price, BigDecimal::from_str("123.45").unwrap());
}
