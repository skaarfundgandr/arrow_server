use arrow_server_lib::data::models::categories::NewCategory;
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::product_category::NewProductCategory;
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use bigdecimal::BigDecimal;
use std::str::FromStr;

#[tokio::test]
#[serial_test::serial]
async fn test_product_category_repo_crud() {
    let product_repo = ProductRepo::new();
    let category_repo = CategoryRepo::new();
    let product_category_repo = ProductCategoryRepo::new();

    // 1. Setup: Create Product and Category
    let product_name = "ProductCategory Test Product";
    let new_product = NewProduct {
        name: product_name,
        description: Some("Test Description"),
        price: BigDecimal::from_str("10.50").unwrap(),
        product_image_uri: None,
    };
    product_repo
        .add(new_product)
        .await
        .expect("Failed to add product");
    let product = product_repo
        .get_by_name(product_name)
        .await
        .expect("Failed to get product")
        .expect("Product not found");

    let category_name = "ProductCategory Test Category";
    let new_category = NewCategory {
        name: category_name,
        description: Some("Test Description"),
    };
    category_repo
        .add(new_category)
        .await
        .expect("Failed to add category");
    let category = category_repo
        .get_by_name(category_name)
        .await
        .expect("Failed to get category")
        .expect("Category not found");

    // 2. Create ProductCategory
    let new_product_category = NewProductCategory {
        product_id: &product.product_id,
        category_id: &category.category_id,
    };
    let add_result = product_category_repo.add(new_product_category).await;
    assert!(add_result.is_ok(), "Failed to add product category");

    // 3. Read (Get by ID)
    let product_category = product_category_repo
        .get_by_id((product.product_id, category.category_id))
        .await
        .expect("Failed to get product category by ID")
        .expect("Product category not found");
    assert_eq!(product_category.product_id, product.product_id);
    assert_eq!(product_category.category_id, category.category_id);

    // 4. Read (Get All)
    let all_links = product_category_repo
        .get_all()
        .await
        .expect("Failed to get all");
    assert!(all_links.is_some());
    let all_links = all_links.unwrap();
    assert!(all_links.iter().any(|pc| pc.product_id == product.product_id && pc.category_id == category.category_id));

    // 4.5 Check get_products_by_category_id
    let products = product_category_repo
        .get_products_by_category_id(category.category_id)
        .await
        .expect("Failed to get products by category")
        .expect("Products not found");
    assert_eq!(products.len(), 1);
    assert_eq!(products[0].name, product_name);

    // 5. Delete
    let delete_result = product_category_repo
        .delete((product.product_id, category.category_id))
        .await;
    assert!(delete_result.is_ok(), "Failed to delete product category");

    // 6. Verify Delete
    let deleted_link = product_category_repo
        .get_by_id((product.product_id, category.category_id))
        .await
        .expect("Failed to get after delete");
    assert!(deleted_link.is_none(), "Product category should be deleted");

    // Cleanup
    product_repo
        .delete(product.product_id)
        .await
        .expect("Failed to delete product");
    category_repo
        .delete(category.category_id)
        .await
        .expect("Failed to delete category");
}
