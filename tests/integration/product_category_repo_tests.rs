use arrow_server_lib::data::models::product_category::NewProductCategory;
use arrow_server_lib::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;

use crate::common::{create_category, create_product, uniq};

#[tokio::test]
async fn test_product_category_repo_crud() {
    let product_category_repo = ProductCategoryRepo::new();
    let product = create_product(&uniq("pc_product")).await;
    let category = create_category(&uniq("pc_category")).await;

    let new_product_category = NewProductCategory {
        product_id: &product.product_id,
        category_id: &category.category_id,
    };
    let add_result = product_category_repo.add(new_product_category).await;
    assert!(add_result.is_ok(), "Failed to add product category");

    let product_category = product_category_repo
        .get_by_id((product.product_id, category.category_id))
        .await
        .expect("Failed to get product category by ID")
        .expect("Product category not found");
    assert_eq!(product_category.product_id, product.product_id);
    assert_eq!(product_category.category_id, category.category_id);

    let all_links = product_category_repo
        .get_all()
        .await
        .expect("Failed to get all");
    assert!(all_links.is_some());
    let all_links = all_links.unwrap();
    assert!(all_links
        .iter()
        .any(|pc| pc.product_id == product.product_id && pc.category_id == category.category_id));

    let products = product_category_repo
        .get_products_by_category_id(category.category_id)
        .await
        .expect("Failed to get products by category")
        .expect("Products not found");
    assert_eq!(products.len(), 1);
    assert_eq!(products[0].name, product.name);

    let delete_result = product_category_repo
        .delete((product.product_id, category.category_id))
        .await;
    assert!(delete_result.is_ok(), "Failed to delete product category");

    let deleted_link = product_category_repo
        .get_by_id((product.product_id, category.category_id))
        .await
        .expect("Failed to get after delete");
    assert!(deleted_link.is_none(), "Product category should be deleted");
}
