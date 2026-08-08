use arrow_server_lib::data::models::categories::{NewCategory, UpdateCategory};
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;

use crate::common::uniq;

#[tokio::test]
async fn test_category_repo_crud() {
    let repo = CategoryRepo::new();
    let name = uniq("Test Category");
    let updated_name = uniq("Updated Test Category");
    let description = "This is a test category";

    let new_category = NewCategory {
        name: &name,
        description: Some(description),
    };
    let add_result = repo.add(new_category).await;
    assert!(add_result.is_ok(), "Failed to add category");

    let category = repo
        .get_by_name(&name)
        .await
        .expect("Failed to get category by name")
        .expect("Category not found");
    assert_eq!(category.name, name);
    assert_eq!(category.description, Some(description.to_string()));

    let update_data = UpdateCategory {
        name: Some(&updated_name),
        description: None,
    };
    let update_result = repo.update(category.category_id, update_data).await;
    assert!(update_result.is_ok(), "Failed to update category");

    let updated_category = repo
        .get_by_id(category.category_id)
        .await
        .expect("Failed to get category by ID")
        .expect("Updated category not found");
    assert_eq!(updated_category.name, updated_name);

    let delete_result = repo.delete(category.category_id).await;
    assert!(delete_result.is_ok(), "Failed to delete category");

    let deleted_category = repo
        .get_by_id(category.category_id)
        .await
        .expect("Failed to get category after delete");
    assert!(deleted_category.is_none(), "Category should be deleted");
}
