use arrow_server_lib::data::models::categories::{NewCategory, UpdateCategory};
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;

#[tokio::test]
#[serial_test::serial]
async fn test_category_repo_crud() {
    let repo = CategoryRepo::new();
    let name = "Test Category";
    let description = "This is a test category";

    // Cleanup
    if let Ok(Some(cat)) = repo.get_by_name(name).await {
        repo.delete(cat.category_id).await.ok();
    }

    // 1. Create
    let new_category = NewCategory {
        name,
        description: Some(description),
    };
    let add_result = repo.add(new_category).await;
    assert!(add_result.is_ok(), "Failed to add category");

    // 2. Read (Get by name)
    let category = repo
        .get_by_name(name)
        .await
        .expect("Failed to get category by name")
        .expect("Category not found");
    assert_eq!(category.name, name);
    assert_eq!(category.description, Some(description.to_string()));

    // 3. Update
    let updated_name = "Updated Test Category";
    let update_data = UpdateCategory {
        name: Some(updated_name),
        description: None,
    };
    let update_result = repo.update(category.category_id, update_data).await;
    assert!(update_result.is_ok(), "Failed to update category");

    // 4. Read (Get by ID)
    let updated_category = repo
        .get_by_id(category.category_id)
        .await
        .expect("Failed to get category by ID")
        .expect("Updated category not found");
    assert_eq!(updated_category.name, updated_name);

    // 5. Delete
    let delete_result = repo.delete(category.category_id).await;
    assert!(delete_result.is_ok(), "Failed to delete category");

    // 6. Verify Delete
    let deleted_category = repo
        .get_by_id(category.category_id)
        .await
        .expect("Failed to get category after delete");
    assert!(deleted_category.is_none(), "Category should be deleted");
}
