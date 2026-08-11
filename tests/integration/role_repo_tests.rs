use arrow_server_lib::data::models::roles::{NewRole, RolePermissions, UpdateRole};
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;

use crate::common::{create_role, uniq};

#[tokio::test]
async fn test_create_role() {
    let repo = RoleRepo::new();
    let name = uniq("admin");

    let new_role = NewRole {
        name: &name,
        description: Some("Administrator role"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name(&name)
        .await
        .expect("Failed to get role")
        .expect("No role found");

    assert_eq!(role.name, name);
    assert_eq!(role.description, Some("Administrator role".to_string()));
}

#[tokio::test]
async fn test_get_role_by_id() {
    let repo = RoleRepo::new();
    let role = create_role(&uniq("customer")).await;

    let fetched_role = repo
        .get_by_id(role.role_id)
        .await
        .expect("Failed to get by id")
        .expect("Role not found by id");

    assert_eq!(fetched_role.name, role.name);
    assert_eq!(fetched_role.role_id, role.role_id);
}

#[tokio::test]
async fn test_get_role_by_id_not_found() {
    let repo = RoleRepo::new();

    let result = repo.get_by_id(i32::MAX - 42).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent role");
}

#[tokio::test]
async fn test_get_role_by_name_not_found() {
    let repo = RoleRepo::new();

    let result = repo
        .get_by_name(&uniq("missing_role"))
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent role name");
}

#[tokio::test]
async fn test_update_role() {
    let repo = RoleRepo::new();
    let old_name = uniq("old_role");
    let new_name = uniq("new_role");
    let role = create_role(&old_name).await;

    let update_form = UpdateRole {
        name: Some(&new_name),
        description: Some("New description"),
    };

    repo.update(role.role_id, update_form)
        .await
        .expect("Failed to update role");

    let updated_role = repo
        .get_by_id(role.role_id)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    assert_eq!(updated_role.name, new_name);
    assert_eq!(
        updated_role.description,
        Some("New description".to_string())
    );
}

#[tokio::test]
async fn test_delete_role() {
    let repo = RoleRepo::new();
    let role = create_role(&uniq("delete_role")).await;

    repo.delete(role.role_id)
        .await
        .expect("Failed to delete role");

    let deleted_role = repo.get_by_id(role.role_id).await.expect("Query failed");

    assert!(deleted_role.is_none(), "Role should be deleted");
}

#[tokio::test]
async fn test_set_permissions() {
    let repo = RoleRepo::new();
    let role = create_role(&uniq("admin_with_perms")).await;

    repo.set_permissions(role.role_id, RolePermissions::Admin)
        .await
        .expect("Failed to set permissions");

    let updated_role = repo
        .get_by_id(role.role_id)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    assert_eq!(updated_role.get_permissions(), Some(RolePermissions::Admin));
}

#[tokio::test]
async fn test_add_permission() {
    let repo = RoleRepo::new();
    let role = create_role(&uniq("multi_perm_role")).await;

    repo.set_permissions(role.role_id, RolePermissions::Read)
        .await
        .expect("Set failed");

    repo.add_permission(role.role_id, RolePermissions::Write)
        .await
        .expect("Add failed");

    let updated_role = repo
        .get_by_id(role.role_id)
        .await
        .expect("Get failed")
        .expect("Not found");

    let perms = updated_role.get_all_permissions();
    assert!(perms.contains(&RolePermissions::Read));
    assert!(perms.contains(&RolePermissions::Write));
    assert_eq!(perms.len(), 2);
}
