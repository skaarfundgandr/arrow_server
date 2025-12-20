use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
use arrow_server_lib::data::models::schema::orders::dsl::orders;
use arrow_server_lib::data::models::schema::products::dsl::products;
use arrow_server_lib::data::models::roles::{NewRole, RolePermissions, UpdateRole};
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use diesel::result;
use diesel_async::RunQueryDsl;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::user_roles::dsl::*;
    use arrow_server_lib::data::models::schema::roles::dsl::roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(roles).execute(&mut conn).await?;
    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_role() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let new_role = NewRole {
        name: "admin",
        description: Some("Administrator role"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name("admin")
        .await
        .expect("Failed to get role")
        .expect("No role found");

    assert_eq!(role.name, "admin");
    assert_eq!(role.description, Some("Administrator role".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_roles() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let roles = repo.get_all().await.expect("Failed to get all roles");

    assert_eq!(roles, None, "Expected no roles in the database");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_id() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let new_role = NewRole {
        name: "customer",
        description: None,
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name("customer")
        .await
        .expect("Failed to get role")
        .expect("No role found");

    let role_id = role.role_id;

    let fetched_role = repo
        .get_by_id(role_id)
        .await
        .expect("Failed to get by id")
        .expect("Role not found by id");

    assert_eq!(fetched_role.name, "customer");
    assert_eq!(fetched_role.role_id, role_id);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let result = repo.get_by_id(99999).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name_not_found() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let result = repo
        .get_by_name("nonexistent_role")
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent role name");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_role() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let new_role = NewRole {
        name: "old_role",
        description: Some("Old description"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name("old_role")
        .await
        .expect("Failed to get role")
        .expect("No role found");

    let role_id = role.role_id;

    let update_form = UpdateRole {
        name: Some("new_role"),
        description: Some("New description"),
    };

    repo.update(role_id, update_form)
        .await
        .expect("Failed to update role");

    let updated_role = repo
        .get_by_id(role_id)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    assert_eq!(updated_role.name, "new_role");
    assert_eq!(
        updated_role.description,
        Some("New description".to_string())
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_role() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let new_role = NewRole {
        name: "delete_role",
        description: None,
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name("delete_role")
        .await
        .expect("Failed to get role")
        .expect("No role found");

    let role_id = role.role_id;

    repo.delete(role_id).await.expect("Failed to delete role");

    let deleted_role = repo.get_by_id(role_id).await.expect("Query failed");

    assert!(deleted_role.is_none(), "Role should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_set_permissions() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let new_role = NewRole {
        name: "admin_with_perms",
        description: Some("Admin with permissions"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name("admin_with_perms")
        .await
        .expect("Failed to get role")
        .expect("No role found");

    let role_id = role.role_id;

    // Set permissions using the new method
    repo.set_permissions(role_id, RolePermissions::Admin)
        .await
        .expect("Failed to set permissions");

    // Verify permissions were set
    let updated_role = repo
        .get_by_id(role_id)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    assert_eq!(updated_role.get_permissions(), Some(RolePermissions::Admin));
}

#[tokio::test]
#[serial_test::serial]
async fn test_add_permission() {
    setup().await.expect("Setup failed");

    let repo = RoleRepo::new();

    let new_role = NewRole {
        name: "multi_perm_role",
        description: None,
    };
    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name("multi_perm_role")
        .await
        .expect("Get failed")
        .expect("Not found");

    // Set initial
    repo.set_permissions(role.role_id, RolePermissions::Read)
        .await
        .expect("Set failed");

    // Add another
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
