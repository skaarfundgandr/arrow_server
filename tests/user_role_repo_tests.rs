use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::user::{NewUser, User};
use arrow_server_lib::data::models::user_roles::{NewUserRole, UpdateUserRole};
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::services::auth_service::AuthService;
use diesel::result;
use diesel_async::RunQueryDsl;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::user_roles::dsl::*;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_test_user() -> User {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("testpass").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username: "role_test_user",
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username("role_test_user")
        .await
        .expect("Failed to get user")
        .expect("User not found")
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_user_role() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id: user.user_id,
        name: "admin",
        description: Some("Administrator role"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let roles = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles")
        .expect("No roles found");

    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "admin");
    assert_eq!(roles[0].description, Some("Administrator role".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_user_roles() {
    setup().await.expect("Setup failed");

    let repo = UserRoleRepo::new();

    let roles = repo.get_all().await.expect("Failed to get all roles");

    assert_eq!(roles, None, "Expected no roles in the database");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_id() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id: user.user_id,
        name: "customer",
        description: None,
    };

    repo.add(new_role).await.expect("Failed to add role");

    let roles = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles")
        .expect("No roles found");

    let role_id = roles[0].role_id;

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

    let repo = UserRoleRepo::new();

    let result = repo.get_by_id(99999).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id: user.user_id,
        name: "employee",
        description: Some("Employee role"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let fetched_role = repo
        .get_by_name("employee")
        .await
        .expect("Failed to get by name")
        .expect("Role not found by name");

    assert_eq!(fetched_role.name, "employee");
    assert_eq!(fetched_role.description, Some("Employee role".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_role_by_name_not_found() {
    setup().await.expect("Setup failed");

    let repo = UserRoleRepo::new();

    let result = repo
        .get_by_name("nonexistent_role")
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent role name");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_user_role() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id: user.user_id,
        name: "old_role",
        description: Some("Old description"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let roles = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles")
        .expect("No roles found");

    let role_id = roles[0].role_id;

    let update_form = UpdateUserRole {
        user_id: None,
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
async fn test_update_user_role_partial() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id: user.user_id,
        name: "partial_role",
        description: Some("Keep this description"),
    };

    repo.add(new_role).await.expect("Failed to add role");

    let roles = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles")
        .expect("No roles found");

    let role_id = roles[0].role_id;

    let update_form = UpdateUserRole {
        user_id: None,
        name: Some("updated_partial_role"),
        description: None,
    };

    repo.update(role_id, update_form)
        .await
        .expect("Failed to update role");

    let updated_role = repo
        .get_by_id(role_id)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    assert_eq!(updated_role.name, "updated_partial_role");
    assert_eq!(
        updated_role.description,
        Some("Keep this description".to_string()),
        "Description should remain unchanged"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_user_role() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id: user.user_id,
        name: "delete_role",
        description: None,
    };

    repo.add(new_role).await.expect("Failed to add role");

    let roles = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles")
        .expect("No roles found");

    let role_id = roles[0].role_id;

    repo.delete(role_id).await.expect("Failed to delete role");

    let deleted_role = repo.get_by_id(role_id).await.expect("Query failed");

    assert!(deleted_role.is_none(), "Role should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_with_roles() {
    setup().await.expect("Setup failed");

    let user = create_test_user().await;
    let repo = UserRoleRepo::new();

    repo.add(NewUserRole {
        user_id: user.user_id,
        name: "role_one",
        description: None,
    })
    .await
    .expect("Failed to add role1");

    repo.add(NewUserRole {
        user_id: user.user_id,
        name: "role_two",
        description: Some("Second role"),
    })
    .await
    .expect("Failed to add role2");

    let roles = repo
        .get_all()
        .await
        .expect("Failed to get all roles")
        .expect("Expected roles");

    assert_eq!(roles.len(), 2);

    let role_names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
    assert!(role_names.contains(&"role_one"));
    assert!(role_names.contains(&"role_two"));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_by_user_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = UserRoleRepo::new();

    let result = repo.get_by_user_id(99999).await.expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent user_id roles"
    );
}
