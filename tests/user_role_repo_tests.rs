use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
use arrow_server_lib::data::models::schema::orders::dsl::orders;
use arrow_server_lib::data::models::schema::products::dsl::products;
use arrow_server_lib::data::models::user::{NewUser, User};
use arrow_server_lib::data::models::roles::{NewRole, Role};
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use diesel::result;
use diesel_async::RunQueryDsl;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
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

async fn create_test_user(username: &str) -> User {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("testpass").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username,
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
}

async fn create_test_role(name: &str) -> Role {
    let repo = RoleRepo::new();
    let new_role = NewRole {
        name,
        description: Some("Test Role"),
    };
    repo.add(new_role).await.expect("Failed to add role");
    repo.get_by_name(name).await.expect("Failed to get role").expect("Role not found")
}

#[tokio::test]
#[serial_test::serial]
async fn test_add_user_role() {
    setup().await.expect("Setup failed");

    let user = create_test_user("user1").await;
    let role = create_test_role("role1").await;
    let repo = UserRoleRepo::new();

    repo.add_user_role(user.user_id, role.role_id)
        .await
        .expect("Failed to add user role");

    let roles = repo
        .get_roles_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles");

    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "role1");
}

#[tokio::test]
#[serial_test::serial]
async fn test_remove_user_role() {
    setup().await.expect("Setup failed");

    let user = create_test_user("user2").await;
    let role = create_test_role("role2").await;
    let repo = UserRoleRepo::new();

    repo.add_user_role(user.user_id, role.role_id)
        .await
        .expect("Failed to add user role");

    repo.remove_user_role(user.user_id, role.role_id)
        .await
        .expect("Failed to remove user role");

    let roles = repo
        .get_roles_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles");

    assert!(roles.is_empty());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_roles_by_user_id_multiple() {
    setup().await.expect("Setup failed");

    let user = create_test_user("user3").await;
    let role1 = create_test_role("roleA").await;
    let role2 = create_test_role("roleB").await;
    let repo = UserRoleRepo::new();

    repo.add_user_role(user.user_id, role1.role_id).await.expect("Failed");
    let err = repo.add_user_role(user.user_id, role2.role_id).await; // this should fail due to unique constraint

    assert!(err.is_err());
}