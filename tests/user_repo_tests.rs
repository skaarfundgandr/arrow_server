use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::user::{NewUser, UpdateUser};
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
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

    use arrow_server_lib::data::models::schema::users::dsl::*;
    use arrow_server_lib::data::models::schema::user_roles::dsl::*;

    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}
// TODO: Implement tests for user repository methods
#[tokio::test]
#[serial_test::serial]
async fn test_create_user() {
    setup().await.expect("Setup failed");

    let auth = AuthService::new();

    let raw_password = "securepassword";
    let hashed = match auth.hash_password(raw_password).await {
        Ok(h) => h,
        Err(_) => panic!("Password hashing failed"),
    };

    let user = "testuser";

    let test_user = NewUser {
        username: user,
        password_hash: &hashed,
    };

    assert_eq!(
        match auth.verify_password(raw_password, &hashed).await {
            Ok(valid) => valid,
            Err(_) => panic!("Password verification failed"),
        },
        true
    );

    let repo = UserRepo::new();

    match repo.add(test_user).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to add test_user"),
    };

    let db_user = match repo.get_by_username(user).await {
        Ok(user) => match user {
            Some(u) => u,
            None => panic!("test_user not found in database"),
        },
        Err(_) => panic!("Failed to retrieve test_user"),
    };

    assert_eq!(db_user.username, user);
}

#[serial_test::serial]
#[tokio::test]
async fn test_get_all_users() {
    setup().await.expect("Setup failed");

    let repo = UserRepo::new();

    let users = match repo.get_all().await {
        Ok(u) => u,
        Err(_) => panic!("Failed to get all users"),
    };

    assert_eq!(users, None, "Expected no users in the database");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_by_id() {
    setup().await.expect("Setup failed");

    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("password123").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username: "getbyid_user",
        password_hash: &hashed,
    };

    match repo.add(test_user).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to add user"),
    };

    let created_user = match repo.get_by_username("getbyid_user").await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found"),
        Err(_) => panic!("Failed to get user"),
    };

    let fetched_user = match repo.get_by_id(created_user.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found by id"),
        Err(_) => panic!("Failed to get by id"),
    };

    assert_eq!(fetched_user.username, "getbyid_user");
    assert_eq!(fetched_user.user_id, created_user.user_id);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_by_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = UserRepo::new();

    let result = match repo.get_by_id(99999).await {
        Ok(r) => r,
        Err(_) => panic!("Query failed"),
    };

    assert!(result.is_none(), "Expected None for non-existent user");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_user() {
    setup().await.expect("Setup failed");

    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("oldpassword").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username: "update_user",
        password_hash: &hashed,
    };

    match repo.add(test_user).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to add user"),
    };

    let created_user = match repo.get_by_username("update_user").await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found"),
        Err(_) => panic!("Failed to get user"),
    };

    let new_hashed = match auth.hash_password("newpassword").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let update_form = UpdateUser {
        username: Some("updated_username"),
        password_hash: Some(&new_hashed),
    };

    match repo.update(created_user.user_id, update_form).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to update user"),
    };

    let updated_user = match repo.get_by_id(created_user.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found"),
        Err(_) => panic!("Failed to get user"),
    };

    assert_eq!(updated_user.username, "updated_username");
    assert!(match auth
        .verify_password("newpassword", &updated_user.password_hash)
        .await
    {
        Ok(valid) => valid,
        Err(_) => panic!("Verification failed"),
    });
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_user_partial() {
    setup().await.expect("Setup failed");

    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("keepthis").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username: "partial_update_user",
        password_hash: &hashed,
    };

    match repo.add(test_user).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to add user"),
    };

    let created_user = match repo.get_by_username("partial_update_user").await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found"),
        Err(_) => panic!("Failed to get user"),
    };

    let update_form = UpdateUser {
        username: Some("new_partial_name"),
        password_hash: None,
    };

    match repo.update(created_user.user_id, update_form).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to update user"),
    };

    let updated_user = match repo.get_by_id(created_user.user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found"),
        Err(_) => panic!("Failed to get user"),
    };

    assert_eq!(updated_user.username, "new_partial_name");
    assert!(
        match auth
            .verify_password("keepthis", &updated_user.password_hash)
            .await
        {
            Ok(valid) => valid,
            Err(_) => panic!("Verification failed"),
        },
        "Password should remain unchanged"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_user() {
    setup().await.expect("Setup failed");

    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("deletepass").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username: "delete_user",
        password_hash: &hashed,
    };

    match repo.add(test_user).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to add user"),
    };

    let created_user = match repo.get_by_username("delete_user").await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("User not found"),
        Err(_) => panic!("Failed to get user"),
    };

    match repo.delete(created_user.user_id).await {
        Ok(_) => (),
        Err(_) => panic!("Failed to delete user"),
    };

    let deleted_user = match repo.get_by_id(created_user.user_id).await {
        Ok(r) => r,
        Err(_) => panic!("Query failed"),
    };

    assert!(deleted_user.is_none(), "User should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_with_users() {
    setup().await.expect("Setup failed");

    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed1 = match auth.hash_password("pass1").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };
    let hashed2 = match auth.hash_password("pass2").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    match repo
        .add(NewUser {
            username: "user_one",
            password_hash: &hashed1,
        })
        .await
    {
        Ok(_) => (),
        Err(_) => panic!("Failed to add user1"),
    };

    match repo
        .add(NewUser {
            username: "user_two",
            password_hash: &hashed2,
        })
        .await
    {
        Ok(_) => (),
        Err(_) => panic!("Failed to add user2"),
    };

    let users = match repo.get_all().await {
        Ok(Some(u)) => u,
        Ok(None) => panic!("Expected users"),
        Err(_) => panic!("Failed to get all users"),
    };

    assert_eq!(users.len(), 2);

    let usernames: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
    assert!(usernames.contains(&"user_one"));
    assert!(usernames.contains(&"user_two"));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_by_username_not_found() {
    setup().await.expect("Setup failed");

    let repo = UserRepo::new();

    let result = match repo.get_by_username("nonexistent_user").await {
        Ok(r) => r,
        Err(_) => panic!("Query failed"),
    };

    assert!(result.is_none(), "Expected None for non-existent username");
}
