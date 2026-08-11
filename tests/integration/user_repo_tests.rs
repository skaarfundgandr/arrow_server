use arrow_server_lib::data::models::user::{NewUser, UpdateUser};
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;

use crate::common::{create_user, uniq};

#[tokio::test]
async fn test_create_user() {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let raw_password = "securepassword";
    let hashed = auth
        .hash_password(raw_password)
        .await
        .expect("Password hashing failed");

    let username = uniq("testuser");
    let test_user = NewUser {
        username: &username,
        password_hash: &hashed,
    };

    assert!(
        auth.verify_password(raw_password, &hashed)
            .await
            .expect("Password verification failed")
    );

    repo.add(test_user).await.expect("Failed to add test_user");

    let db_user = repo
        .get_by_username(&username)
        .await
        .expect("Failed to retrieve test_user")
        .expect("test_user not found in database");

    assert_eq!(db_user.username, username);
}

#[tokio::test]
async fn test_get_by_id() {
    let repo = UserRepo::new();
    let user = create_user(&uniq("getbyid_user")).await;

    let fetched_user = repo
        .get_by_id(user.user_id)
        .await
        .expect("Failed to get by id")
        .expect("User not found by id");

    assert_eq!(fetched_user.username, user.username);
    assert_eq!(fetched_user.user_id, user.user_id);
}

#[tokio::test]
async fn test_get_by_id_not_found() {
    let repo = UserRepo::new();

    let result = repo.get_by_id(i32::MAX - 42).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent user");
}

#[tokio::test]
async fn test_update_user() {
    let auth = AuthService::new();
    let repo = UserRepo::new();
    let user = create_user(&uniq("update_user")).await;

    let new_hashed = auth
        .hash_password("newpassword")
        .await
        .expect("Hashing failed");

    let new_username = uniq("updated_username");
    let update_form = UpdateUser {
        username: Some(&new_username),
        password_hash: Some(&new_hashed),
    };

    repo.update(user.user_id, update_form)
        .await
        .expect("Failed to update user");

    let updated_user = repo
        .get_by_id(user.user_id)
        .await
        .expect("Failed to get user")
        .expect("User not found");

    assert_eq!(updated_user.username, new_username);
    assert!(
        auth.verify_password("newpassword", &updated_user.password_hash)
            .await
            .expect("Verification failed")
    );
}

#[tokio::test]
async fn test_update_user_partial() {
    let auth = AuthService::new();
    let repo = UserRepo::new();
    let user = create_user(&uniq("partial_update_user")).await;

    let new_username = uniq("new_partial_name");
    let update_form = UpdateUser {
        username: Some(&new_username),
        password_hash: None,
    };

    repo.update(user.user_id, update_form)
        .await
        .expect("Failed to update user");

    let updated_user = repo
        .get_by_id(user.user_id)
        .await
        .expect("Failed to get user")
        .expect("User not found");

    assert_eq!(updated_user.username, new_username);
    assert!(
        auth.verify_password("testpass", &updated_user.password_hash)
            .await
            .expect("Verification failed"),
        "Password should remain unchanged"
    );
}

#[tokio::test]
async fn test_delete_user() {
    let repo = UserRepo::new();
    let user = create_user(&uniq("delete_user")).await;

    repo.delete(user.user_id)
        .await
        .expect("Failed to delete user");

    let deleted_user = repo.get_by_id(user.user_id).await.expect("Query failed");

    assert!(deleted_user.is_none(), "User should be deleted");
}

#[tokio::test]
async fn test_get_all_with_users() {
    let repo = UserRepo::new();
    let user1 = create_user(&uniq("user_one")).await;
    let user2 = create_user(&uniq("user_two")).await;

    let users = repo
        .get_all()
        .await
        .expect("Failed to get all users")
        .expect("Expected users");

    let usernames: Vec<&str> = users.iter().map(|u| u.username.as_str()).collect();
    assert!(usernames.contains(&user1.username.as_str()));
    assert!(usernames.contains(&user2.username.as_str()));
}

#[tokio::test]
async fn test_get_by_username_not_found() {
    let repo = UserRepo::new();

    let result = repo
        .get_by_username(&uniq("missing_user"))
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent username");
}
