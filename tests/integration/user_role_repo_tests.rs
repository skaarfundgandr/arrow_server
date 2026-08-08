use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;

use crate::common::{create_role, create_user, uniq};

#[tokio::test]
async fn test_add_user_role() {
    let user = create_user(&uniq("user1")).await;
    let role = create_role(&uniq("role1")).await;
    let repo = UserRoleRepo::new();

    repo.add_user_role(user.user_id, role.role_id)
        .await
        .expect("Failed to add user role");

    let roles = repo
        .get_roles_by_user_id(user.user_id)
        .await
        .expect("Failed to get roles");

    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].role_id, role.role_id);
}

#[tokio::test]
async fn test_remove_user_role() {
    let user = create_user(&uniq("user2")).await;
    let role = create_role(&uniq("role2")).await;
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
async fn test_get_roles_by_user_id_multiple() {
    let user = create_user(&uniq("user3")).await;
    let role1 = create_role(&uniq("roleA")).await;
    let role2 = create_role(&uniq("roleB")).await;
    let repo = UserRoleRepo::new();

    repo.add_user_role(user.user_id, role1.role_id)
        .await
        .expect("Failed");

    let err = repo.add_user_role(user.user_id, role2.role_id).await;

    assert!(err.is_err());
}
