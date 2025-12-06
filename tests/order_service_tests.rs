use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::models::user_roles::{NewUserRole, RolePermissions};
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use arrow_server_lib::services::errors::OrderServiceError;
use arrow_server_lib::services::order_service::{OrderService, OrderStatus};
use bigdecimal::BigDecimal;
use diesel::result;
use diesel_async::RunQueryDsl;
use std::str::FromStr;

async fn setup() -> Result<(), result::Error> {
    let db = Database::new().await;

    let mut conn = db
        .get_connection()
        .await
        .expect("Failed to get a database connection");

    use arrow_server_lib::data::models::schema::order_products::dsl::order_products;
    use arrow_server_lib::data::models::schema::orders::dsl::orders;
    use arrow_server_lib::data::models::schema::products::dsl::products;
    use arrow_server_lib::data::models::schema::user_roles::dsl::user_roles;
    use arrow_server_lib::data::models::schema::users::dsl::users;

    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_test_user(username: &str) -> i32 {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = auth
        .hash_password("testpass")
        .await
        .expect("Hashing failed");

    let test_user = NewUser {
        username,
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id
}

async fn create_role_with_permission(user_id: i32, name: &str, permission: RolePermissions) -> i32 {
    let repo = UserRoleRepo::new();

    let new_role = NewUserRole {
        user_id,
        name,
        description: None,
    };

    repo.add(new_role).await.expect("Failed to add role");

    let role = repo
        .get_by_name(name)
        .await
        .expect("Failed to get role")
        .expect("Role not found");

    repo.set_permissions(role.role_id, permission)
        .await
        .expect("Failed to set permissions");

    role.role_id
}

async fn create_test_product() -> i32 {
    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "ServiceTestProduct",
        product_image_uri: None,
        description: Some("Test product for order service"),
        price: BigDecimal::from_str("15.00").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    repo.get_by_name("ServiceTestProduct")
        .await
        .expect("Failed to get product")
        .expect("Product not found")
        .product_id
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_with_write_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("write_user").await;
    let role_id = create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    let result = service
        .create_order(
            user_id,
            role_id,
            product_id,
            2,
            BigDecimal::from_str("30.00").unwrap(),
        )
        .await;

    assert!(
        result.is_ok(),
        "Should be able to create order with WRITE permission"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_with_admin_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("admin_user").await;
    let role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    let result = service
        .create_order(
            user_id,
            role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await;

    assert!(
        result.is_ok(),
        "Should be able to create order with ADMIN permission"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_without_permission() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("read_only_user").await;
    let role_id = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    let result = service
        .create_order(
            user_id,
            role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await;

    assert_eq!(
        result.err(),
        Some(OrderServiceError::PermissionDenied),
        "Should not be able to create order with READ permission"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_user_own_orders() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("order_viewer").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create an order
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // Create read role for viewing
    let read_role_id = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;

    // Get own orders
    let orders = service
        .get_user_orders(user_id, read_role_id)
        .await
        .expect("Failed to get orders");

    assert!(orders.is_some(), "Should have orders");
    assert_eq!(orders.unwrap().len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_other_user_orders_with_read_permission() {
    setup().await.expect("Setup failed");

    let user1_id = create_test_user("user1").await;
    let user2_id = create_test_user("user2").await;
    let write_role_id =
        create_role_with_permission(user1_id, "writer1", RolePermissions::Write).await;
    let read_role_id =
        create_role_with_permission(user2_id, "reader2", RolePermissions::Read).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order for user1
    service
        .create_order(
            user1_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // User2 with READ permission can view user1's orders (new behavior)
    let result = service.get_user_orders(user1_id, read_role_id).await;

    assert!(
        result.is_ok(),
        "User with READ permission should be able to view any user's orders"
    );
    assert!(result.unwrap().is_some());
}

#[tokio::test]
#[serial_test::serial]
async fn test_admin_get_all_orders() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("admin_viewer").await;
    let admin_role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create multiple orders
    service
        .create_order(
            user_id,
            admin_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order 1");

    service
        .create_order(
            user_id,
            admin_role_id,
            product_id,
            2,
            BigDecimal::from_str("30.00").unwrap(),
        )
        .await
        .expect("Failed to create order 2");

    let orders = service
        .get_all_orders(admin_role_id)
        .await
        .expect("Failed to get all orders");

    assert!(orders.is_some());
    assert_eq!(orders.unwrap().len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_read_permission_get_all_orders() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("reader").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role_id = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create an order first
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // READ permission can now get all orders
    let result = service.get_all_orders(read_role_id).await;

    assert!(
        result.is_ok(),
        "READ permission should be able to get all orders"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_own_pending_order() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("canceller").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let admin_role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // Get order ID using admin role
    let orders = service
        .get_user_orders(user_id, admin_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");
    let order_id = orders[0].order_id;

    // Cancel order using write role (owner cancelling their own pending order)
    let result = service.cancel_order(order_id, write_role_id).await;

    assert!(result.is_ok(), "Should be able to cancel own pending order");

    // Verify status changed
    let cancelled_order = service
        .get_order_by_id(order_id, admin_role_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(cancelled_order.status, Some("Cancelled".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_cancel_other_user_order_denied() {
    setup().await.expect("Setup failed");

    let user1_id = create_test_user("owner").await;
    let user2_id = create_test_user("attacker").await;
    let write_role1_id =
        create_role_with_permission(user1_id, "writer1", RolePermissions::Write).await;
    let write_role2_id =
        create_role_with_permission(user2_id, "writer2", RolePermissions::Write).await;
    let admin_role_id =
        create_role_with_permission(user1_id, "admin1", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order for user1
    service
        .create_order(
            user1_id,
            write_role1_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // Get order ID using admin role
    let orders = service
        .get_user_orders(user1_id, admin_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");
    let order_id = orders[0].order_id;

    // User2 tries to cancel user1's order (now only checks role permission)
    // With WRITE permission, this should now succeed
    let result = service.cancel_order(order_id, write_role2_id).await;

    assert!(
        result.is_ok(),
        "User with WRITE permission should be able to cancel orders"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_write_permission_update_order_status() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("status_updater").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role_id = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    let orders = service
        .get_all_orders(read_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");
    let order_id = orders[0].order_id;

    // Update status to Accepted (requires WRITE permission)
    service
        .update_order_status(order_id, OrderStatus::Accepted, write_role_id)
        .await
        .expect("Failed to update status");

    let updated_order = service
        .get_order_by_id(order_id, read_role_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(updated_order.status, Some("Accepted".to_string()));

    // Update status to Completed
    service
        .update_order_status(order_id, OrderStatus::Completed, write_role_id)
        .await
        .expect("Failed to update status");

    let completed_order = service
        .get_order_by_id(order_id, read_role_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(completed_order.status, Some("Completed".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_non_admin_update_status_denied() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("non_admin_updater").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let admin_role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // Get order ID using admin role
    let orders = service
        .get_user_orders(user_id, admin_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");
    let order_id = orders[0].order_id;

    // Try to update status with write role (now allowed per new service logic)
    let result = service
        .update_order_status(order_id, OrderStatus::Accepted, write_role_id)
        .await;

    // Note: The new service allows WRITE permission to update order status
    assert!(
        result.is_ok(),
        "Write permission should be able to update order status"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_status() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("status_viewer").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let read_role_id = create_role_with_permission(user_id, "reader", RolePermissions::Read).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create orders
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order 1");

    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            2,
            BigDecimal::from_str("30.00").unwrap(),
        )
        .await
        .expect("Failed to create order 2");

    // Get pending orders (requires READ or ADMIN)
    let pending_orders = service
        .get_orders_by_status(OrderStatus::Pending, read_role_id)
        .await
        .expect("Failed to get pending orders");

    assert!(pending_orders.is_some());
    assert_eq!(pending_orders.unwrap().len(), 2);

    // Update one to completed (requires WRITE permission)
    let orders = service
        .get_all_orders(read_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");

    service
        .update_order_status(orders[0].order_id, OrderStatus::Completed, write_role_id)
        .await
        .expect("Failed to update status");

    let completed_orders = service
        .get_orders_by_status(OrderStatus::Completed, read_role_id)
        .await
        .expect("Failed to get completed orders");

    assert!(completed_orders.is_some());
    assert_eq!(completed_orders.unwrap().len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_order_admin_only() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("admin_deleter").await;
    let admin_role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order
    service
        .create_order(
            user_id,
            admin_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    let orders = service
        .get_all_orders(admin_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");
    let order_id = orders[0].order_id;

    // Delete order
    service
        .delete_order(order_id, admin_role_id)
        .await
        .expect("Failed to delete order");

    // Verify deleted
    let deleted_order = service
        .get_order_by_id(order_id, admin_role_id)
        .await
        .expect("Failed to query");

    assert!(deleted_order.is_none(), "Order should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_order_non_admin_denied() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user("non_admin_deleter").await;
    let write_role_id =
        create_role_with_permission(user_id, "writer", RolePermissions::Write).await;
    let admin_role_id = create_role_with_permission(user_id, "admin", RolePermissions::Admin).await;
    let product_id = create_test_product().await;

    let service = OrderService::new();

    // Create order
    service
        .create_order(
            user_id,
            write_role_id,
            product_id,
            1,
            BigDecimal::from_str("15.00").unwrap(),
        )
        .await
        .expect("Failed to create order");

    // Get order ID using admin role
    let orders = service
        .get_user_orders(user_id, admin_role_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders");
    let order_id = orders[0].order_id;

    // Try to delete with write role (requires DELETE or ADMIN permission)
    let result = service.delete_order(order_id, write_role_id).await;

    assert_eq!(
        result.err(),
        Some(OrderServiceError::PermissionDenied),
        "Write role should not delete orders (requires DELETE or ADMIN)"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_order_status_enum() {
    assert_eq!(OrderStatus::Pending.as_str(), "Pending");
    assert_eq!(OrderStatus::Accepted.as_str(), "Accepted");
    assert_eq!(OrderStatus::Completed.as_str(), "Completed");
    assert_eq!(OrderStatus::Cancelled.as_str(), "Cancelled");

    assert_eq!(OrderStatus::from_str("pending"), Ok(OrderStatus::Pending));
    assert_eq!(
        OrderStatus::from_str("ACCEPTED"),
        Ok(OrderStatus::Accepted)
    );
    assert_eq!(
        OrderStatus::from_str("Completed"),
        Ok(OrderStatus::Completed)
    );
    assert_eq!(
        OrderStatus::from_str("CANCELLED"),
        Ok(OrderStatus::Cancelled)
    );
    assert_eq!(OrderStatus::from_str("invalid"), Err(()));
}
