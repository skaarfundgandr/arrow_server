use arrow_server_lib::data::models::roles::RolePermissions;
use arrow_server_lib::services::errors::OrderServiceError;
use arrow_server_lib::services::order_service::{OrderService, OrderStatus};
use std::str::FromStr;

use crate::common::{create_product, create_role_with_permission, create_user, uniq};

#[tokio::test]
async fn test_create_order_with_write_permission() {
    let user_id = create_user(&uniq("write_user")).await.user_id;
    let _role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let result = service.create_order(Some(user_id), vec![(product_id, 2)]).await;

    assert!(
        result.is_ok(),
        "Should be able to create order with WRITE permission"
    );
}

#[tokio::test]
async fn test_create_order_with_admin_permission() {
    let user_id = create_user(&uniq("admin_user")).await.user_id;
    let _role_id = create_role_with_permission(&uniq("ow_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let result = service.create_order(Some(user_id), vec![(product_id, 1)]).await;

    assert!(
        result.is_ok(),
        "Should be able to create order with ADMIN permission"
    );
}

#[tokio::test]
async fn test_create_order_without_permission() {
    let user_id = create_user(&uniq("read_only_user")).await.user_id;
    let _role_id = create_role_with_permission(&uniq("ow_reader"), RolePermissions::Read)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let result = service.create_order(Some(user_id), vec![(product_id, 1)]).await;

    assert!(
        result.is_ok(),
        "Order creation is public and must not require any permission"
    );
}

#[tokio::test]
async fn test_get_user_own_orders() {
    let user_id = create_user(&uniq("order_viewer")).await.user_id;
    let _write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let read_role_id = create_role_with_permission(&uniq("ow_reader"), RolePermissions::Read)
        .await
        .role_id;

    let orders = service
        .get_user_orders(user_id, read_role_id)
        .await
        .expect("Failed to get orders")
        .expect("Should have orders");

    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].0.order_id, order_id);
}

#[tokio::test]
async fn test_get_other_user_orders_with_read_permission() {
    let user1_id = create_user(&uniq("user1")).await.user_id;
    let _write_role1_id = create_role_with_permission(&uniq("ow_writer1"), RolePermissions::Write)
        .await
        .role_id;
    let read_role_id = create_role_with_permission(&uniq("ow_reader2"), RolePermissions::Read)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user1_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let orders = service
        .get_user_orders(user1_id, read_role_id)
        .await
        .expect("User with READ permission should be able to view any user's orders")
        .expect("Should have orders");

    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].0.order_id, order_id);
}

#[tokio::test]
async fn test_admin_get_all_orders() {
    let user_id = create_user(&uniq("admin_viewer")).await.user_id;
    let admin_role_id = create_role_with_permission(&uniq("ow_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order1 = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order 1");

    let order2 = service
        .create_order(Some(user_id), vec![(product_id, 2)])
        .await
        .expect("Failed to create order 2");

    let orders = service
        .get_all_orders(admin_role_id)
        .await
        .expect("Failed to get all orders")
        .expect("No orders");

    let order_ids: Vec<i32> = orders.iter().map(|(o, _)| o.order_id).collect();
    assert!(order_ids.contains(&order1));
    assert!(order_ids.contains(&order2));
}

#[tokio::test]
async fn test_read_permission_get_all_orders() {
    let user_id = create_user(&uniq("reader")).await.user_id;
    let _write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role_id = create_role_with_permission(&uniq("ow_reader"), RolePermissions::Read)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let orders = service
        .get_all_orders(read_role_id)
        .await
        .expect("READ permission should be able to get all orders")
        .expect("No orders");

    assert!(orders.iter().any(|(o, _)| o.order_id == order_id));
}

#[tokio::test]
async fn test_cancel_own_pending_order() {
    let user_id = create_user(&uniq("canceller")).await.user_id;
    let write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let admin_role_id = create_role_with_permission(&uniq("ow_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let result = service.cancel_order(order_id, write_role_id).await;

    assert!(result.is_ok(), "Should be able to cancel own pending order");

    let (cancelled_order, _) = service
        .get_order_by_id(order_id, admin_role_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(cancelled_order.status, "Cancelled".to_string());
}

#[tokio::test]
async fn test_cancel_other_user_order_denied() {
    let user1_id = create_user(&uniq("owner")).await.user_id;
    let _write_role1_id = create_role_with_permission(&uniq("ow_writer1"), RolePermissions::Write)
        .await
        .role_id;
    let write_role2_id = create_role_with_permission(&uniq("ow_writer2"), RolePermissions::Write)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user1_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let result = service.cancel_order(order_id, write_role2_id).await;

    assert!(
        result.is_ok(),
        "User with WRITE permission should be able to cancel orders"
    );
}

#[tokio::test]
async fn test_write_permission_update_order_status() {
    let user_id = create_user(&uniq("status_updater")).await.user_id;
    let write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role_id = create_role_with_permission(&uniq("ow_reader"), RolePermissions::Read)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    service
        .update_order_status(order_id, OrderStatus::Accepted, write_role_id)
        .await
        .expect("Failed to update status");

    let (updated_order, _) = service
        .get_order_by_id(order_id, read_role_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(updated_order.status, "Accepted".to_string());

    service
        .update_order_status(order_id, OrderStatus::Completed, write_role_id)
        .await
        .expect("Failed to update status");

    let (completed_order, _) = service
        .get_order_by_id(order_id, read_role_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(completed_order.status, "Completed".to_string());
}

#[tokio::test]
async fn test_non_admin_update_status_denied() {
    let user_id = create_user(&uniq("non_admin_updater")).await.user_id;
    let write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let result = service
        .update_order_status(order_id, OrderStatus::Accepted, write_role_id)
        .await;

    assert!(
        result.is_ok(),
        "Write permission should be able to update order status"
    );
}

#[tokio::test]
async fn test_get_orders_by_status() {
    let user_id = create_user(&uniq("status_viewer")).await.user_id;
    let write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let read_role_id = create_role_with_permission(&uniq("ow_reader"), RolePermissions::Read)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order1 = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order 1");

    let order2 = service
        .create_order(Some(user_id), vec![(product_id, 2)])
        .await
        .expect("Failed to create order 2");

    let pending_orders = service
        .get_orders_by_status(OrderStatus::Pending, read_role_id)
        .await
        .expect("Failed to get pending orders")
        .expect("No orders");

    let pending_ids: Vec<i32> = pending_orders.iter().map(|(o, _)| o.order_id).collect();
    assert!(pending_ids.contains(&order1));
    assert!(pending_ids.contains(&order2));

    service
        .update_order_status(order1, OrderStatus::Completed, write_role_id)
        .await
        .expect("Failed to update status");

    let completed_orders = service
        .get_orders_by_status(OrderStatus::Completed, read_role_id)
        .await
        .expect("Failed to get completed orders")
        .expect("No orders");

    let completed_ids: Vec<i32> = completed_orders.iter().map(|(o, _)| o.order_id).collect();
    assert!(completed_ids.contains(&order1));
    assert!(!completed_ids.contains(&order2));
}

#[tokio::test]
async fn test_delete_order_admin_only() {
    let user_id = create_user(&uniq("admin_deleter")).await.user_id;
    let admin_role_id = create_role_with_permission(&uniq("ow_admin"), RolePermissions::Admin)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    service
        .delete_order(order_id, admin_role_id)
        .await
        .expect("Failed to delete order");

    let deleted_order = service
        .get_order_by_id(order_id, admin_role_id)
        .await
        .expect("Failed to query");

    assert!(deleted_order.is_none(), "Order should be deleted");
}

#[tokio::test]
async fn test_delete_order_non_admin_denied() {
    let user_id = create_user(&uniq("non_admin_deleter")).await.user_id;
    let write_role_id = create_role_with_permission(&uniq("ow_writer"), RolePermissions::Write)
        .await
        .role_id;
    let product_id = create_product(&uniq("ow_product")).await.product_id;

    let service = OrderService::new();

    let order_id = service
        .create_order(Some(user_id), vec![(product_id, 1)])
        .await
        .expect("Failed to create order");

    let result = service.delete_order(order_id, write_role_id).await;

    assert_eq!(
        result.err(),
        Some(OrderServiceError::PermissionDenied),
        "Write role should not delete orders (requires DELETE or ADMIN)"
    );
}

#[tokio::test]
async fn test_order_status_enum() {
    assert_eq!(OrderStatus::Pending.as_str(), "Pending");
    assert_eq!(OrderStatus::Accepted.as_str(), "Accepted");
    assert_eq!(OrderStatus::Completed.as_str(), "Completed");
    assert_eq!(OrderStatus::Cancelled.as_str(), "Cancelled");

    assert_eq!(OrderStatus::from_str("pending"), Ok(OrderStatus::Pending));
    assert_eq!(OrderStatus::from_str("ACCEPTED"), Ok(OrderStatus::Accepted));
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
