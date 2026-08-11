use arrow_server_lib::data::models::order::UpdateOrder;
use arrow_server_lib::data::repos::implementors::order_repo::OrderRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use bigdecimal::BigDecimal;
use std::str::FromStr;

use crate::common::{create_order, create_product, create_user, create_user_with_role, uniq};

#[tokio::test]
async fn test_create_order() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order = create_order(user.user_id, product.product_id, "20.00", "pending").await;

    assert_eq!(order.user_id, Some(user.user_id));
    assert_eq!(order.total_amount, BigDecimal::from_str("20.00").unwrap());
    assert_eq!(order.status, "pending".to_string());

    let orders = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    assert_eq!(orders.len(), 1);

    let detailed = repo
        .attach_products(orders)
        .await
        .expect("Failed to attach");
    assert_eq!(detailed[0].1.len(), 1);
    assert_eq!(detailed[0].1[0].0.quantity, 1);
    assert_eq!(
        detailed[0].1[0].0.unit_price,
        BigDecimal::from_str("20.00").unwrap()
    );
}

#[tokio::test]
async fn test_get_order_by_id() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order = create_order(user.user_id, product.product_id, "10.00", "confirmed").await;

    let fetched_order = repo
        .get_by_id(order.order_id)
        .await
        .expect("Failed to get by id")
        .expect("Order not found by id");

    assert_eq!(fetched_order.order_id, order.order_id);
    assert_eq!(fetched_order.user_id, Some(user.user_id));
}

#[tokio::test]
async fn test_get_order_by_id_not_found() {
    let repo = OrderRepo::new();

    let result = repo.get_by_id(i32::MAX - 42).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent order");
}

#[tokio::test]
async fn test_get_orders_by_user_id() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order1 = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let order2 = create_order(user.user_id, product.product_id, "30.00", "completed").await;

    let orders = repo
        .get_by_user_id(user.user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    assert_eq!(orders.len(), 2);

    let order_ids: Vec<i32> = orders.iter().map(|o| o.order_id).collect();
    assert!(order_ids.contains(&order1.order_id));
    assert!(order_ids.contains(&order2.order_id));
}

#[tokio::test]
async fn test_get_orders_by_user_id_not_found() {
    let repo = OrderRepo::new();

    let result = repo
        .get_by_user_id(i32::MAX - 43)
        .await
        .expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent user orders"
    );
}

#[tokio::test]
async fn test_get_orders_by_role_name() {
    let role_name = uniq("Customer");
    let (user, _role) = create_user_with_role(&uniq("role_user"), &role_name).await;
    let product = create_product(&uniq("role_product")).await;
    let repo = OrderRepo::new();

    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;

    let orders = repo
        .get_orders_by_role_name(&role_name)
        .await
        .expect("Failed query")
        .expect("No orders");
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].order_id, order.order_id);

    let orders_none = repo
        .get_orders_by_role_name(&uniq("nobody"))
        .await
        .expect("Failed query");
    assert!(orders_none.is_none());
}

#[tokio::test]
async fn test_get_orders_by_status() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order1 = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let order2 = create_order(user.user_id, product.product_id, "20.00", "completed").await;
    let order3 = create_order(user.user_id, product.product_id, "30.00", "pending").await;

    let pending_orders = repo
        .get_by_status("pending")
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    let pending_ids: Vec<i32> = pending_orders.iter().map(|o| o.order_id).collect();
    assert!(pending_ids.contains(&order1.order_id));
    assert!(pending_ids.contains(&order3.order_id));

    let completed_orders = repo
        .get_by_status("completed")
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    let completed_ids: Vec<i32> = completed_orders.iter().map(|o| o.order_id).collect();
    assert!(completed_ids.contains(&order2.order_id));
}

#[tokio::test]
async fn test_get_orders_by_status_not_found() {
    let repo = OrderRepo::new();

    let result = repo
        .get_by_status(&uniq("nonexistent_status"))
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent status");
}

#[tokio::test]
async fn test_update_order() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;

    let update_form = UpdateOrder {
        user_id: None,
        total_amount: Some(BigDecimal::from_str("50.00").unwrap()),
        status: Some("completed"),
        payment_status: None,
    };

    repo.update(order.order_id, update_form)
        .await
        .expect("Failed to update order");

    let updated_order = repo
        .get_by_id(order.order_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(
        updated_order.total_amount,
        BigDecimal::from_str("50.00").unwrap()
    );
    assert_eq!(updated_order.status, "completed".to_string());
}

#[tokio::test]
async fn test_update_order_partial() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order = create_order(user.user_id, product.product_id, "20.00", "pending").await;

    let update_form = UpdateOrder {
        user_id: None,
        total_amount: None,
        status: Some("shipped"),
        payment_status: None,
    };

    repo.update(order.order_id, update_form)
        .await
        .expect("Failed to update order");

    let updated_order = repo
        .get_by_id(order.order_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(
        updated_order.total_amount,
        BigDecimal::from_str("20.00").unwrap(),
        "Total amount should remain unchanged"
    );
    assert_eq!(updated_order.status, "shipped".to_string());
}

#[tokio::test]
async fn test_delete_order() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;

    repo.delete(order.order_id)
        .await
        .expect("Failed to delete order");

    let deleted_order = repo.get_by_id(order.order_id).await.expect("Query failed");

    assert!(deleted_order.is_none(), "Order should be deleted");
}

#[tokio::test]
async fn test_get_all_with_orders() {
    let user = create_user(&uniq("order_user")).await;
    let product = create_product(&uniq("order_product")).await;
    let repo = OrderRepo::new();

    let order1 = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let order2 = create_order(user.user_id, product.product_id, "20.00", "completed").await;

    let orders = repo
        .get_all()
        .await
        .expect("Failed to get all orders")
        .expect("Expected orders");

    let order_ids: Vec<i32> = orders.iter().map(|o| o.order_id).collect();
    assert!(order_ids.contains(&order1.order_id));
    assert!(order_ids.contains(&order2.order_id));
}
