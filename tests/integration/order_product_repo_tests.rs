use arrow_server_lib::data::models::order_product::UpdateOrderProduct;
use arrow_server_lib::data::repos::implementors::order_product_repo::{
    OrderProductId, OrderProductRepo,
};
use arrow_server_lib::data::repos::traits::repository::Repository;
use bigdecimal::BigDecimal;
use std::str::FromStr;

use crate::common::{
    add_order_product, create_order, create_product, create_user, uniq,
};

#[tokio::test]
async fn test_create_order_product() {
    let user = create_user(&uniq("op_user")).await;
    let product = create_product(&uniq("op_product")).await;
    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let product_2 = create_product(&uniq("op_product_2")).await;
    let repo = OrderProductRepo::new();

    add_order_product(order.order_id, product_2.product_id, 3, "10.00").await;

    let order_products = repo
        .get_by_order_id(order.order_id)
        .await
        .expect("Failed to get order products")
        .expect("No order products found");

    assert_eq!(order_products.len(), 2);

    let op = order_products
        .iter()
        .find(|op| op.product_id == product_2.product_id)
        .expect("Product not found");

    assert_eq!(op.order_id, order.order_id);
    assert_eq!(op.product_id, product_2.product_id);
    assert_eq!(op.quantity, 3);
    assert_eq!(
        op.unit_price,
        BigDecimal::from_str("10.00").unwrap()
    );
    assert_eq!(
        op.line_total,
        Some(BigDecimal::from_str("30.00").unwrap())
    );
}

#[tokio::test]
async fn test_get_order_product_by_id() {
    let user = create_user(&uniq("op_user")).await;
    let product = create_product(&uniq("op_product")).await;
    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let product_2 = create_product(&uniq("op_product_2")).await;
    let repo = OrderProductRepo::new();

    add_order_product(order.order_id, product_2.product_id, 2, "15.00").await;

    let composite_id = OrderProductId {
        order_id: order.order_id,
        product_id: product_2.product_id,
    };

    let fetched_order_product = repo
        .get_by_id(composite_id)
        .await
        .expect("Failed to get by id")
        .expect("Order product not found by id");

    assert_eq!(fetched_order_product.order_id, order.order_id);
    assert_eq!(fetched_order_product.product_id, product_2.product_id);
    assert_eq!(fetched_order_product.quantity, 2);
}

#[tokio::test]
async fn test_get_order_product_by_id_not_found() {
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id: i32::MAX - 42,
        product_id: i32::MAX - 43,
    };

    let result = repo.get_by_id(composite_id).await.expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent order product"
    );
}

#[tokio::test]
async fn test_get_order_products_by_order_id() {
    let user = create_user(&uniq("op_user")).await;
    let product_1 = create_product(&uniq("op_product_1")).await;
    let product_2 = create_product(&uniq("op_product_2")).await;
    let order = create_order(user.user_id, product_1.product_id, "10.00", "pending").await;
    let repo = OrderProductRepo::new();

    add_order_product(order.order_id, product_2.product_id, 1, "20.00").await;

    let order_products = repo
        .get_by_order_id(order.order_id)
        .await
        .expect("Failed to get order products")
        .expect("No order products found");

    assert_eq!(order_products.len(), 2);
}

#[tokio::test]
async fn test_get_order_products_by_order_id_not_found() {
    let repo = OrderProductRepo::new();

    let result = repo
        .get_by_order_id(i32::MAX - 44)
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent order");
}

#[tokio::test]
async fn test_get_order_products_by_product_id() {
    let product = create_product(&uniq("op_shared_product")).await;
    let repo = OrderProductRepo::new();

    let order_products = repo
        .get_by_product_id(product.product_id)
        .await
        .expect("Failed to get order products");

    assert!(order_products.is_none());
}

#[tokio::test]
async fn test_get_order_products_by_product_id_not_found() {
    let repo = OrderProductRepo::new();

    let result = repo
        .get_by_product_id(i32::MAX - 45)
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent product");
}

#[tokio::test]
async fn test_update_order_product() {
    let user = create_user(&uniq("op_user")).await;
    let product = create_product(&uniq("op_product")).await;
    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id: order.order_id,
        product_id: product.product_id,
    };

    let update_form = UpdateOrderProduct {
        quantity: Some(5),
        unit_price: Some(BigDecimal::from_str("12.00").unwrap()),
    };

    repo.update(composite_id, update_form)
        .await
        .expect("Failed to update order product");

    let updated_order_product = repo
        .get_by_id(composite_id)
        .await
        .expect("Failed to get order product")
        .expect("Order product not found");

    assert_eq!(updated_order_product.quantity, 5);
    assert_eq!(
        updated_order_product.unit_price,
        BigDecimal::from_str("12.00").unwrap()
    );
    assert_eq!(
        updated_order_product.line_total,
        Some(BigDecimal::from_str("60.00").unwrap())
    );
}

#[tokio::test]
async fn test_update_order_product_partial() {
    let user = create_user(&uniq("op_user")).await;
    let product = create_product(&uniq("op_product")).await;
    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id: order.order_id,
        product_id: product.product_id,
    };

    let update_form = UpdateOrderProduct {
        quantity: Some(4),
        unit_price: None,
    };

    repo.update(composite_id, update_form)
        .await
        .expect("Failed to update order product");

    let updated_order_product = repo
        .get_by_id(composite_id)
        .await
        .expect("Failed to get order product")
        .expect("Order product not found");

    assert_eq!(updated_order_product.quantity, 4);
    assert_eq!(
        updated_order_product.unit_price,
        BigDecimal::from_str("10.00").unwrap(),
        "Unit price should remain unchanged"
    );
    assert_eq!(
        updated_order_product.line_total,
        Some(BigDecimal::from_str("40.00").unwrap()),
        "Line total should remain unchanged"
    );
}

#[tokio::test]
async fn test_delete_order_product() {
    let user = create_user(&uniq("op_user")).await;
    let product = create_product(&uniq("op_product")).await;
    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id: order.order_id,
        product_id: product.product_id,
    };

    repo.delete(composite_id)
        .await
        .expect("Failed to delete order product");

    let deleted_order_product = repo.get_by_id(composite_id).await.expect("Query failed");

    assert!(
        deleted_order_product.is_none(),
        "Order product should be deleted"
    );
}

#[tokio::test]
async fn test_get_all_with_order_products() {
    let user = create_user(&uniq("op_user")).await;
    let product_1 = create_product(&uniq("op_product_1")).await;
    let product_2 = create_product(&uniq("op_product_2")).await;
    let order = create_order(user.user_id, product_1.product_id, "10.00", "pending").await;
    let repo = OrderProductRepo::new();

    add_order_product(order.order_id, product_2.product_id, 2, "20.00").await;

    let order_products = repo
        .get_all()
        .await
        .expect("Failed to get all order products")
        .expect("Expected order products");

    let keys: Vec<(i32, i32)> = order_products
        .iter()
        .map(|op| (op.order_id, op.product_id))
        .collect();
    assert!(keys.contains(&(order.order_id, product_1.product_id)));
    assert!(keys.contains(&(order.order_id, product_2.product_id)));
}

#[tokio::test]
async fn test_order_product_decimal_precision() {
    let user = create_user(&uniq("op_user")).await;
    let product = create_product(&uniq("op_precision_product")).await;
    let order = create_order(user.user_id, product.product_id, "10.00", "pending").await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id: order.order_id,
        product_id: product.product_id,
    };

    let update = UpdateOrderProduct {
        quantity: Some(3),
        unit_price: Some(BigDecimal::from_str("99.99").unwrap()),
    };
    repo.update(composite_id, update).await.expect("Failed update");

    let fetched = repo
        .get_by_id(composite_id)
        .await
        .expect("Failed to get order product")
        .expect("Order product not found");

    assert_eq!(fetched.unit_price, BigDecimal::from_str("99.99").unwrap());
    assert_eq!(
        fetched.line_total,
        Some(BigDecimal::from_str("299.97").unwrap())
    );
}
