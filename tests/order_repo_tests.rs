use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::order::{NewOrder, UpdateOrder};
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::repos::implementors::order_repo::OrderRepo;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
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
    use arrow_server_lib::data::models::schema::roles::dsl::roles;

    // Clean up in order due to foreign key constraints
    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
    diesel::delete(roles).execute(&mut conn).await?;
    diesel::delete(users).execute(&mut conn).await?;

    Ok(())
}

async fn create_test_user() -> i32 {
    let auth = AuthService::new();
    let repo = UserRepo::new();

    let hashed = match auth.hash_password("testpass").await {
        Ok(h) => h,
        Err(_) => panic!("Hashing failed"),
    };

    let test_user = NewUser {
        username: "order_test_user",
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username("order_test_user")
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id
}

async fn create_test_product() -> i32 {
    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name: "TestProduct",
        product_image_uri: None,
        description: Some("Test product for orders"),
        price: BigDecimal::from_str("10.00").unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    repo.get_by_name("TestProduct")
        .await
        .expect("Failed to get product")
        .expect("Product not found")
        .product_id
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    let new_order = NewOrder {
        user_id,
        product_id,
        quantity: 2,
        total_amount: BigDecimal::from_str("20.00").unwrap(),
        status: Some("pending".to_string()),
    };

    repo.add(new_order).await.expect("Failed to add order");

    let orders = repo
        .get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].user_id, user_id);
    assert_eq!(orders[0].product_id, product_id);
    assert_eq!(orders[0].quantity, 2);
    assert_eq!(
        orders[0].total_amount,
        BigDecimal::from_str("20.00").unwrap()
    );
    assert_eq!(orders[0].status, Some("pending".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_orders_empty() {
    setup().await.expect("Setup failed");

    let repo = OrderRepo::new();

    let orders = repo.get_all().await.expect("Failed to get all orders");

    assert_eq!(orders, None, "Expected no orders in the database");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_by_id() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    let new_order = NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("confirmed".to_string()),
    };

    repo.add(new_order).await.expect("Failed to add order");

    let orders = repo
        .get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    let order_id = orders[0].order_id;

    let fetched_order = repo
        .get_by_id(order_id)
        .await
        .expect("Failed to get by id")
        .expect("Order not found by id");

    assert_eq!(fetched_order.order_id, order_id);
    assert_eq!(fetched_order.user_id, user_id);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_by_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = OrderRepo::new();

    let result = repo.get_by_id(99999).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent order");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_user_id() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    })
    .await
    .expect("Failed to add order1");

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 3,
        total_amount: BigDecimal::from_str("30.00").unwrap(),
        status: Some("completed".to_string()),
    })
    .await
    .expect("Failed to add order2");

    let orders = repo
        .get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    assert_eq!(orders.len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_user_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = OrderRepo::new();

    let result = repo.get_by_user_id(99999).await.expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent user orders"
    );
}

async fn create_test_role(role_name: &str, user_id: i32) {
    let role_repo = RoleRepo::new();
    let user_role_repo = UserRoleRepo::new();
    
    let new_role = arrow_server_lib::data::models::roles::NewRole {
        name: role_name,
        description: None,
    };
    role_repo.add(new_role).await.expect("Failed to add role");
    
    let role = role_repo.get_by_name(role_name).await.expect("Failed to get role").expect("Role not found");
    
    user_role_repo.add_user_role(user_id, role.role_id).await.expect("Failed to assign role");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_role_name() {
    setup().await.expect("Setup failed");
    let user_id = create_test_user().await;
    create_test_role("Customer", user_id).await;

    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    })
    .await
    .expect("Failed to add order");

    let orders = repo
        .get_orders_by_role_name("Customer")
        .await
        .expect("Failed query")
        .expect("No orders");
    assert_eq!(orders.len(), 1);

    let orders_none = repo
        .get_orders_by_role_name("Admin")
        .await
        .expect("Failed query");
    assert!(orders_none.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_status() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    })
    .await
    .expect("Failed to add order1");

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 2,
        total_amount: BigDecimal::from_str("20.00").unwrap(),
        status: Some("completed".to_string()),
    })
    .await
    .expect("Failed to add order2");

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 3,
        total_amount: BigDecimal::from_str("30.00").unwrap(),
        status: Some("pending".to_string()),
    })
    .await
    .expect("Failed to add order3");

    let pending_orders = repo
        .get_by_status("pending")
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    assert_eq!(pending_orders.len(), 2);

    let completed_orders = repo
        .get_by_status("completed")
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    assert_eq!(completed_orders.len(), 1);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_orders_by_status_not_found() {
    setup().await.expect("Setup failed");

    let repo = OrderRepo::new();

    let result = repo
        .get_by_status("nonexistent")
        .await
        .expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent status");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    let new_order = NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    };

    repo.add(new_order).await.expect("Failed to add order");

    let orders = repo
        .get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    let order_id = orders[0].order_id;

    let update_form = UpdateOrder {
        user_id: None,
        product_id: None,
        quantity: Some(5),
        total_amount: Some(BigDecimal::from_str("50.00").unwrap()),
        status: Some("completed"),
    };

    repo.update(order_id, update_form)
        .await
        .expect("Failed to update order");

    let updated_order = repo
        .get_by_id(order_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(updated_order.quantity, 5);
    assert_eq!(
        updated_order.total_amount,
        BigDecimal::from_str("50.00").unwrap()
    );
    assert_eq!(updated_order.status, Some("completed".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order_partial() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    let new_order = NewOrder {
        user_id,
        product_id,
        quantity: 2,
        total_amount: BigDecimal::from_str("20.00").unwrap(),
        status: Some("pending".to_string()),
    };

    repo.add(new_order).await.expect("Failed to add order");

    let orders = repo
        .get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    let order_id = orders[0].order_id;

    let update_form = UpdateOrder {
        user_id: None,
        product_id: None,
        quantity: None,
        total_amount: None,
        status: Some("shipped"),
    };

    repo.update(order_id, update_form)
        .await
        .expect("Failed to update order");

    let updated_order = repo
        .get_by_id(order_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found");

    assert_eq!(
        updated_order.quantity, 2,
        "Quantity should remain unchanged"
    );
    assert_eq!(
        updated_order.total_amount,
        BigDecimal::from_str("20.00").unwrap(),
        "Total amount should remain unchanged"
    );
    assert_eq!(updated_order.status, Some("shipped".to_string()));
}

#[tokio::test]
#[serial_test::serial]
async fn test_delete_order() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    let new_order = NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    };

    repo.add(new_order).await.expect("Failed to add order");

    let orders = repo
        .get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found");

    let order_id = orders[0].order_id;

    repo.delete(order_id).await.expect("Failed to delete order");

    let deleted_order = repo.get_by_id(order_id).await.expect("Query failed");

    assert!(deleted_order.is_none(), "Order should be deleted");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_all_with_orders() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product().await;
    let repo = OrderRepo::new();

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 1,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    })
    .await
    .expect("Failed to add order1");

    repo.add(NewOrder {
        user_id,
        product_id,
        quantity: 2,
        total_amount: BigDecimal::from_str("20.00").unwrap(),
        status: Some("completed".to_string()),
    })
    .await
    .expect("Failed to add order2");

    let orders = repo
        .get_all()
        .await
        .expect("Failed to get all orders")
        .expect("Expected orders");

    assert_eq!(orders.len(), 2);
}