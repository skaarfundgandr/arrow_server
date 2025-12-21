use arrow_server_lib::data::database::*;
use arrow_server_lib::data::models::order::NewOrder;
use arrow_server_lib::data::models::order_product::{NewOrderProduct, UpdateOrderProduct};
use arrow_server_lib::data::models::product::NewProduct;
use arrow_server_lib::data::models::user::NewUser;
use arrow_server_lib::data::repos::implementors::order_product_repo::{
    OrderProductId, OrderProductRepo,
};
use arrow_server_lib::data::repos::implementors::order_repo::OrderRepo;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
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

    // Clean up in order due to foreign key constraints
    diesel::delete(order_products).execute(&mut conn).await?;
    diesel::delete(orders).execute(&mut conn).await?;
    diesel::delete(products).execute(&mut conn).await?;
    diesel::delete(user_roles).execute(&mut conn).await?;
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
        username: "order_product_test_user",
        password_hash: &hashed,
    };

    repo.add(test_user).await.expect("Failed to add user");

    repo.get_by_username("order_product_test_user")
        .await
        .expect("Failed to get user")
        .expect("User not found")
        .user_id
}

async fn create_test_product(name: &str, price: &str) -> i32 {
    let repo = ProductRepo::new();

    let new_product = NewProduct {
        name,
        product_image_uri: None,
        description: Some("Test product"),
        price: BigDecimal::from_str(price).unwrap(),
    };

    repo.add(new_product).await.expect("Failed to add product");

    repo.get_by_name(name)
        .await
        .expect("Failed to get product")
        .expect("Product not found")
        .product_id
}

async fn create_test_order(user_id: i32, product_id: i32) -> i32 {
    let repo = OrderRepo::new();

    let new_order = NewOrder {
        user_id,
        total_amount: BigDecimal::from_str("10.00").unwrap(),
        status: Some("pending".to_string()),
    };

    // We use create_with_items to ensure the order is created validly, 
    // but for some tests we might manually add more items later.
    repo.create_with_items(new_order, vec![(product_id, 1, BigDecimal::from(10))])
        .await
        .expect("Failed to add order");

    repo.get_by_user_id(user_id)
        .await
        .expect("Failed to get orders")
        .expect("No orders found")
        .last()
        .expect("No orders")
        .order_id
}

#[tokio::test]
#[serial_test::serial]
async fn test_create_order_product() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product("TestProductOP", "10.00").await;
    let order_id = create_test_order(user_id, product_id).await;
    let repo = OrderProductRepo::new();
    
    // create_test_order already adds an item. 
    // Let's create a NEW product to add manually to verify OrderProductRepo directly.
    let product_id_2 = create_test_product("TestProductOP2", "10.00").await;

    let new_order_product = NewOrderProduct {
        order_id,
        product_id: product_id_2,
        quantity: 3,
        unit_price: BigDecimal::from_str("10.00").unwrap(),
    };

    repo.add(new_order_product)
        .await
        .expect("Failed to add order product");

    let order_products = repo
        .get_by_order_id(order_id)
        .await
        .expect("Failed to get order products")
        .expect("No order products found");

    // Expect 2 items now (one from create_test_order, one added here)
    assert_eq!(order_products.len(), 2);
    
    // Find our new item
    let op = order_products.iter().find(|op| op.product_id == product_id_2).expect("Product not found");
    
    assert_eq!(op.order_id, order_id);
    assert_eq!(op.product_id, product_id_2);
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
#[serial_test::serial]
async fn test_get_all_order_products_empty() {
    setup().await.expect("Setup failed");

    let repo = OrderProductRepo::new();

    let order_products = repo
        .get_all()
        .await
        .expect("Failed to get all order products");

    assert_eq!(
        order_products, None,
        "Expected no order products in the database"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_product_by_id() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product("TestProductById", "15.00").await;
    let order_id = create_test_order(user_id, product_id).await;
    let repo = OrderProductRepo::new();

    // Add another product
    let product_id_2 = create_test_product("TestProductById2", "15.00").await;
    let new_order_product = NewOrderProduct {
        order_id,
        product_id: product_id_2,
        quantity: 2,
        unit_price: BigDecimal::from_str("15.00").unwrap(),
    };

    repo.add(new_order_product)
        .await
        .expect("Failed to add order product");

    let composite_id = OrderProductId {
        order_id,
        product_id: product_id_2,
    };

    let fetched_order_product = repo
        .get_by_id(composite_id)
        .await
        .expect("Failed to get by id")
        .expect("Order product not found by id");

    assert_eq!(fetched_order_product.order_id, order_id);
    assert_eq!(fetched_order_product.product_id, product_id_2);
    assert_eq!(fetched_order_product.quantity, 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_product_by_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id: 99999,
        product_id: 99999,
    };

    let result = repo.get_by_id(composite_id).await.expect("Query failed");

    assert!(
        result.is_none(),
        "Expected None for non-existent order product"
    );
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_products_by_order_id() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id1 = create_test_product("Product1OP", "10.00").await;
    let product_id2 = create_test_product("Product2OP", "20.00").await;
    
    // Create order with product 1
    let order_id = create_test_order(user_id, product_id1).await;
    let repo = OrderProductRepo::new();

    // Add product 2
    repo.add(NewOrderProduct {
        order_id,
        product_id: product_id2,
        quantity: 1,
        unit_price: BigDecimal::from_str("20.00").unwrap(),
    })
    .await
    .expect("Failed to add order product 2");

    let order_products = repo
        .get_by_order_id(order_id)
        .await
        .expect("Failed to get order products")
        .expect("No order products found");

    assert_eq!(order_products.len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_products_by_order_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = OrderProductRepo::new();

    let result = repo.get_by_order_id(99999).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent order");
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_products_by_product_id() {
    setup().await.expect("Setup failed");
    
    let product_id = create_test_product("SharedProduct", "15.00").await;
    let repo = OrderProductRepo::new();

    let order_products = repo
        .get_by_product_id(product_id)
        .await
        .expect("Failed to get order products");

    assert!(order_products.is_none());
}

#[tokio::test]
#[serial_test::serial]
async fn test_get_order_products_by_product_id_not_found() {
    setup().await.expect("Setup failed");

    let repo = OrderProductRepo::new();

    let result = repo.get_by_product_id(99999).await.expect("Query failed");

    assert!(result.is_none(), "Expected None for non-existent product");
}

#[tokio::test]
#[serial_test::serial]
async fn test_update_order_product() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product("UpdateTestProduct", "10.00").await;
    let order_id = create_test_order(user_id, product_id).await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id,
        product_id,
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
#[serial_test::serial]
async fn test_update_order_product_partial() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product("PartialUpdateProduct", "10.00").await;
    let order_id = create_test_order(user_id, product_id).await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id,
        product_id,
    };

    // Note: create_test_order creates with qty 1, unit price 10.00
    
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
#[serial_test::serial]
async fn test_delete_order_product() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product("DeleteTestProduct", "10.00").await;
    let order_id = create_test_order(user_id, product_id).await;
    let repo = OrderProductRepo::new();

    let composite_id = OrderProductId {
        order_id,
        product_id,
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
#[serial_test::serial]
async fn test_get_all_with_order_products() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id1 = create_test_product("AllProduct1", "10.00").await;
    let product_id2 = create_test_product("AllProduct2", "20.00").await;
    
    // Create order with p1
    let order_id = create_test_order(user_id, product_id1).await;
    let repo = OrderProductRepo::new();

    // Add p2
    repo.add(NewOrderProduct {
        order_id,
        product_id: product_id2,
        quantity: 2,
        unit_price: BigDecimal::from_str("20.00").unwrap(),
    })
    .await
    .expect("Failed to add order product 2");

    let order_products = repo
        .get_all()
        .await
        .expect("Failed to get all order products")
        .expect("Expected order products");

    assert_eq!(order_products.len(), 2);
}

#[tokio::test]
#[serial_test::serial]
async fn test_order_product_decimal_precision() {
    setup().await.expect("Setup failed");

    let user_id = create_test_user().await;
    let product_id = create_test_product("PrecisionProduct", "99.99").await;
    let order_id = create_test_order(user_id, product_id).await;
    let repo = OrderProductRepo::new();

    // Update the existing item to have higher qty, because create_test_order makes it with qty=1
    // Or we can verify the one created by create_test_order.
    
    let composite_id = OrderProductId {
        order_id,
        product_id,
    };
    
    // Let's update it to qty 3 and price 99.99 to verify precision
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