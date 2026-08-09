use arrow_server_lib::data::database::Database;
use arrow_server_lib::data::models::categories::{Category, NewCategory};
use arrow_server_lib::data::models::order::{NewOrder, Order};
use arrow_server_lib::data::models::order_product::NewOrderProduct;
use arrow_server_lib::data::models::product::{NewProduct, Product};
use arrow_server_lib::data::models::product_category::NewProductCategory;
use arrow_server_lib::data::models::roles::{NewRole, Role, RolePermissions};
use arrow_server_lib::data::models::user::{NewUser, User};
use arrow_server_lib::data::repos::implementors::category_repo::CategoryRepo;
use arrow_server_lib::data::repos::implementors::order_product_repo::OrderProductRepo;
use arrow_server_lib::data::repos::implementors::order_repo::OrderRepo;
use arrow_server_lib::data::repos::implementors::product_category_repo::ProductCategoryRepo;
use arrow_server_lib::data::repos::implementors::product_repo::ProductRepo;
use arrow_server_lib::data::repos::implementors::role_repo::RoleRepo;
use arrow_server_lib::data::repos::implementors::user_repo::UserRepo;
use arrow_server_lib::data::repos::implementors::user_role_repo::UserRoleRepo;
use arrow_server_lib::data::repos::traits::repository::Repository;
use arrow_server_lib::security::auth::AuthService;
use bigdecimal::BigDecimal;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::AsyncMysqlConnection;
use std::str::FromStr;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);
static WARMED: Once = Once::new();

fn warm_up_pool() {
    WARMED.call_once(|| {
        std::thread::spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to build warm-up runtime");
            rt.block_on(async {
                let mut conns = Vec::new();
                for _ in 0..64 {
                    let db = Database::new().await;
                    match tokio::time::timeout(Duration::from_secs(2), db.get_connection()).await {
                        Ok(Ok(conn)) => conns.push(conn),
                        _ => break,
                    }
                }
                drop(conns);
            });
            std::mem::forget(rt);
        })
        .join()
        .expect("Pool warm-up thread panicked");
    });
}

pub fn uniq(prefix: &str) -> String {
    warm_up_pool();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    format!(
        "{prefix}-{}-{nanos}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub async fn get_conn() -> Object<AsyncMysqlConnection> {
    let db = Database::new().await;
    db.get_connection()
        .await
        .expect("Failed to get a database connection")
}

pub async fn create_product(name: &str) -> Product {
    let repo = ProductRepo::new();
    repo.add(NewProduct {
        name,
        product_image_uri: None,
        description: Some("Test product"),
        price: BigDecimal::from_str("9.99").unwrap(),
    })
    .await
    .expect("Failed to add product");
    repo.get_by_name(name)
        .await
        .expect("Failed to get product")
        .expect("Product not found")
}

pub async fn create_product_with_price(name: &str, price: &str) -> Product {
    let repo = ProductRepo::new();
    repo.add(NewProduct {
        name,
        product_image_uri: None,
        description: Some("Test product"),
        price: BigDecimal::from_str(price).unwrap(),
    })
    .await
    .expect("Failed to add product");
    repo.get_by_name(name)
        .await
        .expect("Failed to get product")
        .expect("Product not found")
}

pub async fn create_category(name: &str) -> Category {
    let repo = CategoryRepo::new();
    repo.add(NewCategory {
        name,
        description: Some("Test category"),
    })
    .await
    .expect("Failed to add category");
    repo.get_by_name(name)
        .await
        .expect("Failed to get category")
        .expect("Category not found")
}

pub async fn create_user(username: &str) -> User {
    let auth = AuthService::new();
    let repo = UserRepo::new();
    let hashed = auth
        .hash_password("testpass")
        .await
        .expect("Failed to hash password");
    repo.add(NewUser {
        username,
        password_hash: &hashed,
    })
    .await
    .expect("Failed to add user");
    repo.get_by_username(username)
        .await
        .expect("Failed to get user")
        .expect("User not found")
}

pub async fn create_role(name: &str) -> Role {
    let repo = RoleRepo::new();
    repo.add(NewRole {
        name,
        description: Some("Test role"),
    })
    .await
    .expect("Failed to add role");
    repo.get_by_name(name)
        .await
        .expect("Failed to get role")
        .expect("Role not found")
}

pub async fn create_role_with_permission(name: &str, perm: RolePermissions) -> Role {
    let role = create_role(name).await;
    RoleRepo::new()
        .set_permissions(role.role_id, perm)
        .await
        .expect("Failed to set permissions");
    role
}

pub async fn create_user_with_role(username: &str, role_name: &str) -> (User, Role) {
    let user = create_user(username).await;
    let role = create_role(role_name).await;
    UserRoleRepo::new()
        .add_user_role(user.user_id, role.role_id)
        .await
        .expect("Failed to assign role");
    (user, role)
}

pub async fn create_order(user_id: i32, product_id: i32, total_amount: &str, status: &str) -> Order {
    let repo = OrderRepo::new();
    let order_id = repo
        .create_with_items(
            NewOrder {
                user_id: Some(user_id),
                total_amount: BigDecimal::from_str(total_amount).unwrap(),
                status: status.to_string(),
            },
            vec![(
                product_id,
                1,
                BigDecimal::from_str(total_amount).unwrap(),
            )],
        )
        .await
        .expect("Failed to add order");
    repo.get_by_id(order_id)
        .await
        .expect("Failed to get order")
        .expect("Order not found")
}

pub async fn assign_product_to_category(product_id: i32, category_id: i32) {
    let repo = ProductCategoryRepo::new();
    repo.add(NewProductCategory {
        product_id: &product_id,
        category_id: &category_id,
    })
    .await
    .expect("Failed to add product category");
}

pub async fn add_order_product(order_id: i32, product_id: i32, quantity: i32, unit_price: &str) {
    let repo = OrderProductRepo::new();
    repo.add(NewOrderProduct {
        order_id,
        product_id,
        quantity,
        unit_price: BigDecimal::from_str(unit_price).unwrap(),
    })
    .await
    .expect("Failed to add order product");
}
