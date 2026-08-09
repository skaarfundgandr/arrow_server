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
use arrow_server_lib::services::blob_storage_service::{BlobStore, BlobStoreError};
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::AsyncMysqlConnection;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

static CUSTOMER_ROLE: Once = Once::new();
pub async fn ensure_customer_role() {
    CUSTOMER_ROLE.call_once(|| {
        std::thread::spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("Failed to build CUSTOMER role runtime");
            rt.block_on(async {
                let repo = RoleRepo::new();
                if repo.get_by_name("CUSTOMER").await.ok().flatten().is_some() {
                    return;
                }
                if repo
                    .add(NewRole {
                        name: "CUSTOMER",
                        description: Some("Default customer role"),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                if let Ok(Some(role)) = repo.get_by_name("CUSTOMER").await {
                    let _ = repo.set_permissions(role.role_id, RolePermissions::Write).await;
                }
            });
            std::mem::forget(rt);
        })
        .join()
        .expect("CUSTOMER role pre-seed thread panicked");
    });
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlobCall {
    Upload { bytes_len: usize, content_type: String },
    Delete { blob_name: String },
    Mint { blob_name: String, ttl_minutes: u64 },
}

#[derive(Debug, Default)]
pub struct StubBlobStore {
    calls: Mutex<Vec<BlobCall>>,
    name_counter: AtomicU64,
    fail_deletes: AtomicBool,
}

impl StubBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_deletes(&self, fail: bool) {
        self.fail_deletes.store(fail, Ordering::SeqCst);
    }

    pub fn calls(&self) -> Vec<BlobCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl BlobStore for StubBlobStore {
    async fn upload(&self, bytes: &[u8], content_type: &str) -> Result<String, BlobStoreError> {
        self.calls.lock().unwrap().push(BlobCall::Upload {
            bytes_len: bytes.len(),
            content_type: content_type.to_string(),
        });
        let n = self.name_counter.fetch_add(1, Ordering::Relaxed);
        Ok(format!("products/00000000-0000-4000-8000-{:012}.png", n))
    }

    async fn delete(&self, blob_name: &str) -> Result<(), BlobStoreError> {
        self.calls.lock().unwrap().push(BlobCall::Delete {
            blob_name: blob_name.to_string(),
        });
        if self.fail_deletes.load(Ordering::SeqCst) {
            Err(BlobStoreError::Delete("stub delete failure".to_string()))
        } else {
            Ok(())
        }
    }

    async fn mint_read_url(
        &self,
        blob_name: &str,
        ttl_minutes: u64,
    ) -> Result<String, BlobStoreError> {
        self.calls.lock().unwrap().push(BlobCall::Mint {
            blob_name: blob_name.to_string(),
            ttl_minutes,
        });
        Ok(format!(
            "https://stub.blob.core.windows.net/{blob_name}?sig=stub&ttl={ttl_minutes}"
        ))
    }

    fn is_configured(&self) -> bool {
        true
    }
}

pub fn png_bytes() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01, 0x02, 0x03,
    ]
}

pub fn jpeg_bytes() -> Vec<u8> {
    vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01]
}

pub fn webp_bytes() -> Vec<u8> {
    vec![b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P']
}

pub fn gif_bytes() -> Vec<u8> {
    vec![b'G', b'I', b'F', b'8', b'9', b'a', 0, 0]
}
