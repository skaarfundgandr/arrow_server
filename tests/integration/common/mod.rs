use arrow_server_lib::data::database::Database;
use diesel_async::AsyncMysqlConnection;
use diesel_async::pooled_connection::deadpool::Object;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn uniq(prefix: &str) -> String {
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
