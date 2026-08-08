use diesel_async::AsyncMysqlConnection;
use diesel_async::pooled_connection::deadpool::{BuildError, Object, Pool, PoolError};
use diesel_async::pooled_connection::{AsyncDieselConnectionManager};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use std::env;

#[derive(Debug)]
pub enum DatabaseError {
    MissingVar,
    PoolBuild(BuildError),
    PoolGet(PoolError),
    PoolUnavailable,
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::MissingVar => write!(f, "DATABASE_URL must be set"),
            DatabaseError::PoolBuild(e) => {
                write!(f, "Failed to create database connection pool: {}", e)
            }
            DatabaseError::PoolGet(e) => {
                write!(f, "Failed to acquire database connection: {}", e)
            }
            DatabaseError::PoolUnavailable => write!(f, "Database connection pool unavailable"),
        }
    }
}

impl std::error::Error for DatabaseError {}

pub struct Database {
    pool: Option<Pool<AsyncMysqlConnection>>,
}

impl Database {
    pub async fn new() -> Self {
        Database {
            pool: DB_POOL.as_ref().ok().cloned(),
        }
    }

    pub async fn get_connection(
        &self,
    ) -> Result<Object<AsyncMysqlConnection>, DatabaseError> {
        match &self.pool {
            Some(pool) => pool.get().await.map_err(DatabaseError::PoolGet),
            None => Err(DatabaseError::PoolUnavailable),
        }
    }
}
/// Lazily initialized global database connection pool
static DB_POOL: Lazy<Result<Pool<AsyncMysqlConnection>, DatabaseError>> = Lazy::new(|| {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").map_err(|_| DatabaseError::MissingVar)?;

    let config = AsyncDieselConnectionManager::<AsyncMysqlConnection>::new(database_url);
    let pool = Pool::builder(config)
        .build()
        .map_err(DatabaseError::PoolBuild)?;

    tracing::info!("DB connection pool created");

    Ok(pool)
});
