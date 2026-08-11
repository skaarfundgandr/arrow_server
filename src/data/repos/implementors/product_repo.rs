use crate::data::database::Database;
use crate::data::models::product::{NewProduct, Product, UpdateProduct};
use crate::data::repos::traits::repository::Repository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::result;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};

pub struct ProductRepo {}

impl ProductRepo {
    pub fn new() -> Self {
        ProductRepo {}
    }

    /// Retrieves a product by its name.
    pub async fn get_by_name(&self, name_query: &str) -> Result<Option<Product>, result::Error> {
        use crate::data::models::schema::products::dsl::{name, products};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match products
            .filter(name.eq(name_query))
            .first::<Product>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl Repository for ProductRepo {
    type Id = i32;
    type Item = Product;
    type NewItem<'a> = NewProduct<'a>;
    type UpdateForm<'a> = UpdateProduct<'a>;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::products::dsl::products;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match products.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::products::dsl::{product_id, products};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match products
            .filter(product_id.eq(id))
            .first::<Self::Item>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::products::dsl::products;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::insert_into(products)
                    .values(&item)
                    .execute(connection)
                    .await?;
                Ok(())
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn update<'a>(
        &self,
        id: Self::Id,
        item: Self::UpdateForm<'a>,
    ) -> Result<(), result::Error> {
        use crate::data::models::schema::products::dsl::{product_id, products};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::update(products.filter(product_id.eq(id)))
                    .set(&item)
                    .execute(connection)
                    .await?;
                Ok(())
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, id: Self::Id) -> Result<(), result::Error> {
        use crate::data::models::schema::products::dsl::{product_id, products};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::delete(products.filter(product_id.eq(id)))
                    .execute(connection)
                    .await?;
                Ok(())
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Default for ProductRepo {
    fn default() -> Self {
        Self::new()
    }
}
