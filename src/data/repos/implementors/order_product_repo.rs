use crate::data::database::Database;
use crate::data::models::order_product::{NewOrderProduct, OrderProduct, UpdateOrderProduct};
use crate::data::repos::traits::repository::Repository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::result;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};

/// Composite key for OrderProduct (order_id, product_id)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderProductId {
    pub order_id: i32,
    pub product_id: i32,
}

pub struct OrderProductRepo {}

impl OrderProductRepo {
    pub fn new() -> Self {
        OrderProductRepo {}
    }

    /// Retrieves all order products for a specific order.
    pub async fn get_by_order_id(
        &self,
        order_id_query: i32,
    ) -> Result<Option<Vec<OrderProduct>>, result::Error> {
        use crate::data::models::schema::order_products::dsl::{order_id, order_products};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match order_products
            .filter(order_id.eq(order_id_query))
            .load::<OrderProduct>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Retrieves all order products for a specific product.
    pub async fn get_by_product_id(
        &self,
        product_id_query: i32,
    ) -> Result<Option<Vec<OrderProduct>>, result::Error> {
        use crate::data::models::schema::order_products::dsl::{order_products, product_id};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match order_products
            .filter(product_id.eq(product_id_query))
            .load::<OrderProduct>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl Repository for OrderProductRepo {
    type Id = OrderProductId;
    type Item = OrderProduct;
    type NewItem<'a> = NewOrderProduct;
    type UpdateForm<'a> = UpdateOrderProduct;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::order_products::dsl::order_products;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match order_products.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::order_products::dsl::{
            order_id, order_products, product_id,
        };

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match order_products
            .filter(order_id.eq(id.order_id))
            .filter(product_id.eq(id.product_id))
            .first::<Self::Item>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::order_products::dsl::order_products;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::insert_into(order_products)
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
        use crate::data::models::schema::order_products::dsl::{
            order_id, order_products, product_id,
        };

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::update(
                    order_products
                        .filter(order_id.eq(id.order_id))
                        .filter(product_id.eq(id.product_id)),
                )
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
        use crate::data::models::schema::order_products::dsl::{
            order_id, order_products, product_id,
        };

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::delete(
                    order_products
                        .filter(order_id.eq(id.order_id))
                        .filter(product_id.eq(id.product_id)),
                )
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

impl Default for OrderProductRepo {
    fn default() -> Self {
        Self::new()
    }
}
