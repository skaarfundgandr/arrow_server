use std::collections::HashMap;
use crate::data::database::Database;
use crate::data::models::order::{NewOrder, Order, UpdateOrder};
use crate::data::models::order_product::{NewOrderProduct, OrderProduct};
use crate::data::models::product::Product;
use crate::data::repos::traits::repository::Repository;
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use diesel::prelude::*;
use diesel::result;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};

pub struct OrderRepo {}

impl OrderRepo {
    pub fn new() -> Self {
        OrderRepo {}
    }

    /// Retrieves all orders for a specific user by user_id.
    pub async fn get_by_user_id(
        &self,
        user_id_query: i32,
    ) -> Result<Option<Vec<Order>>, result::Error> {
        use crate::data::models::schema::orders::dsl::{orders, user_id};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match orders
            .filter(user_id.eq(user_id_query))
            .load::<Order>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Retrieves all orders with a specific status.
    pub async fn get_by_status(
        &self,
        status_query: &str,
    ) -> Result<Option<Vec<Order>>, result::Error> {
        use crate::data::models::schema::orders::dsl::{orders, status};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match orders
            .filter(status.eq(status_query))
            .load::<Order>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Retrieves all orders for users with a specific role name.
    pub async fn get_orders_by_role_name(
        &self,
        role: &str,
    ) -> Result<Option<Vec<Order>>, result::Error> {
        use crate::data::models::schema::orders::dsl::{orders, user_id};
        use crate::data::models::schema::user_roles::dsl::{
            user_id as role_user_id, user_roles,
        };
        use crate::data::models::schema::roles::dsl::{
            roles, name as role_name
        };

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        // Find user_ids with the given role
        // user_roles belongs_to roles
        let user_ids = user_roles
            .inner_join(roles)
            .filter(role_name.eq(role))
            .select(role_user_id)
            .load::<i32>(&mut conn)
            .await?;

        if user_ids.is_empty() {
            return Ok(None);
        }

        match orders
            .filter(user_id.eq_any(user_ids))
            .load::<Order>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn create_with_items(
        &self,
        new_order: NewOrder,
        items: Vec<(i32, i32, BigDecimal)>,
    ) -> Result<(), result::Error> {
        use crate::data::models::schema::orders::dsl::{orders};
        use crate::data::models::schema::order_products::dsl::order_products;

        let db = Database::new().await;
        let mut conn = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        conn.transaction::<_, result::Error, _>(|connection| {
            async move {
                diesel::insert_into(orders)
                    .values(&new_order)
                    .execute(connection)
                    .await?;

                let new_id: i32 = diesel::select(diesel::dsl::sql::<diesel::sql_types::Integer>("LAST_INSERT_ID()"))
                    .get_result(connection)
                    .await?;

                let new_items: Vec<NewOrderProduct> = items.into_iter().map(|(pid, qty, price)| {
                    NewOrderProduct {
                        order_id: new_id,
                        product_id: pid,
                        quantity: qty,
                        unit_price: price,
                    }
                }).collect();

                diesel::insert_into(order_products)
                    .values(&new_items)
                    .execute(connection)
                    .await?;

                Ok(())
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn attach_products(
        &self,
        orders_list: Vec<Order>,
    ) -> Result<Vec<(Order, Vec<(OrderProduct, Product)>)>, result::Error> {
        if orders_list.is_empty() {
            return Ok(Vec::new());
        }

        use crate::data::models::schema::order_products::dsl::{order_products, order_id};
        use crate::data::models::schema::products::dsl::products;

        let db = Database::new().await;
        let mut conn = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        let ids: Vec<i32> = orders_list.iter().map(|o| o.order_id).collect();

        let items_data: Vec<(OrderProduct, Product)> = order_products
            .inner_join(products)
            .filter(order_id.eq_any(ids))
            .load::<(OrderProduct, Product)>(&mut conn)
            .await?;

        let mut map: HashMap<i32, Vec<(OrderProduct, Product)>> = HashMap::new();
        
        for item in items_data {
            map.entry(item.0.order_id).or_default().push(item);
        }

        let result = orders_list.into_iter().map(|o| {
            let items = map.remove(&o.order_id).unwrap_or_default();
            (o, items)
        }).collect();

        Ok(result)
    }
}

#[async_trait]
impl Repository for OrderRepo {
    type Id = i32;
    type Item = Order;
    type NewItem<'a> = NewOrder;
    type UpdateForm<'a> = UpdateOrder<'a>;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::orders::dsl::orders;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match orders.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::orders::dsl::{order_id, orders};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match orders
            .filter(order_id.eq(id))
            .first::<Self::Item>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::orders::dsl::orders;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(|connection| {
                async move {
                    diesel::insert_into(orders)
                        .values(&item)
                        .execute(connection)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
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
        use crate::data::models::schema::orders::dsl::{order_id, orders};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(|connection| {
                async move {
                    diesel::update(orders.filter(order_id.eq(id)))
                        .set(&item)
                        .execute(connection)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, id: Self::Id) -> Result<(), result::Error> {
        use crate::data::models::schema::orders::dsl::{order_id, orders};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(|connection| {
                async move {
                    diesel::delete(orders.filter(order_id.eq(id)))
                        .execute(connection)
                        .await?;
                    Ok(())
                }
                .scope_boxed()
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

impl Default for OrderRepo {
    fn default() -> Self {
        Self::new()
    }
}
