use crate::data::database::Database;
use crate::data::models::product_category::*;
use crate::data::repos::traits::repository::Repository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::result;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};

pub struct ProductCategoryRepo;

impl ProductCategoryRepo {
    pub fn new() -> Self {
        ProductCategoryRepo
    }

    pub async fn get_products_by_category_id(
        &self,
        id: i32,
    ) -> Result<Option<Vec<crate::data::models::product::Product>>, result::Error> {
        use crate::data::models::schema::product_categories::dsl::{
            category_id, product_categories,
        };
        use crate::data::models::schema::products::dsl::products;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match product_categories
            .filter(category_id.eq(id))
            .inner_join(products)
            .select(crate::data::models::product::Product::as_select())
            .load::<crate::data::models::product::Product>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn get_categories_by_product_id(
        &self,
        id: i32,
    ) -> Result<Option<Vec<crate::data::models::categories::Category>>, result::Error> {
        use crate::data::models::schema::categories::dsl::categories;
        use crate::data::models::schema::product_categories::dsl::{
            product_categories, product_id,
        };

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match product_categories
            .filter(product_id.eq(id))
            .inner_join(categories)
            .select(crate::data::models::categories::Category::as_select())
            .load::<crate::data::models::categories::Category>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn delete_by_product_id(&self, product_id: i32) -> Result<(), result::Error> {
        use crate::data::models::schema::product_categories::dsl::{
            product_categories, product_id as pc_product_id,
        };

        let db = Database::new().await;

        let mut conn = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::delete(product_categories.filter(pc_product_id.eq(product_id)))
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

#[async_trait]
impl Repository for ProductCategoryRepo {
    type Id = (i32, i32);
    type Item = ProductCategory;
    type NewItem<'a> = NewProductCategory<'a>;
    type UpdateForm<'a> = UpdateProductCategory<'a>;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::product_categories::dsl::product_categories;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match product_categories.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::product_categories::dsl::{
            category_id, product_categories, product_id,
        };

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match product_categories
            .filter(product_id.eq(id.0))
            .filter(category_id.eq(id.1))
            .first::<Self::Item>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::product_categories::dsl::product_categories;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match conn
            .transaction(async |connection| {
                diesel::insert_into(product_categories)
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
        use crate::data::models::schema::product_categories::dsl::{
            category_id, product_categories, product_id,
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
                    product_categories
                        .filter(product_id.eq(id.0))
                        .filter(category_id.eq(id.1)),
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
        use crate::data::models::schema::product_categories::dsl::{
            category_id, product_categories, product_id,
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
                    product_categories
                        .filter(product_id.eq(id.0))
                        .filter(category_id.eq(id.1)),
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

impl Default for ProductCategoryRepo {
    fn default() -> Self {
        Self::new()
    }
}
