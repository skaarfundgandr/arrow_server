use crate::data::database::Database;
use crate::data::models::user_roles::{NewUserRole, UpdateUserRole, UserRole};
use crate::data::repos::traits::repository::Repository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::result;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};

pub struct UserRoleRepo {}

impl UserRoleRepo {
    pub fn new() -> Self {
        UserRoleRepo {}
    }

    /// Retrieves all roles for a specific user by user_id.
    /// # Arguments
    /// * `user_id_query` - The user ID to search for.
    /// # Returns
    /// * `Result<Option<Vec<UserRole>>, result::Error>` - Ok(Some(Vec)) if found, Ok(None) if not found, Err on error.
    pub async fn get_by_user_id(
        &self,
        user_id_query: i32,
    ) -> Result<Option<Vec<UserRole>>, result::Error> {
        use crate::data::models::schema::user_roles::dsl::{user_id, user_roles};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match user_roles
            .filter(user_id.eq(user_id_query))
            .load::<UserRole>(&mut conn)
            .await
        {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Retrieves a role by its name.
    /// # Arguments
    /// * `role_name` - The role name to search for.
    /// # Returns
    /// * `Result<Option<UserRole>, result::Error>` - Ok(Some(UserRole)) if found, Ok(None) if not found, Err on error.
    pub async fn get_by_name(&self, role_name: &str) -> Result<Option<UserRole>, result::Error> {
        use crate::data::models::schema::user_roles::dsl::{name, user_roles};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match user_roles
            .filter(name.eq(role_name))
            .first::<UserRole>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// TODO: Create tests
#[async_trait]
impl Repository for UserRoleRepo {
    type Id = i32;
    type Item = UserRole;
    type NewItem<'a> = NewUserRole<'a>;
    type UpdateForm<'a> = UpdateUserRole<'a>;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::user_roles::dsl::user_roles;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match user_roles.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::user_roles::dsl::{role_id, user_roles};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match user_roles
            .filter(role_id.eq(id))
            .first::<Self::Item>(&mut conn)
            .await
        {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::user_roles::dsl::user_roles;

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
                    diesel::insert_into(user_roles)
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
        use crate::data::models::schema::user_roles::dsl::{role_id, user_roles};

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
                    diesel::update(user_roles.filter(role_id.eq(id)))
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
        use crate::data::models::schema::user_roles::dsl::{role_id, user_roles};

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
                    diesel::delete(user_roles.filter(role_id.eq(id)))
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

impl Default for UserRoleRepo {
    fn default() -> Self {
        Self::new()
    }
}
