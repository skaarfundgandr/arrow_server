use crate::data::database::Database;
use crate::data::models::roles::{NewRole, Role, UpdateRole};
use crate::data::repos::traits::repository::Repository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::result;
use diesel_async::pooled_connection::deadpool::Object;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncMysqlConnection, RunQueryDsl};

pub struct RoleRepo {}

impl RoleRepo {
    pub fn new() -> Self {
        RoleRepo {}
    }

    pub async fn get_by_name(&self, name_val: &str) -> Result<Option<Role>, result::Error> {
        use crate::data::models::schema::roles::dsl::{name, roles};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match roles.filter(name.eq(name_val)).first::<Role>(&mut conn).await {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn set_permissions(
        &self,
        id: i32,
        perm: crate::data::models::roles::RolePermissions,
    ) -> Result<(), result::Error> {
        use diesel::sql_query;
        use diesel::sql_types::{Integer, Text};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        conn.transaction(|connection| {
            async move {
                sql_query("UPDATE roles SET permissions = ? WHERE role_id = ?")
                    .bind::<Text, _>(perm.as_str())
                    .bind::<Integer, _>(id)
                    .execute(connection)
                    .await?;
                Ok(())
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn add_permission(
        &self,
        id: i32,
        perm: crate::data::models::roles::RolePermissions,
    ) -> Result<(), result::Error> {
        use diesel::sql_query;
        use diesel::sql_types::{Integer, Text};

        let role = self.get_by_id(id).await?;
        let role = match role {
            Some(r) => r,
            None => return Err(result::Error::NotFound),
        };

        if role.has_permission(perm) {
            return Ok(());
        }

        let mut perms = role.get_all_permissions();
        perms.push(perm);

        let perm_str = perms
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(",");

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        conn.transaction(|connection| {
            async move {
                sql_query("UPDATE roles SET permissions = ? WHERE role_id = ?")
                    .bind::<Text, _>(perm_str)
                    .bind::<Integer, _>(id)
                    .execute(connection)
                    .await?;
                Ok(())
            }
            .scope_boxed()
        })
        .await
    }
}

#[async_trait]
impl Repository for RoleRepo {
    type Id = i32;
    type Item = Role;
    type NewItem<'a> = NewRole<'a>;
    type UpdateForm<'a> = UpdateRole<'a>;

    async fn get_all(&self) -> Result<Option<Vec<Self::Item>>, result::Error> {
        use crate::data::models::schema::roles::dsl::roles;

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match roles.load::<Self::Item>(&mut conn).await {
            Ok(value) if value.is_empty() => Ok(None),
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_by_id(&self, id: Self::Id) -> Result<Option<Self::Item>, result::Error> {
        use crate::data::models::schema::roles::dsl::{role_id, roles};

        let db = Database::new().await;

        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        match roles.filter(role_id.eq(id)).first::<Self::Item>(&mut conn).await {
            Ok(value) => Ok(Some(value)),
            Err(result::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn add<'a>(&self, item: Self::NewItem<'a>) -> Result<(), result::Error> {
        use crate::data::models::schema::roles::dsl::roles;

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
                    diesel::insert_into(roles)
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
        use crate::data::models::schema::roles::dsl::{role_id, roles};

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
                    diesel::update(roles.filter(role_id.eq(id)))
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
        use crate::data::models::schema::roles::dsl::{role_id, roles};

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
                    diesel::delete(roles.filter(role_id.eq(id)))
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

impl Default for RoleRepo {
    fn default() -> Self {
        Self::new()
    }
}
