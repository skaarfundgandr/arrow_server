use crate::data::database::Database;
use crate::data::models::roles::Role;
use crate::data::models::user_roles::{NewUserRole};
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

    pub async fn add_user_role(&self, user_id_val: i32, role_id_val: i32) -> Result<(), result::Error> {
        use crate::data::models::schema::user_roles::dsl::user_roles;

        let db = Database::new().await;
        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        let new_item = NewUserRole {
            user_id: user_id_val,
            role_id: role_id_val,
        };

        conn.transaction(|connection| {
            async move {
                diesel::insert_into(user_roles)
                    .values(&new_item)
                    .execute(connection)
                    .await?;
                Ok(())
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn remove_user_role(&self, user_id_val: i32, role_id_val: i32) -> Result<(), result::Error> {
        use crate::data::models::schema::user_roles::dsl::{role_id, user_id, user_roles};

        let db = Database::new().await;
        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        conn.transaction(|connection| {
            async move {
                diesel::delete(user_roles.filter(user_id.eq(user_id_val)).filter(role_id.eq(role_id_val)))
                    .execute(connection)
                    .await?;
                Ok(())
            }
            .scope_boxed()
        })
        .await
    }

    pub async fn get_roles_by_user_id(&self, user_id_val: i32) -> Result<Vec<Role>, result::Error> {
        use crate::data::models::schema::roles::dsl::roles;
        use crate::data::models::schema::user_roles::dsl::{user_id, user_roles};

        let db = Database::new().await;
        let mut conn: Object<AsyncMysqlConnection> = db.get_connection().await.map_err(|e| {
            result::Error::DatabaseError(
                result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(e.to_string()),
            )
        })?;

        // Join user_roles and roles to get all roles for a user
        // user_roles belongs_to roles
        let result = user_roles
            .filter(user_id.eq(user_id_val))
            .inner_join(roles)
            .select(crate::data::models::roles::Role::as_select())
            .load::<Role>(&mut conn)
            .await?;
            
        Ok(result)
    }
}

impl Default for UserRoleRepo {
    fn default() -> Self {
        Self::new()
    }
}