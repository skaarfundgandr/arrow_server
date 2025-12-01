use crate::data::models::schema::sql_types::UserRolesPermissionsSet;
use crate::data::models::schema::*;
use crate::data::models::user::User;
use diesel::deserialize::FromSqlRow;
use diesel::expression::AsExpression;
use diesel::prelude::*;

#[derive(Selectable, Queryable, Identifiable, Associations, PartialEq, Debug)]
#[diesel(table_name = user_roles)]
#[diesel(primary_key(role_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct UserRole {
    pub role_id: i32,
    pub user_id: Option<i32>,
    pub name: String,
    pub permissions: Option<PermissionString>,
    pub description: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

impl UserRole {
    /// Get the permissions as a RolePermissions enum
    pub fn get_permissions(&self) -> Option<RolePermissions> {
        self.permissions
            .as_ref()
            .and_then(|s| RolePermissions::from_str(&s.0))
    }
}

/// Insertable struct for creating new user roles
/// Note: permissions field is excluded due to MySQL SET type complexity.
/// Use UserRoleRepo::set_permissions() to set permissions after creation.
#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = user_roles)]
pub struct NewUserRole<'a> {
    pub user_id: i32,
    pub name: &'a str,
    pub description: Option<&'a str>,
}

/// Changeset struct for updating user roles
/// Note: permissions field is excluded due to MySQL SET type complexity.
/// Use UserRoleRepo::set_permissions() to update permissions.
#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = user_roles)]
pub struct UpdateUserRole<'a> {
    pub user_id: Option<i32>,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}

/// Newtype wrapper for permissions string that implements diesel traits for reading
#[derive(Debug, Clone, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = UserRolesPermissionsSet)]
pub struct PermissionString(pub String);

impl PermissionString {
    pub fn new(s: impl Into<String>) -> Self {
        PermissionString(s.into())
    }

    pub fn from_permission(perm: RolePermissions) -> Self {
        PermissionString(perm.as_str().to_string())
    }

    pub fn as_permission(&self) -> Option<RolePermissions> {
        RolePermissions::from_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolePermissions {
    Read,
    Write,
    Delete,
    Admin,
}

impl RolePermissions {
    pub fn as_str(&self) -> &'static str {
        match self {
            RolePermissions::Read => "READ",
            RolePermissions::Write => "WRITE",
            RolePermissions::Delete => "DELETE",
            RolePermissions::Admin => "ADMIN",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "READ" => Some(RolePermissions::Read),
            "WRITE" => Some(RolePermissions::Write),
            "DELETE" => Some(RolePermissions::Delete),
            "ADMIN" => Some(RolePermissions::Admin),
            _ => None,
        }
    }
}

