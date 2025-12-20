use crate::data::models::schema::sql_types::RolesPermissionsSet;
use crate::data::models::schema::*;
use diesel::deserialize::FromSqlRow;
use diesel::expression::AsExpression;
use diesel::prelude::*;
use std::str::FromStr;

#[derive(Selectable, Queryable, Identifiable, PartialEq, Debug, Clone)]
#[diesel(table_name = roles)]
#[diesel(primary_key(role_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct Role {
    pub role_id: i32,
    pub name: String,
    pub permissions: Option<PermissionString>,
    pub description: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

impl Role {
    /// Get the permissions as a RolePermissions enum (returns first valid one found)
    pub fn get_permissions(&self) -> Option<RolePermissions> {
        self.get_all_permissions().into_iter().next()
    }

    /// Get all permissions
    pub fn get_all_permissions(&self) -> Vec<RolePermissions> {
        self.permissions
            .as_ref()
            .map(|s| {
                s.0.split(',')
                    .filter_map(|p| p.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if role has specific permission
    pub fn has_permission(&self, perm: RolePermissions) -> bool {
        self.get_all_permissions().contains(&perm)
    }
}

/// Insertable struct for creating new user roles
/// Note: permissions field is excluded due to MySQL SET type complexity.
/// Use UserRoleRepo::set_permissions() to set permissions after creation.
#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = roles)]
pub struct NewRole<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
}

/// Changeset struct for updating user roles
/// Note: permissions field is excluded due to MySQL SET type complexity.
/// Use UserRoleRepo::set_permissions() to update permissions.
#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = roles)]
pub struct UpdateRole<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}

/// Newtype wrapper for permissions string that implements diesel traits for reading
#[derive(Debug, Clone, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = RolesPermissionsSet)]
pub struct PermissionString(pub String);

impl PermissionString {
    pub fn new(s: impl Into<String>) -> Self {
        PermissionString(s.into())
    }

    pub fn from_permission(perm: RolePermissions) -> Self {
        PermissionString(perm.as_str().to_string())
    }

    pub fn as_permission(&self) -> Option<RolePermissions> {
        RolePermissions::from_str(&self.0).ok()
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
}
