use crate::api::controllers::dto::{role_dto::{NewRoleDTO, RoleDTO, UpdateRoleDTO}, user_dto::{NewUserDTO, UpdateUserDTO}};
use crate::data::models::schema::sql_types::UserRolesPermissionsSet;
use crate::data::models::user::{NewUser, UpdateUser};
use crate::data::models::user_roles::{NewUserRole, PermissionString, RolePermissions, UpdateUserRole, UserRole};
use diesel::deserialize::FromSql;
use diesel::mysql::{Mysql, MysqlValue};
use diesel::serialize::{Output, ToSql};
use diesel::{deserialize, serialize};
use std::io::Write;

impl<'a> From<&'a NewUserDTO> for NewUser<'a> {
    fn from(user_dto: &'a NewUserDTO) -> Self {
        NewUser {
            username: &user_dto.username,
            password_hash: &user_dto.password,
        }
    }
}

impl<'a> From<&'a UpdateUserDTO> for UpdateUser<'a> {
    fn from(dto: &'a UpdateUserDTO) -> Self {
        UpdateUser {
            username: dto.username.as_deref(),
            password_hash: dto.password.as_deref(),
        }
    }
}

impl<'a> From<&'a NewRoleDTO> for NewUserRole<'a> {
    fn from(dto: &'a NewRoleDTO) -> Self {
        NewUserRole {
            user_id: dto.user_id,
            name: &dto.name,
            description: dto.description.as_deref(),
        }
    }
}

impl<'a> From<&'a UpdateRoleDTO> for UpdateUserRole<'a> {
    fn from(dto: &'a UpdateRoleDTO) -> Self {
        UpdateUserRole {
            user_id: None,
            name: dto.name.as_deref(),
            description: dto.description.as_deref(),
        }
    }
}

impl From<RolePermissions> for PermissionString {
    fn from(perm: RolePermissions) -> Self {
        PermissionString::from_permission(perm)
    }
}

impl ToSql<UserRolesPermissionsSet, Mysql> for PermissionString {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Mysql>) -> serialize::Result {
        out.write_all(self.0.as_bytes())?;
        Ok(serialize::IsNull::No)
    }
}

impl FromSql<UserRolesPermissionsSet, Mysql> for PermissionString {
    fn from_sql(bytes: MysqlValue<'_>) -> deserialize::Result<Self> {
        Ok(PermissionString(String::from_utf8(
            bytes.as_bytes().to_vec(),
        )?))
    }
}

impl From<UserRole> for RoleDTO {
    fn from(user_role: UserRole) -> Self {
        let permissions = user_role
            .get_permissions()
            .map(|p| vec![p.as_str().to_string()])
            .unwrap_or_default();

        RoleDTO {
            name: user_role.name.clone(),
            permissions,
            description: user_role.description,
            created_at: user_role
                .created_at
                .map(|dt| dt.format("%d/%m/%Y").to_string()),
            updated_at: user_role
                .updated_at
                .map(|dt| dt.format("%d/%m/%Y").to_string()),
        }
    }
}
