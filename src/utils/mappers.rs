use std::io::Write;
use diesel::mysql::{Mysql, MysqlValue};
use diesel::{deserialize, serialize};
use diesel::deserialize::FromSql;
use diesel::serialize::{Output, ToSql};
use crate::controllers::dto::user_dto::NewUserDTO;
use crate::data::models::schema::sql_types::UserRolesPermissionsSet;
use crate::data::models::user::NewUser;
use crate::data::models::user_roles::{PermissionString, RolePermissions};

impl<'a> From<&'a NewUserDTO> for NewUser<'a> {
    fn from(user_dto: &'a NewUserDTO) -> Self {
        NewUser {
            username: &user_dto.username,
            password_hash: &user_dto.password,
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
