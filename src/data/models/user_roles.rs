use diesel::prelude::*;
use crate::data::models::schema::*;
use crate::data::models::user::User;
use crate::data::models::roles::Role;

#[derive(Debug, Queryable, Identifiable, Associations, PartialEq, Clone)]
#[diesel(table_name = user_roles)]
#[diesel(primary_key(user_id, role_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(Role, foreign_key = role_id))]
pub struct UserRole {
    pub user_id: i32,
    pub role_id: i32,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = user_roles)]
pub struct NewUserRole {
    pub user_id: i32,
    pub role_id: i32,
}
