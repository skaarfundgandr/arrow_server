use crate::data::models::schema::*;
use crate::data::models::user::User;
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
    pub description: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = user_roles)]
pub struct NewUserRole<'a> {
    pub user_id: i32,
    pub name: &'a str,
    pub description: Option<&'a str>,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = user_roles)]
pub struct UpdateUserRole<'a> {
    pub user_id: Option<i32>,
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}
