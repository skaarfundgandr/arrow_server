use diesel::prelude::*;
use crate::data::models::schema::*;

#[derive(Queryable, Selectable, Identifiable, PartialEq, Debug)]
#[diesel(table_name = users)]
#[diesel(primary_key(user_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub password_hash: String,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = users)]
pub struct UpdateUser<'a> {
    pub username: Option<&'a str>,
    pub password_hash: Option<&'a str>,
}