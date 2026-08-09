use crate::data::models::schema::categories;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Identifiable, PartialEq, Debug)]
#[diesel(table_name = categories)]
#[diesel(primary_key(category_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct Category {
    pub category_id: i32,
    pub name: String,
    pub description: Option<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = categories)]
pub struct NewCategory<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = categories)]
pub struct UpdateCategory<'a> {
    pub name: Option<&'a str>,
    pub description: Option<&'a str>,
}
