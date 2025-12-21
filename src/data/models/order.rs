use crate::data::models::schema::*;
use crate::data::models::user::User;
use bigdecimal::BigDecimal;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Identifiable, Associations, PartialEq, Debug)]
#[diesel(table_name = orders)]
#[diesel(primary_key(order_id))]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct Order {
    pub order_id: i32,
    pub user_id: i32,
    pub total_amount: BigDecimal,
    pub status: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = orders)]
pub struct NewOrder {
    pub user_id: i32,
    pub total_amount: BigDecimal,
    pub status: Option<String>,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = orders)]
pub struct UpdateOrder<'a> {
    pub user_id: Option<i32>,
    pub total_amount: Option<BigDecimal>,
    pub status: Option<&'a str>,
}