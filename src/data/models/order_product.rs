use crate::data::models::order::Order;
use crate::data::models::product::Product;
use crate::data::models::schema::*;
use bigdecimal::BigDecimal;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Identifiable, Associations, PartialEq, Debug)]
#[diesel(table_name = order_products)]
#[diesel(primary_key(order_id, product_id))]
#[diesel(belongs_to(Order, foreign_key = order_id))]
#[diesel(belongs_to(Product, foreign_key = product_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct OrderProduct {
    pub order_id: i32,
    pub product_id: i32,
    pub quantity: i32,
    pub unit_price: BigDecimal,
    pub line_total: Option<BigDecimal>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = order_products)]
pub struct NewOrderProduct {
    pub order_id: i32,
    pub product_id: i32,
    pub quantity: i32,
    pub unit_price: BigDecimal,
    pub line_total: Option<BigDecimal>,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = order_products)]
pub struct UpdateOrderProduct {
    pub quantity: Option<i32>,
    pub unit_price: Option<BigDecimal>,
    pub line_total: Option<BigDecimal>,
}
