use crate::data::models::schema::*;
use bigdecimal::BigDecimal;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Identifiable, PartialEq, Debug)]
#[diesel(table_name = products)]
#[diesel(primary_key(product_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct Product {
    pub product_id: i32,
    pub name: String,
    pub product_image_uri: Option<String>,
    pub description: Option<String>,
    pub price: BigDecimal,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub updated_at: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = products)]
pub struct NewProduct<'a> {
    pub name: &'a str,
    pub product_image_uri: Option<&'a str>,
    pub description: Option<&'a str>,
    pub price: BigDecimal,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = products)]
pub struct UpdateProduct<'a> {
    pub name: Option<&'a str>,
    pub product_image_uri: Option<&'a str>,
    pub description: Option<&'a str>,
    pub price: Option<BigDecimal>,
}
