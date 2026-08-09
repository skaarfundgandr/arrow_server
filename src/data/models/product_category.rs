use crate::data::models::categories::Category;
use crate::data::models::product::Product;
use crate::data::models::schema::*;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Identifiable, Associations, PartialEq, Debug)]
#[diesel(table_name = product_categories)]
#[diesel(primary_key(product_id, category_id))]
#[diesel(belongs_to(Product, foreign_key = product_id))]
#[diesel(belongs_to(Category, foreign_key = category_id))]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
#[diesel(treat_none_as_null = true)]
pub struct ProductCategory {
    pub product_id: i32,
    pub category_id: i32,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Insertable, PartialEq, Debug)]
#[diesel(table_name = product_categories)]
pub struct NewProductCategory<'a> {
    pub product_id: &'a i32,
    pub category_id: &'a i32,
}

#[derive(AsChangeset, PartialEq, Debug)]
#[diesel(table_name = product_categories)]
pub struct UpdateProductCategory<'a> {
    pub product_id: Option<&'a i32>,
    pub category_id: Option<&'a i32>,
}
