// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(mysql_type(name = "Set"))]
    pub struct RolesPermissionsSet;
}

diesel::table! {
    categories (category_id) {
        category_id -> Integer,
        #[max_length = 255]
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    order_products (order_id, product_id) {
        order_id -> Integer,
        product_id -> Integer,
        quantity -> Integer,
        unit_price -> Decimal,
        line_total -> Nullable<Decimal>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    orders (order_id) {
        order_id -> Integer,
        user_id -> Integer,
        total_amount -> Decimal,
        #[max_length = 50]
        status -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    product_categories (product_id, category_id) {
        product_id -> Integer,
        category_id -> Integer,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    products (product_id) {
        product_id -> Integer,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 255]
        product_image_uri -> Nullable<Varchar>,
        description -> Nullable<Text>,
        price -> Decimal,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::RolesPermissionsSet;

    roles (role_id) {
        role_id -> Integer,
        #[max_length = 50]
        name -> Varchar,
        #[max_length = 23]
        permissions -> Nullable<RolesPermissionsSet>,
        description -> Nullable<Text>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    user_roles (user_id, role_id) {
        role_id -> Integer,
        user_id -> Integer,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (user_id) {
        user_id -> Integer,
        #[max_length = 50]
        username -> Varchar,
        #[max_length = 255]
        password_hash -> Varchar,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::joinable!(order_products -> orders (order_id));
diesel::joinable!(order_products -> products (product_id));
diesel::joinable!(orders -> users (user_id));
diesel::joinable!(product_categories -> categories (category_id));
diesel::joinable!(product_categories -> products (product_id));
diesel::joinable!(user_roles -> roles (role_id));
diesel::joinable!(user_roles -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    categories,
    order_products,
    orders,
    product_categories,
    products,
    roles,
    user_roles,
    users,
);
