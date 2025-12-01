// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(mysql_type(name = "Set"))]
    pub struct UserRolesPermissionsSet;
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
        product_id -> Integer,
        quantity -> Integer,
        total_amount -> Decimal,
        #[max_length = 50]
        status -> Nullable<Varchar>,
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
    use super::sql_types::UserRolesPermissionsSet;

    user_roles (role_id) {
        role_id -> Integer,
        user_id -> Nullable<Integer>,
        #[max_length = 50]
        name -> Varchar,
        #[max_length = 23]
        permissions -> Nullable<UserRolesPermissionsSet>,
        description -> Nullable<Text>,
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
diesel::joinable!(user_roles -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(order_products, orders, products, user_roles, users,);
