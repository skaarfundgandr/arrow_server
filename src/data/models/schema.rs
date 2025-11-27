// @generated automatically by Diesel CLI.

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
    user_roles (role_id) {
        role_id -> Integer,
        user_id -> Nullable<Integer>,
        #[max_length = 50]
        name -> Varchar,
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

diesel::joinable!(user_roles -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(products, user_roles, users,);
