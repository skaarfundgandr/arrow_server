use crate::data::models::order::Order;
use crate::data::models::product::Product;
use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct LoginResponse {
    pub token: String,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct OrderResponse {
    pub order_id: i32,
    pub user_id: i32,
    pub product_id: i32,
    pub quantity: i32,
    pub total_amount: BigDecimal,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<Order> for OrderResponse {
    fn from(order: Order) -> Self {
        Self {
            order_id: order.order_id,
            user_id: order.user_id,
            product_id: order.product_id,
            quantity: order.quantity,
            total_amount: order.total_amount,
            status: order.status,
            created_at: order.created_at.map(|d| d.to_string()),
            updated_at: order.updated_at.map(|d| d.to_string()),
        }
    }
}

impl From<Product> for ProductResponse {
    fn from(product: Product) -> Self {
        Self {
            product_id: product.product_id,
            name: product.name,
            description: product.description,
            price: product.price,
            product_image_uri: product.product_image_uri,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProductResponse {
    pub product_id: i32,
    pub name: String,
    pub description: Option<String>,
    pub price: BigDecimal,
    pub product_image_uri: Option<String>,
}
