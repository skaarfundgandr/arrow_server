use bigdecimal::BigDecimal;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CreateProductRequest {
    pub name: String,
    pub description: Option<String>,
    pub price: BigDecimal,
    pub product_image_uri: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub price: Option<BigDecimal>,
    pub product_image_uri: Option<String>,
}

#[derive(Deserialize)]
pub struct OrderItemRequest {
    pub product_id: i32,
    pub quantity: i32,
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    pub products: Vec<OrderItemRequest>,
}

/// Struct for updating order status
#[derive(Deserialize)]
pub struct UpdateOrderStatusRequest {
    pub status: Option<String>,
}
