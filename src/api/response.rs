use bigdecimal::BigDecimal;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ProductResponse {
    pub product_id: i32,
    pub name: String,
    pub description: Option<String>,
    pub price: BigDecimal,
    pub product_image_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
pub struct CategoryResponse {
    pub category_id: Option<i32>,
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ProductCategoryResponse {
    pub product: ProductResponse,
    pub category: CategoryResponse,
}
