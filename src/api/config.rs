use bigdecimal::BigDecimal;
use dotenvy::dotenv;
use once_cell::sync::Lazy;

// API Config goes here
#[derive(Debug, Clone)]
pub struct Config {
    pub jwt_secret: String,
    pub jwt_expiration_minutes: u64,
    pub admin_username: String,
    pub admin_password: String,
    pub qr_signing_secret: String,
    pub order_link_ttl_minutes: u64,
    pub api_base_url: String,
    pub max_payment_amount: BigDecimal,
}

impl Config {
    pub fn new() -> Self {
        CONFIG.clone()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new()
    }
}

static CONFIG: Lazy<Config> = Lazy::new(|| {
    dotenv().ok();

    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let jwt_expiration_minutes = std::env::var("JWT_EXPIRATION_MINUTES")
        .unwrap_or_else(|_| "60".to_string())
        .parse()
        .expect("JWT_EXPIRATION_MINUTES must be a valid u64");
    let admin_username =
        std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let admin_password = std::env::var("ADMIN_PASSWORD").expect("ADMIN_PASSWORD must be set");
    let qr_signing_secret =
        std::env::var("QR_SIGNING_SECRET").expect("QR_SIGNING_SECRET must be set");
    let order_link_ttl_minutes = std::env::var("ORDER_LINK_EXPIRATION_MINUTES")
        .unwrap_or_else(|_| "1440".to_string())
        .parse()
        .expect("ORDER_LINK_EXPIRATION_MINUTES must be a valid u64");
    let api_base_url = std::env::var("API_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let max_payment_amount = std::env::var("MAX_PAYMENT_AMOUNT")
        .unwrap_or_else(|_| "1000.00".to_string())
        .parse()
        .expect("MAX_PAYMENT_AMOUNT must be a valid decimal");

    tracing::info!("Config loaded");

    Config {
        jwt_secret,
        jwt_expiration_minutes,
        admin_username,
        admin_password,
        qr_signing_secret,
        order_link_ttl_minutes,
        api_base_url,
        max_payment_amount,
    }
});
