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
    pub ordering_base_url: String,
    pub max_payment_amount: BigDecimal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingVar(String),
    InvalidVar { name: String, reason: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingVar(name) => write!(f, "Environment variable {} must be set", name),
            ConfigError::InvalidVar { name, reason } => {
                write!(f, "Environment variable {} is invalid: {}", name, reason)
            }
        }
    }
}

impl std::error::Error for ConfigError {}

static CONFIG: Lazy<Result<Config, ConfigError>> = Lazy::new(Config::try_new);

impl Config {
    pub fn try_new() -> Result<Self, ConfigError> {
        dotenv().ok();

        let jwt_secret = Config::require_var("JWT_SECRET")?;
        let jwt_expiration_minutes = Config::var_or_parsed("JWT_EXPIRATION_MINUTES", "60")?;
        let admin_username = Config::var_or("ADMIN_USERNAME", "admin");
        let admin_password = Config::require_var("ADMIN_PASSWORD")?;
        let qr_signing_secret = Config::require_var("QR_SIGNING_SECRET")?;
        let order_link_ttl_minutes =
            Config::var_or_parsed("ORDER_LINK_EXPIRATION_MINUTES", "1440")?;
        let api_base_url = Config::var_or("API_BASE_URL", "http://localhost:3000");
        let ordering_base_url =
            Config::var_or("ORDERING_BASE_URL", &format!("{}/api/v1/products", api_base_url));
        let max_payment_amount = Config::var_or_parsed("MAX_PAYMENT_AMOUNT", "1000.00")?;

        tracing::info!("Config loaded");

        Ok(Config {
            jwt_secret,
            jwt_expiration_minutes,
            admin_username,
            admin_password,
            qr_signing_secret,
            order_link_ttl_minutes,
            api_base_url,
            ordering_base_url,
            max_payment_amount,
        })
    }

    pub fn get() -> Result<&'static Config, ConfigError> {
        match CONFIG.as_ref() {
            Ok(config) => Ok(config),
            Err(e) => Err(e.clone()),
        }
    }

    fn require_var(name: &str) -> Result<String, ConfigError> {
        std::env::var(name).map_err(|_| ConfigError::MissingVar(name.to_string()))
    }

    fn var_or(name: &str, default: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| default.to_string())
    }

    fn var_or_parsed<T: std::str::FromStr>(name: &str, default: &str) -> Result<T, ConfigError>
    where
        T::Err: std::fmt::Display,
    {
        let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
        raw.parse::<T>()
            .map_err(|e| ConfigError::InvalidVar {
                name: name.to_string(),
                reason: e.to_string(),
            })
    }
}
