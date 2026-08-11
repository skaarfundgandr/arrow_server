use crate::api::config::Config;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderUrlError {
    InvalidSignature,
    Expired,
    Config,
    SigningKey,
}

impl std::fmt::Display for OrderUrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderUrlError::InvalidSignature => write!(f, "Invalid order url signature"),
            OrderUrlError::Expired => write!(f, "Order url expired"),
            OrderUrlError::Config => write!(f, "Order url configuration error"),
            OrderUrlError::SigningKey => write!(f, "Order url signing key error"),
        }
    }
}

impl std::error::Error for OrderUrlError {}

/// Computes the HMAC-SHA256 hex signature over `order_id={id}&exp={exp}`
/// keyed with the configured QR signing secret.
pub fn sign_order_url(order_id: i32, exp: u64) -> Result<String, OrderUrlError> {
    let config = Config::get().map_err(|_| OrderUrlError::Config)?;
    sign_order_url_with_key(&config.qr_signing_secret, order_id, exp)
}

pub fn sign_order_url_with_key(
    secret: &str,
    order_id: i32,
    exp: u64,
) -> Result<String, OrderUrlError> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| OrderUrlError::SigningKey)?;
    mac.update(format!("order_id={}&exp={}", order_id, exp).as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Builds the full public order URL: `{API_BASE}/api/v1/orders/{id}?exp={ts}&sig={hex}`
pub fn build_order_url(order_id: i32) -> Result<String, OrderUrlError> {
    let config = Config::get().map_err(|_| OrderUrlError::Config)?;
    let now = chrono::Utc::now().timestamp() as u64;
    let exp = now + config.order_link_ttl_minutes * 60;
    let sig = sign_order_url(order_id, exp)?;
    Ok(format!(
        "{}/api/v1/orders/{}?exp={}&sig={}",
        config.api_base_url, order_id, exp, sig
    ))
}

/// Verifies the signature and expiry of an order url.
/// Returns `Err(OrderUrlError::InvalidSignature)` for a tampered signature and
/// `Err(OrderUrlError::Expired)` when `exp` is in the past.
pub fn verify_order_url(order_id: i32, exp: u64, sig: &str) -> Result<(), OrderUrlError> {
    let now = chrono::Utc::now().timestamp() as u64;
    if now >= exp {
        return Err(OrderUrlError::Expired);
    }
    let config = Config::get().map_err(|_| OrderUrlError::Config)?;
    verify_order_url_with_key(&config.qr_signing_secret, order_id, exp, sig)
}

pub fn verify_order_url_with_key(
    secret: &str,
    order_id: i32,
    exp: u64,
    sig: &str,
) -> Result<(), OrderUrlError> {
    let now = chrono::Utc::now().timestamp() as u64;
    if now >= exp {
        return Err(OrderUrlError::Expired);
    }

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| OrderUrlError::SigningKey)?;
    mac.update(format!("order_id={}&exp={}", order_id, exp).as_bytes());

    let provided = hex::decode(sig).map_err(|_| OrderUrlError::InvalidSignature)?;

    mac.verify_slice(&provided)
        .map_err(|_| OrderUrlError::InvalidSignature)
}
