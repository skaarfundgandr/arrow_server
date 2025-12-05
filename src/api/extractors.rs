use axum::extract::FromRequestParts;
use crate::api::errors::APIErrors;
use axum::http::request::Parts;
use axum::RequestPartsExt;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use axum_extra::TypedHeader;
use crate::security::jwt::{AccessClaims, JwtService};

// TODO: JWT Extractor

impl FromRequestParts<()> for AccessClaims
{
    type Rejection = APIErrors;

    async fn from_request_parts(parts: &mut Parts, _state: &()) -> Result<Self, Self::Rejection> {
        decode_token_from_request_part(parts).await
    }
}

async fn decode_token_from_request_part<T>(parts: &mut Parts) -> Result<T, APIErrors>
where
    T: for<'de> serde::Deserialize<'de> + std::fmt::Debug + Sync + Send,
{
    let tokenizer = JwtService::new();

    let TypedHeader(Authorization(bearer)) = parts
        .extract::<TypedHeader<Authorization<Bearer>>>()
        .await
        .map_err(|_| {
            tracing::error!("Invalid authorization header");
            APIErrors::Unauthorized
        })?;

    let claims = tokenizer.decode_token::<T>(&bearer.token()).await.map_err(|e| {;
        tracing::error!("Token decoding error: {:?}", e);
        APIErrors::Unauthorized
    })?;

    Ok(claims)
}
