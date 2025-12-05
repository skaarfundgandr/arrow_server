use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum APIErrors {
    AuthenticationFailed,
    InvalidRequest,
    ResourceNotFound,
    InternalServerError,
    Unauthorized,
}
impl std::error::Error for APIErrors {}

impl std::fmt::Display for APIErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            APIErrors::InternalServerError => write!(f, "Internal server error"),
            APIErrors::AuthenticationFailed => write!(f, "Authentication failed"),
            APIErrors::InvalidRequest => write!(f, "Invalid request"),
            APIErrors::ResourceNotFound => write!(f, "Resource not found"),
            APIErrors::Unauthorized => write!(f, "Unauthorized"),
        }
    }
}

impl From<StatusCode> for APIErrors {
    fn from(status: StatusCode) -> Self {
        match status {
            StatusCode::UNAUTHORIZED => APIErrors::Unauthorized,
            StatusCode::NOT_FOUND => APIErrors::ResourceNotFound,
            StatusCode::BAD_REQUEST => APIErrors::InvalidRequest,
            StatusCode::INTERNAL_SERVER_ERROR => APIErrors::InternalServerError,
            _ => APIErrors::InternalServerError,
        }
    }
}

impl From<APIErrors> for StatusCode {
    fn from(error: APIErrors) -> Self {
        match error {
            APIErrors::Unauthorized => StatusCode::UNAUTHORIZED,
            APIErrors::ResourceNotFound => StatusCode::NOT_FOUND,
            APIErrors::InvalidRequest => StatusCode::BAD_REQUEST,
            APIErrors::AuthenticationFailed => StatusCode::FORBIDDEN,
            APIErrors::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for APIErrors {
    fn into_response(self) -> Response {
        tracing::error!("Error occurred: {}", self);
        let status_code = StatusCode::from(self);

        status_code.into_response()
    }
}
