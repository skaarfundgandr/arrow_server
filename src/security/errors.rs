#[derive(Debug)]
pub enum AuthError {
    HashingError,
    VerificationError,
    InvalidCredentials,
    UserNotFound,
    TokenExpired,
    UnauthorizedAccess,
    TokenCreationError,
    InvalidToken,
    ConfigError,
}

impl std::error::Error for AuthError {}

impl From<diesel::result::Error> for AuthError {
    fn from(_: diesel::result::Error) -> Self {
        AuthError::InvalidCredentials
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::HashingError => write!(f, "Password hashing failed"),
            AuthError::VerificationError => write!(f, "Password verification failed"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials provided."),
            AuthError::UserNotFound => write!(f, "User not found."),
            AuthError::TokenExpired => write!(f, "Authentication token has expired."),
            AuthError::UnauthorizedAccess => write!(f, "Unauthorized access attempt detected."),
            AuthError::TokenCreationError => write!(f, "Token creation failed"),
            AuthError::InvalidToken => write!(f, "Invalid token credentials provided."),
            AuthError::ConfigError => write!(f, "Configuration error"),
        }
    }
}
