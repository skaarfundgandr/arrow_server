#[derive(Debug)]
pub enum AuthServiceError {
    HashingError,
    VerificationError,
}

impl std::error::Error for AuthServiceError {}

impl std::fmt::Display for AuthServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthServiceError::HashingError => write!(f, "Password hashing failed"),
            AuthServiceError::VerificationError => write!(f, "Password verification failed"),
        }
    }
}
