use crate::api::config::Config;
use crate::api::controllers::dto::user_dto::UserDTO;
use crate::data::repos::implementors::user_repo::UserRepo;
use crate::data::repos::implementors::user_role_repo::UserRoleRepo;
use crate::security::errors::AuthError;
use serde::{Deserialize, Serialize};

pub struct JwtService;
// TODO: Wire to endpoints
// TODO: Generate tests
impl JwtService {
    pub fn new() -> Self {
        JwtService
    }

    pub async fn generate_token(&self, user: UserDTO) -> Result<String, AuthError> {
        let curr_time = chrono::Utc::now().timestamp() as usize;
        let config = Config::default();

        let user_repo = UserRepo::new();
        let role_repo = UserRoleRepo::new();

        let user = user_repo
            .get_by_username(&user.username)
            .await
            .map_err(|_| AuthError::UserNotFound)?
            .ok_or(AuthError::UserNotFound)?;

        let roles: Option<Vec<usize>> = role_repo
            .get_by_user_id(user.user_id)
            .await
            .map_err(|_| AuthError::UserNotFound)?
            .map(|role_vec| role_vec.into_iter().map(|r| r.role_id as usize).collect());

        let claims = AccessClaims {
            sub: user.user_id as usize,
            iat: curr_time,
            exp: curr_time + config.jwt_expiration_minutes as usize,
            roles,
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(config.jwt_secret.as_ref()),
        )
        .map_err(|_| AuthError::TokenCreationError);

        tracing::info!("Token generated: {:?}", token);

        Ok(token?)
    }

    pub async fn decode_token<T: for<'de> Deserialize<'de>>(
        &self,
        token: &str,
    ) -> Result<T, AuthError> {
        let validation = jsonwebtoken::Validation::default();

        let token_data = jsonwebtoken::decode::<T>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(Config::default().jwt_secret.as_ref()),
            &validation,
        )
        .map_err(|_| AuthError::InvalidToken);

        Ok(token_data?.claims)
    }
}

impl Default for JwtService {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Subject (user ID)
    pub sub: usize,
    /// Issued at (as UTC timestamp)
    pub iat: usize,
    /// Expiration time (as UTC timestamp)
    pub exp: usize,
    /// Roles assigned to the user
    pub roles: Option<Vec<usize>>,
}

impl AccessClaims {
    pub fn get_sub(&self) -> usize {
        self.sub
    }
    pub fn get_exp(&self) -> usize {
        self.exp
    }
    pub fn get_iat(&self) -> usize {
        self.iat
    }
    pub fn get_roles(&self) -> Option<Vec<usize>> {
        self.roles.clone()
    }
}
