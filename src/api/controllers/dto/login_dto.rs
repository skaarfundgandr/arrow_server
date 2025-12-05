use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginDTO {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct LoginResponse {
    pub token: String,
    pub message: String,
}
