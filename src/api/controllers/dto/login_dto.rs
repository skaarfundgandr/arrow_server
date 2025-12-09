use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginDTO {
    pub username: String,
    pub password: String,
}
