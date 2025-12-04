use serde::{Deserialize, Serialize};
use crate::api::controllers::dto::role_dto::RoleDTO;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserDTO {
    pub username: String,
    pub role: Option<RoleDTO>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NewUserDTO {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UpdateUserDTO {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserQueryParams {
    pub username: Option<String>,
}
