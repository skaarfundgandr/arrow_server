use crate::api::controllers::dto::role_dto::RoleDTO;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<i32>,
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
