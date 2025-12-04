use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoleDTO {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
// TODO: Do not use user_id here, use username instead
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NewRoleDTO {
    pub user_id: i32,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct UpdateRoleDTO {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SetPermissionDTO {
    pub permission: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AssignRoleDTO {
    pub username: String,
    pub role_name: String,
}
