#[derive(Debug)]
pub enum RoleError {
    RoleNotFound,
    PermissionDenied,
    RoleAssignmentFailed,
    RoleCreationFailed,
    PermissionAssignmentFailed,
}

impl std::error::Error for RoleError {}

impl std::fmt::Display for RoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoleError::RoleNotFound => write!(f, "Role not found"),
            RoleError::PermissionDenied => write!(f, "Permission denied"),
            RoleError::RoleAssignmentFailed => write!(f, "Role assignment failed"),
            RoleError::RoleCreationFailed => write!(f, "Role creation failed"),
            RoleError::PermissionAssignmentFailed => write!(f, "Permission assignment failed"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum OrderServiceError {
    OrderNotFound,
    OrderCreationFailed,
    OrderUpdateFailed,
    OrderDeletionFailed,
    PermissionDenied,
    InvalidStatusTransition,
    DatabaseError,
}

impl std::error::Error for OrderServiceError {}

impl std::fmt::Display for OrderServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderServiceError::OrderNotFound => write!(f, "Order not found"),
            OrderServiceError::OrderCreationFailed => write!(f, "Order creation failed"),
            OrderServiceError::OrderUpdateFailed => write!(f, "Order update failed"),
            OrderServiceError::OrderDeletionFailed => write!(f, "Order deletion failed"),
            OrderServiceError::PermissionDenied => write!(f, "Permission denied"),
            OrderServiceError::InvalidStatusTransition => write!(f, "Invalid status transition"),
            OrderServiceError::DatabaseError => write!(f, "Database error"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ProductServiceError {
    ProductNotFound,
    ProductAlreadyExists,
    ProductCreationFailed,
    ProductUpdateFailed,
    ProductDeletionFailed,
    PermissionDenied,
    DatabaseError,
}

impl std::error::Error for ProductServiceError {}

impl std::fmt::Display for ProductServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProductServiceError::ProductNotFound => write!(f, "Product not found"),
            ProductServiceError::ProductAlreadyExists => write!(f, "Product already exists"),
            ProductServiceError::ProductCreationFailed => write!(f, "Product creation failed"),
            ProductServiceError::ProductUpdateFailed => write!(f, "Product update failed"),
            ProductServiceError::ProductDeletionFailed => write!(f, "Product deletion failed"),
            ProductServiceError::PermissionDenied => write!(f, "Permission denied"),
            ProductServiceError::DatabaseError => write!(f, "Database error"),
        }
    }
}

#[derive(Debug)]
pub enum ProductCategoryServiceError {
    CategoryNotFound,
    CategoryCreationFailed,
    CategoryUpdateFailed,
    CategoryDeletionFailed,
    PermissionDenied,
    DatabaseError,
}

impl std::error::Error for ProductCategoryServiceError {}

impl std::fmt::Display for ProductCategoryServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProductCategoryServiceError::CategoryNotFound => write!(f, "Category not found"),
            ProductCategoryServiceError::CategoryCreationFailed => {
                write!(f, "Category creation failed")
            }
            ProductCategoryServiceError::CategoryUpdateFailed => {
                write!(f, "Category update failed")
            }
            ProductCategoryServiceError::CategoryDeletionFailed => {
                write!(f, "Category deletion failed")
            }
            ProductCategoryServiceError::PermissionDenied => write!(f, "Permission denied"),
            ProductCategoryServiceError::DatabaseError => write!(f, "Database error"),
        }
    }
}
