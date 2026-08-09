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
    PaymentConflict,
    InvalidOrderItems,
    DatabaseError,
    ConfigError,
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
            OrderServiceError::PaymentConflict => write!(f, "Order payment conflict"),
            OrderServiceError::InvalidOrderItems => write!(f, "Invalid order items"),
            OrderServiceError::DatabaseError => write!(f, "Database error"),
            OrderServiceError::ConfigError => write!(f, "Configuration error"),
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
    ImageTooLarge,
    InvalidImageType,
    ImageUploadFailed,
    ImageDeletionFailed,
    StorageNotConfigured,
    ConfigError,
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
            ProductServiceError::ImageTooLarge => write!(f, "Image exceeds the maximum allowed size"),
            ProductServiceError::InvalidImageType => write!(f, "Image type is not supported"),
            ProductServiceError::ImageUploadFailed => write!(f, "Image upload failed"),
            ProductServiceError::ImageDeletionFailed => write!(f, "Image deletion failed"),
            ProductServiceError::StorageNotConfigured => {
                write!(f, "Object storage is not configured")
            }
            ProductServiceError::ConfigError => write!(f, "Configuration error"),
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
    ProductNotFound,
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
            ProductCategoryServiceError::ProductNotFound => write!(f, "Product not found"),
        }
    }
}

#[derive(Debug)]
pub enum UserServiceError {
    HashingError,
    UserCreationFailed,
    UserNotFound,
    RoleCreationFailed,
    RoleAssignmentFailed,
    DatabaseError,
    ConfigError,
}

impl std::error::Error for UserServiceError {}

impl std::fmt::Display for UserServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserServiceError::HashingError => write!(f, "Password hashing failed"),
            UserServiceError::UserCreationFailed => write!(f, "User creation failed"),
            UserServiceError::UserNotFound => write!(f, "User not found"),
            UserServiceError::RoleCreationFailed => write!(f, "Role creation failed"),
            UserServiceError::RoleAssignmentFailed => write!(f, "Role assignment failed"),
            UserServiceError::DatabaseError => write!(f, "Database error"),
            UserServiceError::ConfigError => write!(f, "Configuration error"),
        }
    }
}
