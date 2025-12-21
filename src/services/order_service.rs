use crate::data::models::order::{NewOrder, Order, UpdateOrder};
use crate::data::models::order_product::OrderProduct;
use crate::data::models::product::Product;
use crate::data::models::roles::RolePermissions;
use crate::data::repos::implementors::order_repo::OrderRepo;
use crate::data::repos::traits::repository::Repository;
use crate::services::errors::OrderServiceError;
use bigdecimal::{BigDecimal, FromPrimitive};

/// Order statuses for workflow management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    Pending,
    Accepted,
    Ready,
    Completed,
    Cancelled,
}

impl OrderStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OrderStatus::Pending => "Pending",
            OrderStatus::Accepted => "Accepted",
            OrderStatus::Ready => "Ready",
            OrderStatus::Completed => "Completed",
            OrderStatus::Cancelled => "Cancelled",
        }
    }
}

impl std::str::FromStr for OrderStatus {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(OrderStatus::Pending),
            "accepted" => Ok(OrderStatus::Accepted),
            "ready" => Ok(OrderStatus::Ready),
            "completed" => Ok(OrderStatus::Completed),
            "cancelled" => Ok(OrderStatus::Cancelled),
            _ => Err(()),
        }
    }
}

pub struct OrderService;

impl OrderService {
    pub fn new() -> Self {
        OrderService
    }

    /// Creates a new order for a user (requires WRITE permission or Admin)
    pub async fn create_order(
        &self,
        user_id: i32,
        role_id: i32,
        items: Vec<(i32, i32)>, // product_id, quantity
    ) -> Result<(), OrderServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(OrderServiceError::PermissionDenied);
        }

        let product_repo = crate::data::repos::implementors::product_repo::ProductRepo::new();
        let mut order_items = Vec::new();
        let mut total_amount = BigDecimal::from(0);

        for (pid, qty) in items {
            let product = product_repo.get_by_id(pid).await
                .map_err(|_| OrderServiceError::DatabaseError)?
                .ok_or(OrderServiceError::OrderCreationFailed)?; 

            let price = product.price;
            let qty_bd = BigDecimal::from_i32(qty).unwrap_or_default();
            let line_total = &price * &qty_bd;
            total_amount += line_total;

            order_items.push((pid, qty, price));
        }

        let repo = OrderRepo::new();
        let new_order = NewOrder {
            user_id,
            total_amount,
            status: Some(OrderStatus::Pending.as_str().to_string()),
        };

        repo.create_with_items(new_order, order_items)
            .await
            .map_err(|_| OrderServiceError::OrderCreationFailed)
    }

    /// Gets all orders for a specific user (requires READ permission or Admin)
    pub async fn get_user_orders(
        &self,
        target_user_id: i32,
        role_id: i32,
    ) -> Result<Option<Vec<(Order, Vec<(OrderProduct, Product)>)>>, OrderServiceError> {
        let is_admin = self.has_permission(role_id, RolePermissions::Admin).await?;
        let has_read = self.has_permission(role_id, RolePermissions::Read).await?;
        let has_write = self.has_permission(role_id, RolePermissions::Write).await?;

        if !has_read && !is_admin && !has_write {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();
        let orders = repo.get_by_user_id(target_user_id)
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?;

        if let Some(orders) = orders {
            let detailed = repo.attach_products(orders).await
                .map_err(|_| OrderServiceError::DatabaseError)?;
            Ok(Some(detailed))
        } else {
            Ok(None)
        }
    }

    /// Gets all orders (READ or ADMIN permission required)
    pub async fn get_all_orders(
        &self,
        role_id: i32,
    ) -> Result<Option<Vec<(Order, Vec<(OrderProduct, Product)>)>>, OrderServiceError> {
        if !self.has_permission(role_id, RolePermissions::Admin).await?
            && !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Write).await?
        {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();
        let orders = repo.get_all()
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?;

        if let Some(orders) = orders {
            let detailed = repo.attach_products(orders).await
                .map_err(|_| OrderServiceError::DatabaseError)?;
            Ok(Some(detailed))
        } else {
            Ok(None)
        }
    }

    /// Gets an order by ID (must have READ permission or be Admin)
    pub async fn get_order_by_id(
        &self,
        order_id: i32,
        role_id: i32,
    ) -> Result<Option<(Order, Vec<(OrderProduct, Product)>)>, OrderServiceError> {
        let is_admin = self.has_permission(role_id, RolePermissions::Admin).await?;
        let has_read = self.has_permission(role_id, RolePermissions::Read).await?;
        let has_write = self.has_permission(role_id, RolePermissions::Write).await?;

        if !has_read && !is_admin && !has_write {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();
        let order = repo
            .get_by_id(order_id)
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?;

        if let Some(order) = order {
            let detailed_list = repo.attach_products(vec![order]).await
                .map_err(|_| OrderServiceError::DatabaseError)?;
            Ok(detailed_list.into_iter().next())
        } else {
            Ok(None)
        }
    }

    /// Cancels an order (must have WRITE permission or be Admin)
    pub async fn cancel_order(&self, order_id: i32, role_id: i32) -> Result<(), OrderServiceError> {
        let has_permission = self.has_permission(role_id, RolePermissions::Admin).await?
            || self.has_permission(role_id, RolePermissions::Write).await?;

        if !has_permission {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();

        let update = UpdateOrder {
            user_id: None,
            total_amount: None,
            status: Some(OrderStatus::Cancelled.as_str()),
        };

        repo.update(order_id, update)
            .await
            .map_err(|_| OrderServiceError::OrderUpdateFailed)
    }

    /// Updates order status
    pub async fn update_order_status(
        &self,
        order_id: i32,
        new_status: OrderStatus,
        role_id: i32,
    ) -> Result<(), OrderServiceError> {
        if !self.has_permission(role_id, RolePermissions::Write).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();

        // Verify order exists
        repo.get_by_id(order_id)
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?
            .ok_or(OrderServiceError::OrderNotFound)?;

        let update = UpdateOrder {
            user_id: None,
            total_amount: None,
            status: Some(new_status.as_str()),
        };

        repo.update(order_id, update)
            .await
            .map_err(|_| OrderServiceError::OrderUpdateFailed)
    }

    /// Gets orders by status
    pub async fn get_orders_by_status(
        &self,
        status: OrderStatus,
        role_id: i32,
    ) -> Result<Option<Vec<(Order, Vec<(OrderProduct, Product)>)>>, OrderServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
            && !self.has_permission(role_id, RolePermissions::Write).await?
        {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();
        let orders = repo.get_by_status(status.as_str())
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?;

        if let Some(orders) = orders {
            let detailed = repo.attach_products(orders).await
                .map_err(|_| OrderServiceError::DatabaseError)?;
            Ok(Some(detailed))
        } else {
            Ok(None)
        }
    }

    /// Gets orders by role (READ or ADMIN permission required)
    pub async fn get_orders_by_role(
        &self,
        role_name: &str,
        role_id: i32,
    ) -> Result<Option<Vec<(Order, Vec<(OrderProduct, Product)>)>>, OrderServiceError> {
        if !self.has_permission(role_id, RolePermissions::Read).await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();
        let orders = repo.get_orders_by_role_name(role_name)
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?;
            
        if let Some(orders) = orders {
            let detailed = repo.attach_products(orders).await
                .map_err(|_| OrderServiceError::DatabaseError)?;
            Ok(Some(detailed))
        } else {
            Ok(None)
        }
    }

    /// Deletes an order
    pub async fn delete_order(&self, order_id: i32, role_id: i32) -> Result<(), OrderServiceError> {
        if !self
            .has_permission(role_id, RolePermissions::Delete)
            .await?
            && !self.has_permission(role_id, RolePermissions::Admin).await?
        {
            return Err(OrderServiceError::PermissionDenied);
        }

        let repo = OrderRepo::new();

        // Verify order exists
        repo.get_by_id(order_id)
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?
            .ok_or(OrderServiceError::OrderNotFound)?;

        repo.delete(order_id)
            .await
            .map_err(|_| OrderServiceError::OrderDeletionFailed)
    }

    async fn has_permission(
        &self,
        role_id: i32,
        required_permission: RolePermissions,
    ) -> Result<bool, OrderServiceError> {
        use crate::data::repos::implementors::role_repo::RoleRepo;
        let role_repo = RoleRepo::new();
        if let Some(role) = role_repo
            .get_by_id(role_id)
            .await
            .map_err(|_| OrderServiceError::DatabaseError)?
        {
            return Ok(role.has_permission(required_permission));
        }
        Ok(false)
    }
}

impl Default for OrderService {
    fn default() -> Self {
        Self::new()
    }
}