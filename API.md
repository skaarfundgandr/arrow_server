# Arrow Server API Documentation

**Base URL:** `http://127.0.0.1:3000/api/v1`

## Authentication

### Login
Authenticate a user and receive a JWT token.

*   **URL:** `/auth/login`
*   **Method:** `POST`
*   **Auth Required:** No
*   **Body:** `LoginDTO`
    ```json
    {
      "username": "adminuser",
      "password": "password123"
    }
    ```
*   **Response:** `LoginResponse`
    ```json
    {
      "token": "eyJhbGciOiJIUzI1Ni...",
      "message": "Login successful"
    }
    ```

### Register
Register a new user. Public registration is only open if the database is empty (creates the first Admin).

*   **URL:** `/auth/register`
*   **Method:** `POST`
*   **Auth Required:** No
*   **Body:** `NewUserDTO`
    ```json
    {
      "username": "newuser",
      "password": "password123"
    }
    ```
*   **Response:** `LoginResponse` (201 Created)

### Refresh Token
Refresh the current JWT token.

*   **URL:** `/auth/refresh`
*   **Method:** `GET`
*   **Auth Required:** Yes (Bearer Token)
*   **Response:** `LoginResponse`

---

## Users

### Get All Users
Retrieve a list of all users.

*   **URL:** `/users`
*   **Method:** `GET`
*   **Auth Required:** Yes
*   **Response:** `Vec<UserDTO>`
    ```json
    [
      {
        "user_id": 1,
        "username": "admin",
        "role": { ... },
        "created_at": "20/12/2025",
        "updated_at": "20/12/2025"
      }
    ]
    ```

### Create User (Admin)
Create a new user manually.

*   **URL:** `/users/create`
*   **Method:** `POST`
*   **Auth Required:** Yes (Admin)
*   **Body:** `NewUserDTO`
*   **Response:** 201 Created

### Get User by ID
*   **URL:** `/users/:id`
*   **Method:** `GET`
*   **Auth Required:** Yes
*   **Response:** `UserDTO`

### Search User by Name
*   **URL:** `/users/search?username=...`
*   **Method:** `GET`
*   **Auth Required:** Yes
*   **Query Params:** `username`
*   **Response:** `UserDTO`

### Edit User (Admin)
*   **URL:** `/users/:id`
*   **Method:** `POST`
*   **Auth Required:** Yes (Admin)
*   **Body:** `UpdateUserDTO`
    ```json
    {
      "username": "updated_name",
      "password": "new_password" // Optional
    }
    ```
*   **Response:** 200 OK

### Delete User (Admin)
*   **URL:** `/users/:id`
*   **Method:** `DELETE`
*   **Auth Required:** Yes (Admin)
*   **Response:** 200 OK

---

## Roles

### Get All Roles (Admin)
*   **URL:** `/roles`
*   **Method:** `GET`
*   **Response:** `Vec<RoleDTO>`

### Create Role (Admin)
*   **URL:** `/roles/create`
*   **Method:** `POST`
*   **Body:** `NewRoleDTO`
    ```json
    {
      "name": "Manager",
      "description": "Store manager"
    }
    ```
*   **Response:** 201 Created

### Update Role (Admin)
*   **URL:** `/roles/update/:id`
*   **Method:** `POST`
*   **Body:** `UpdateRoleDTO`
*   **Response:** 200 OK

### Delete Role (Admin)
*   **URL:** `/roles/:id`
*   **Method:** `DELETE`
*   **Response:** 200 OK

### Assign Role to User (Admin)
*   **URL:** `/roles/assign`
*   **Method:** `POST`
*   **Body:** `AssignRoleDTO`
    ```json
    {
      "username": "target_user",
      "role_name": "Manager"
    }
    ```
*   **Response:** 201 Created

### Add Permission to Role (Admin)
*   **URL:** `/roles/add_permission`
*   **Method:** `POST`
*   **Body:** `AddPermissionRequest`
    ```json
    {
      "role_name": "Manager",
      "permission": "WRITE" // READ, WRITE, DELETE, ADMIN
    }
    ```

### Set Permission (Overwrite) (Admin)
*   **URL:** `/roles/:id/set_permission`
*   **Method:** `POST`
*   **Body:** `SetPermissionDTO`
    ```json
    { "permission": "READ" }
    ```

### Remove Permission (Reset to Read) (Admin)
*   **URL:** `/roles/:id/delete_permission`
*   **Method:** `PATCH`
*   **Response:** 200 OK

---

## Products

### Get All Products
*   **URL:** `/products`
*   **Method:** `GET`
*   **Response:** `Vec<ProductResponse>`

### Get Product by ID
*   **URL:** `/products/:id`
*   **Method:** `GET`
*   **Response:** `ProductResponse`

### Create Product
*   **URL:** `/products`
*   **Method:** `POST`
*   **Body:** `CreateProductRequest`
    ```json
    {
      "name": "Burger",
      "description": "Beef burger",
      "price": "9.99",
      "product_image_uri": "/img/burger.png",
      "categories": ["Food"]
    }
    ```
*   **Response:** 201 Created

### Update Product
*   **URL:** `/products/:id`
*   **Method:** `PUT`
*   **Body:** `UpdateProductRequest`
*   **Response:** 200 OK

### Delete Product
*   **URL:** `/products/:id`
*   **Method:** `DELETE`
*   **Response:** 200 OK

---

## Categories

### Get All Categories
*   **URL:** `/categories`
*   **Method:** `GET`
*   **Response:** `Vec<CategoryResponse>`

### Get Products by Category
*   **URL:** `/categories/:category_name/products`
*   **Method:** `GET`
*   **Response:** `Vec<ProductCategoryResponse>`

### Create Category
*   **URL:** `/categories`
*   **Method:** `POST`
*   **Body:** `CreateCategoryRequest`
    ```json
    {
      "name": "Food",
      "description": "Edible items"
    }
    ```
*   **Response:** 201 Created

### Edit Category
*   **URL:** `/categories/:id`
*   **Method:** `PUT`
*   **Body:** `UpdateCategoryRequest`
*   **Response:** 201 Created

### Delete Category
*   **URL:** `/categories/:id`
*   **Method:** `DELETE`
*   **Response:** 200 OK

### Add Product to Category
*   **URL:** `/categories/product`
*   **Method:** `POST`
*   **Body:** `AssignCategoryRequest`
    ```json
    {
      "category": "Food",
      "product": "Burger"
    }
    ```

### Remove Product from Category
*   **URL:** `/categories/product/remove`
*   **Method:** `POST`
*   **Body:** `AssignCategoryRequest`

---

## Orders

### Get All Orders
*   **URL:** `/orders`
*   **Method:** `GET`
*   **Response:** `Vec<OrderResponse>`

### Create Order
*   **URL:** `/orders`
*   **Method:** `POST`
*   **Body:** `CreateOrderRequest`
    ```json
    {
      "products": [
        { "product_id": 1, "quantity": 2 }
      ]
    }
    ```
*   **Response:** 201 Created

### Get Order by ID
*   **URL:** `/orders/:id`
*   **Method:** `GET`
*   **Response:** `OrderResponse`

### Update Order Status
*   **URL:** `/orders/:id`
*   **Method:** `POST`
*   **Body:** `UpdateOrderStatusRequest`
    ```json
    { "status": "completed" }
    ```
*   **Response:** 200 OK

### Get User Orders
*   **URL:** `/orders/user/:username`
*   **Method:** `GET`
*   **Response:** `Vec<OrderResponse>`

### Get Orders by Role
*   **URL:** `/orders/role/:role_name`
*   **Method:** `GET`
*   **Response:** `Vec<OrderResponse>`
