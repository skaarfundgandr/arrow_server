-- Your SQL goes here
CREATE TABLE `user_roles` (
    role_id INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    user_id INT,
    name VARCHAR(50) NOT NULL UNIQUE,
    permissions SET('READ', 'WRITE', 'DELETE', 'ADMIN') DEFAULT 'READ',
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES users(`user_id`),
    UNIQUE (`user_id`, `role_id`) -- Ensure a user cannot have the same role multiple times
);