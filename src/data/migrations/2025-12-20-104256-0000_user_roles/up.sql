-- Your SQL goes here
-- Your SQL goes here
CREATE TABLE `user_roles` (
    role_id INT NOT NULL,
    user_id INT NOT NULL UNIQUE, -- Each user can have only one role
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (`user_id`) REFERENCES users(`user_id`) ON DELETE CASCADE,
    FOREIGN KEY (`role_id`) REFERENCES roles(`role_id`) ON DELETE CASCADE,
    PRIMARY KEY (`user_id`, `role_id`) -- Ensure a user cannot have the same role multiple times
);