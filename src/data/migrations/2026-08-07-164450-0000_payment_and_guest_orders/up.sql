-- Your SQL goes here
ALTER TABLE orders MODIFY user_id INT NULL;
ALTER TABLE orders ADD COLUMN payment_status VARCHAR(20) NOT NULL DEFAULT 'unpaid';
ALTER TABLE orders MODIFY status VARCHAR(50) NOT NULL DEFAULT 'Pending';
UPDATE orders SET status='Pending' WHERE status='pending';
