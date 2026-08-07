-- This file should undo anything in `up.sql`
ALTER TABLE orders MODIFY status VARCHAR(50) DEFAULT 'pending';
ALTER TABLE orders DROP COLUMN payment_status;
ALTER TABLE orders MODIFY user_id INT NOT NULL;
