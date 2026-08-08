-- ============================================================================
-- Arrow Server - optional seed data
--
-- Loads the two built-in roles plus a modest starter menu (categories,
-- products and their category assignments).
--
-- NOTE: the admin USER is deliberately NOT inserted here. The admin account
-- is seeded from environment variables (ADMIN_USERNAME / ADMIN_PASSWORD) at
-- server startup, idempotently - see src/services/user_service.rs
-- (seed_admin_from_env) and src/api/server.rs.
--
-- Roles carry their permissions in a MySQL SET column on the `roles` table
-- (values: READ, WRITE, DELETE, ADMIN). The values below mirror exactly what
-- the server seeds at startup:
--   - ADMIN    -> READ, WRITE, DELETE, ADMIN
--   - CUSTOMER -> WRITE   (created by ensure_role on first registration)
--
-- Apply with:  mysql -u <user> -p <database> < seed.sql
-- Idempotency: safe to run twice only on an empty database; name columns
-- are UNIQUE so re-runs fail with a duplicate-key error instead of
-- duplicating rows.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
INSERT INTO roles (name, permissions, description) VALUES
    ('ADMIN',    'READ,WRITE,DELETE,ADMIN', 'Full administrative access: user, role, product, category and order management'),
    ('CUSTOMER', 'WRITE',                   'Regular customer: can browse the menu and place orders');

-- ---------------------------------------------------------------------------
-- Categories
-- ---------------------------------------------------------------------------
INSERT INTO categories (name, description) VALUES
    ('Drinks',  'Hot and cold beverages'),
    ('Burgers', 'Hand-made burgers and sides'),
    ('Mains',   'Grilled dishes and seafood specials');

-- ---------------------------------------------------------------------------
-- Products
--
-- Lobster Platter is priced so that a multi-item order (e.g. 2x Lobster
-- Platter = 1100.00) exceeds the default MAX_PAYMENT_AMOUNT (1000.00) and
-- demonstrates the mock-payment failure rule.
-- ---------------------------------------------------------------------------
INSERT INTO products (name, product_image_uri, description, price) VALUES
    ('Espresso',           '/img/drinks/espresso.png',           'Single shot of freshly pulled espresso', 3.50),
    ('Cappuccino',         '/img/drinks/cappuccino.png',         'Espresso with steamed milk and foam',    4.25),
    ('Fresh Orange Juice', '/img/drinks/orange-juice.png',       'Cold-pressed orange juice',              5.50),
    ('Classic Burger',     '/img/burgers/classic.png',           'Beef patty, lettuce, tomato, house sauce', 9.99),
    ('Double Smash Burger','/img/burgers/double-smash.png',      'Two smashed patties with cheddar',       13.50),
    ('Grilled Salmon',     '/img/mains/salmon.png',              'Atlantic salmon with lemon butter',      28.00),
    ('Lobster Platter',    '/img/mains/lobster.png',             'Whole grilled lobster with sides',       550.00);

-- ---------------------------------------------------------------------------
-- Product <-> category assignments
-- ---------------------------------------------------------------------------
INSERT INTO product_categories (product_id, category_id)
SELECT p.product_id, c.category_id
FROM products p
JOIN categories c ON c.name = 'Drinks'
WHERE p.name IN ('Espresso', 'Cappuccino', 'Fresh Orange Juice');

INSERT INTO product_categories (product_id, category_id)
SELECT p.product_id, c.category_id
FROM products p
JOIN categories c ON c.name = 'Burgers'
WHERE p.name IN ('Classic Burger', 'Double Smash Burger');

INSERT INTO product_categories (product_id, category_id)
SELECT p.product_id, c.category_id
FROM products p
JOIN categories c ON c.name = 'Mains'
WHERE p.name IN ('Grilled Salmon', 'Lobster Platter');
