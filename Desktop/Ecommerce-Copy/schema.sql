-- Run once:  psql -U postgres -c "CREATE DATABASE IF NOT EXISTS ecommerce-db;"
--            psql -U postgres -d ecommerce-db -f schema.sql

DROP TABLE IF EXISTS customers, order_items, orders, items, brand_setup, type_setup, category_setup, group_setup CASCADE;

-- Hierarchy: group -> category -> type -> brand
CREATE TABLE group_setup (
    group_id   SERIAL PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE category_setup (
    category_id   SERIAL PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL,
    group_id      INT NOT NULL REFERENCES group_setup(group_id) ON DELETE RESTRICT,
    UNIQUE (group_id, category_name)
);

CREATE TABLE type_setup (
    type_id     SERIAL PRIMARY KEY,
    type_name   VARCHAR(100) NOT NULL,
    category_id INT NOT NULL REFERENCES category_setup(category_id) ON DELETE RESTRICT,
    UNIQUE (category_id, type_name)
);

CREATE TABLE brand_setup (
    brand_id   SERIAL PRIMARY KEY,
    brand_name VARCHAR(100) NOT NULL,
    type_id    INT NOT NULL REFERENCES type_setup(type_id) ON DELETE RESTRICT,
    UNIQUE (type_id, brand_name)
);

-- Items: brand_id is the single link into the hierarchy;
-- type, category and group are derived through the foreign-key chain.
CREATE TABLE items (
    sku           VARCHAR(50) PRIMARY KEY,
    name          VARCHAR(200) NOT NULL,
    qty           INT NOT NULL CHECK (qty >= 0),
    rate          NUMERIC(12,2) NOT NULL CHECK (rate >= 0),
    amount        NUMERIC(14,2) GENERATED ALWAYS AS (qty * rate) STORED,
    closing_stock INT NOT NULL CHECK (closing_stock >= 0),
    color         VARCHAR(50),
    size          VARCHAR(50),
    brand_id      INT NOT NULL REFERENCES brand_setup(brand_id) ON DELETE RESTRICT,
    image_filename VARCHAR(255),
    product_code  VARCHAR(50),
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Sample data
INSERT INTO group_setup (group_name) VALUES ('Apparel'), ('Electronics');
INSERT INTO category_setup (category_name, group_id) VALUES ('Menswear', 1), ('Mobiles', 2);
INSERT INTO type_setup (type_name, category_id) VALUES ('T-Shirts', 1), ('Smartphones', 2);
INSERT INTO brand_setup (brand_name, type_id) VALUES ('Nike', 1), ('Adidas', 1), ('Samsung', 2), ('Apple', 2);
INSERT INTO items (sku, name, qty, rate, closing_stock, color, size, brand_id) VALUES
    ('TS-001', 'Dri-FIT Running Tee', 40, 29.99, 36, 'Black', 'M', 1),
    ('SP-001', 'Galaxy S Series 128GB', 15, 699.00, 12, 'Silver', '6.1"', 3);

-- Customer orders (shop)

CREATE TABLE IF NOT EXISTS orders (
    order_id      SERIAL PRIMARY KEY,
    customer_name VARCHAR(150) NOT NULL,
    email         VARCHAR(150) NOT NULL,
    phone         VARCHAR(30)  NOT NULL,
    address       TEXT NOT NULL,
    total         NUMERIC(14,2) NOT NULL,
    status        VARCHAR(20) NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'shipped', 'delivered', 'cancelled')),
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Name, color, size and rate are copied at purchase time so old orders stay correct
-- even if the item is later edited or deleted (sku becomes NULL if the item is deleted).
CREATE TABLE IF NOT EXISTS order_items (
    order_item_id SERIAL PRIMARY KEY,
    order_id      INT NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
    sku           VARCHAR(50) REFERENCES items(sku) ON DELETE SET NULL,
    item_name     VARCHAR(200) NOT NULL,
    color         VARCHAR(50),
    size          VARCHAR(50),
    qty           INT NOT NULL CHECK (qty > 0),
    rate          NUMERIC(12,2) NOT NULL,
    line_total    NUMERIC(14,2) GENERATED ALWAYS AS (qty * rate) STORED
);

CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);

-- Customer accounts (login)

CREATE TABLE IF NOT EXISTS customers (
    customer_id   SERIAL PRIMARY KEY,
    username      VARCHAR(30) NOT NULL,
    email         VARCHAR(150),
    password_hash TEXT,                 -- NULL for accounts created with Google
    google_sub    VARCHAR(64) UNIQUE,   -- Google's stable user id, NULL for username accounts
    created_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK (password_hash IS NOT NULL OR google_sub IS NOT NULL)
);
-- usernames are unique regardless of upper/lower case ("Sam" and "sam" are the same name)
CREATE UNIQUE INDEX IF NOT EXISTS customers_username_lower_key ON customers (LOWER(username));

CREATE TABLE IF NOT EXISTS customers (
    customer_id   SERIAL PRIMARY KEY,
    username      VARCHAR(30) NOT NULL,
    email         VARCHAR(150),
    password_hash TEXT,                 -- NULL for accounts created with Google
    google_sub    VARCHAR(64) UNIQUE,   -- Google's stable user id, NULL for username accounts
    created_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK (password_hash IS NOT NULL OR google_sub IS NOT NULL)
);
-- usernames are unique regardless of upper/lower case ("Sam" and "sam" are the same name)
CREATE UNIQUE INDEX IF NOT EXISTS customers_username_lower_key ON customers (LOWER(username));

-- Contact form messages (the app also creates this table automatically on first use)
CREATE TABLE IF NOT EXISTS contact_messages (
    message_id SERIAL PRIMARY KEY,
    first_name VARCHAR(80)  NOT NULL,
    last_name  VARCHAR(80)  NOT NULL,
    email      VARCHAR(150) NOT NULL,
    topic      VARCHAR(60)  NOT NULL,
    message    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
