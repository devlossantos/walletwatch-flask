-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- Create the wallets table
CREATE TABLE IF NOT EXISTS wallets (
    wallet_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    status VARCHAR(15)
);

-- Create the types table
CREATE TABLE IF NOT EXISTS types (
    type_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(15) NOT NULL
);

-- Insert the pre-defined types
INSERT INTO types (name) VALUES ('Basic'), ('Personal'), ('Saving');

-- Create the categories table
CREATE TABLE IF NOT EXISTS categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL
);

-- Create the expenses table
CREATE TABLE IF NOT EXISTS expenses (
    expense_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    category_id INT,
    name VARCHAR(50),
    amount DECIMAL(10, 2) NOT NULL,
    type_id INT,
    description VARCHAR(180),
    place VARCHAR(50),
    wallet_id INT,
    FOREIGN KEY (category_id) REFERENCES categories(category_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (type_id) REFERENCES types(type_id),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id)
);

-- Create the wallets_users table (to represent the many-to-many relationship between users and wallets)
CREATE TABLE IF NOT EXISTS wallets_users (
    wallet_id INT,
    user_id INT,
    PRIMARY KEY (wallet_id, user_id),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);