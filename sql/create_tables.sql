-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(100) NOT NULL,
    user_password VARCHAR(255) NOT NULL,
    user_creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the wallets table
CREATE TABLE IF NOT EXISTS wallets (
    wallet_id INT AUTO_INCREMENT PRIMARY KEY,
    wallet_name VARCHAR(50) NOT NULL,
    wallet_status VARCHAR(15),
    wallet_user_id INT,
    wallet_creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (wallet_user_id) REFERENCES users(user_id)
);

-- Create the types table
CREATE TABLE IF NOT EXISTS types (
    type_id INT AUTO_INCREMENT PRIMARY KEY,
    type_name VARCHAR(50) NOT NULL
);

-- Insert the pre-defined types
INSERT INTO types (type_name) VALUES ('Needs'), ('Wants'), ('Savings and Debt Repayment');

-- Create the categories table
CREATE TABLE IF NOT EXISTS categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(50) NOT NULL,
    category_creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the subcategories table
CREATE TABLE IF NOT EXISTS subcategories (
    subcategory_id INT AUTO_INCREMENT PRIMARY KEY,
    subcategory_name VARCHAR(50) NOT NULL,
    subcategory_creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the funds table
CREATE TABLE IF NOT EXISTS funds (
    fund_id INT AUTO_INCREMENT PRIMARY KEY,
    fund_user_id INT,
    fund_amount DECIMAL(10, 2) NOT NULL,
    fund_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (fund_user_id) REFERENCES users(user_id)
);

-- Create the expenses table
CREATE TABLE IF NOT EXISTS expenses (
    expense_id INT AUTO_INCREMENT PRIMARY KEY,
	expense_user_id INT,
    expense_wallet_id INT,
    expense_type_id INT,
    expense_category_id INT,
    expense_subcategory_id INT,
    expense_amount DECIMAL(10, 2) NOT NULL,
    expense_name VARCHAR(50) NOT NULL,
    expense_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (expense_user_id) REFERENCES users(user_id),
	FOREIGN KEY (expense_wallet_id) REFERENCES wallets(wallet_id),
    FOREIGN KEY (expense_type_id) REFERENCES types(type_id),
    FOREIGN KEY (expense_category_id) REFERENCES categories(category_id),
    FOREIGN KEY (expense_subcategory_id) REFERENCES subcategories(subcategory_id)
);

-- Create the wallets_users table (to represent the many-to-many relationship between users and wallets)
CREATE TABLE IF NOT EXISTS wallets_users (
    wallet_id INT,
    user_id INT,
    PRIMARY KEY (wallet_id, user_id),
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);