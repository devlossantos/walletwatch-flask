use walletwatch_db;

CREATE TABLE IF NOT EXISTS users (
  user_id int NOT NULL AUTO_INCREMENT,
  user_email varchar(100) NOT NULL,
  user_password varchar(255) NOT NULL,
  user_creation_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id)
);

CREATE TABLE IF NOT EXISTS wallets (
  wallet_id int NOT NULL AUTO_INCREMENT,
  wallet_name varchar(30) NOT NULL,
  wallet_status varchar(15) DEFAULT NULL,
  wallet_user_id int DEFAULT NULL,
  wallet_creation_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (wallet_id),
  KEY wallet_user_id (wallet_user_id),
  CONSTRAINT wallets_ibfk_1 FOREIGN KEY (wallet_user_id) REFERENCES users (user_id)
);

CREATE TABLE IF NOT EXISTS types (
  type_id int NOT NULL AUTO_INCREMENT,
  type_name varchar(50) NOT NULL,
  PRIMARY KEY (type_id)
);

INSERT INTO types VALUES (1,'Needs'),(2,'Wants'),(3,'Savings and Debt Repayment');

CREATE TABLE IF NOT EXISTS categories (
  category_id int NOT NULL AUTO_INCREMENT,
  category_name varchar(30) NOT NULL,
  category_creation_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (category_id)
);

CREATE TABLE IF NOT EXISTS subcategories (
  subcategory_id int NOT NULL AUTO_INCREMENT,
  subcategory_name varchar(30) NOT NULL,
  subcategory_creation_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (subcategory_id)
);

CREATE TABLE IF NOT EXISTS expenses (
  expense_id int NOT NULL AUTO_INCREMENT,
  expense_user_id int DEFAULT NULL,
  expense_wallet_id int DEFAULT NULL,
  expense_type_id int DEFAULT NULL,
  expense_category_id int DEFAULT NULL,
  expense_subcategory_id int DEFAULT NULL,
  expense_amount decimal(10,2) NOT NULL,
  expense_name varchar(30) NOT NULL,
  expense_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (expense_id),
  KEY expense_user_id (expense_user_id),
  KEY expense_wallet_id (expense_wallet_id),
  KEY expense_type_id (expense_type_id),
  KEY expense_category_id (expense_category_id),
  KEY expense_subcategory_id (expense_subcategory_id),
  CONSTRAINT expenses_ibfk_1 FOREIGN KEY (expense_user_id) REFERENCES users (user_id),
  CONSTRAINT expenses_ibfk_2 FOREIGN KEY (expense_wallet_id) REFERENCES wallets (wallet_id),
  CONSTRAINT expenses_ibfk_3 FOREIGN KEY (expense_type_id) REFERENCES types (type_id),
  CONSTRAINT expenses_ibfk_4 FOREIGN KEY (expense_category_id) REFERENCES categories (category_id),
  CONSTRAINT expenses_ibfk_5 FOREIGN KEY (expense_subcategory_id) REFERENCES subcategories (subcategory_id)
);

CREATE TABLE IF NOT EXISTS funds (
  fund_id int NOT NULL AUTO_INCREMENT,
  fund_user_id int DEFAULT NULL,
  fund_amount decimal(10,2) NOT NULL,
  fund_date timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (fund_id),
  KEY fund_user_id (fund_user_id),
  CONSTRAINT funds_ibfk_1 FOREIGN KEY (fund_user_id) REFERENCES users (user_id)
);

CREATE TABLE IF NOT EXISTS wallets_users (
  wallet_id int NOT NULL,
  user_id int NOT NULL,
  PRIMARY KEY (wallet_id,user_id),
  KEY user_id (user_id),
  CONSTRAINT wallets_users_ibfk_1 FOREIGN KEY (wallet_id) REFERENCES wallets (wallet_id),
  CONSTRAINT wallets_users_ibfk_2 FOREIGN KEY (user_id) REFERENCES users (user_id)
);