CREATE DATABASE IF NOT EXISTS agrilinkk;

USE agrilinkk;


-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    phone VARCHAR(15) NOT NULL,
    role ENUM(
        'Farmer',
        'MSME',
        'Logistics',
        'Community',
        'Apartment',
        'Admin'
    ) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- FARMERS TABLE
CREATE TABLE IF NOT EXISTS farmers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    land_area DECIMAL(10,2),
    land_location VARCHAR(255),
    crop_name VARCHAR(100),
    farming_type ENUM('Organic', 'Pesticide') DEFAULT 'Organic',
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);


-- PRODUCTS TABLE
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    farmer_id INT NOT NULL,
    product_name VARCHAR(100) NOT NULL,
    quantity DECIMAL(10,2) NOT NULL,
    grade ENUM('A', 'B', 'C') NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (farmer_id) REFERENCES farmers(id)
        ON DELETE CASCADE
);


-- MSME TABLE
CREATE TABLE IF NOT EXISTS msmes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    company_name VARCHAR(150) NOT NULL,
    business_type VARCHAR(100),
    address VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);


-- LOGISTICS TABLE
CREATE TABLE IF NOT EXISTS logistics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    company_name VARCHAR(150),
    vehicle_type VARCHAR(100),
    service_area VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);


-- COMMUNITY TABLE
CREATE TABLE IF NOT EXISTS communities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    community_name VARCHAR(150),
    location VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);


-- APARTMENT TABLE
CREATE TABLE IF NOT EXISTS apartments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    apartment_name VARCHAR(150),
    location VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);