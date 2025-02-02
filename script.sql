-- Créer la base de données
CREATE DATABASE IF NOT EXISTS auth_project;

-- Utiliser la base de données
USE auth_project;

-- Créer la table 'users'
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
