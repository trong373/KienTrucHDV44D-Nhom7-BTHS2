create database bths2;
use bths2;
CREATE TABLE User (
    IdUser INT AUTO_INCREMENT PRIMARY KEY,
    UserName VARCHAR(255) NOT NULL UNIQUE,
    Password VARCHAR(255) NOT NULL,
    Token VARCHAR(255)
);
