create database prac;

use prac;

create table user(
id int AUTO_INCREMENT PRIMARY KEY ,
full_name VARCHAR(100) NOT NULL,
email VARCHAR(150) NOT NULL UNIQUE,
password VARCHAR(255) NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
);