<?php
// Enable error reporting (use only in development)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Database configuration
$servername = "localhost";
$username   = "root";
$password   = "";
$dbname     = "parc";

// Create connection using MySQLi (Object-Oriented)
$conn = new mysqli($servername, $username, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

?>
