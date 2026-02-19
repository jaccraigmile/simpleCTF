<?php
// Database connection settings
$servername = "db";          // Docker service name
$username   = "admin";        // your DB user
$password   = "password";        // your DB password
$dbname     = "bankingai";     // your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
?>
