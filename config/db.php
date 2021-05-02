<?php
require_once 'constants.php';

$conn = new mysqli('localhost', 'root', '', 'email');

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
