<?php
require "config.php";

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $name  = $_POST["full_name"];
    $email = $_POST["email"];
    $pass  = password_hash($_POST["password"], PASSWORD_DEFAULT);

    $sql = "INSERT INTO users (full_name, email, password) 
            VALUES ('$name', '$email', '$pass')";

    if (mysqli_query($conn, $sql)) {
        echo "Signup success";
    } else {
        echo "Error: " . mysqli_error($conn);
    }
}
?>
