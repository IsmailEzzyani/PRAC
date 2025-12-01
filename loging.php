<?php
require "config.php";
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $email = $_POST["email"];
    $pass  = $_POST["password"];

    // Select user by email
    $result = mysqli_query($conn, "SELECT * FROM users WHERE email='$email'");

    if ($result && mysqli_num_rows($result) > 0) {
        $user = mysqli_fetch_assoc($result);

        // Check password
        if (password_verify($pass, $user["password"])) {
            $_SESSION["user_id"] = $user["id"];
            echo "Login_OK";
        } else {
            echo "Wrong email or password";
        }
    } else {
        echo "Wrong email or password";
    }
}
?>
