<?php
// Include your database connection code here

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Retrieve email, token, and new password from the form
    $email = $_POST['email'];
    $token = $_POST['token'];
    $newPassword = $_POST['password'];
    $confirmPassword = $_POST['confirm_password'];

    if (empty($email) || empty($token) || empty($newPassword) || empty($confirmPassword)) {
        // One or more fields are missing, show an error message
        echo "All fields are required. Please try again.";
        exit();
    }

    if ($newPassword !== $confirmPassword) {
        // Passwords do not match, show an error message
        echo "Passwords do not match. Please try again.";
        exit();
    }

    // Verify the email and token in the database
    $sql = "SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_token_expiration >= NOW()";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $email, $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows == 1) {
        // Valid email and token, update the user's password
        // For debugging, you can set the password directly without hashing
        $updateSql = "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?";
        $updateStmt = $conn->prepare($updateSql);
        $updateStmt->bind_param("ss", $newPassword, $email);

        if ($updateStmt->execute()) {
            // Password updated successfully
            echo "Password updated successfully. You can now <a href='login.php'>login</a> with your new password.";
        } else {
            // Error updating password
            echo "Error updating password. Please try again.";
        }
    } else {
        // Invalid email or token, show an error message
        echo "Invalid request. Please try again.";
    }
}
?>
