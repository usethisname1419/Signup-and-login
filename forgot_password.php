<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email']; // Change variable name to $email

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
         echo "Invalid email address: " . $email; // Use $email here
        exit();
    }

    $servername = "";
    $dbUsername = ""; // Change to your database username
    $dbPassword = ""; // Change to your database password
    $dbname = "";

    // Create a database connection
    $conn = new mysqli($servername, $dbUsername, $dbPassword, $dbname);

    // Check if the connection was successful
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Generate a unique token
    $token = bin2hex(random_bytes(32));

    // Set the token expiration time (e.g., 1 hour from now)
    $tokenExpiration = date("Y-m-d H:i:s", strtotime("+1 hour"));

    // Check if the email exists in your database
    $sql = "SELECT * FROM users WHERE username = ?"; // Update the query to use username
    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        echo "Error preparing SQL statement: " . $conn->error;
    } else {
        $stmt->bind_param("s", $email); // Use $email here
        $stmt->execute();
        $result = $stmt->get_result();
    
        if ($result->num_rows == 1) {
            // Update the user's token and token expiration time in the database
            $sql = "UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE username = ?";
            $stmt = $conn->prepare($sql);

            if (!$stmt) {
                echo "Error preparing SQL statement: " . $conn->error;
            } else {
                $stmt->bind_param("sss", $token, $tokenExpiration, $email); // Use $email here

                if ($stmt->execute()) {
                    // Compose the email message
                    $subject = "Password Reset Request";
                    $message = "To reset your password, click the following link:\n\n";
                    $message .= "https://website/reset_password.php?username=" . urlencode($email) . "&token=" . $token; // Use $email here

                    // Send the email
                    $headers = ""; // Replace with your email address
                    if (mail($email, $subject, $message, $headers)) { // Use $email here
                        echo "Password reset instructions sent to your email.";
                    } else {
                        echo "Failed to send password reset instructions.";
                    }
                } else {
                    echo "Error updating reset token: " . $stmt->error;
                }
            }
        } else {
            echo "Username not found.";
        }

        $stmt->close();
    }

    // Close the database connection
    $conn->close();
}
?>
