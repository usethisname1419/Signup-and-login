<?php
// Include your database connection code here
$servername = "";
$username = "";
$password = "";
$dbname = "";

// Create a database connection
$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "GET") {
    // Retrieve username and token from the URL
    $username = $_GET['username']; // Change 'email' to 'username'
    $token = $_GET['token'];

    if (empty($username) || empty($token)) {
        // Username or token is missing, show an error message
        echo "Invalid reset link. Please try again.";
    } else {
        // Verify the username and token in the database
        $sql = "SELECT * FROM users WHERE username = ? AND reset_token = ? AND reset_token_expiration >= NOW()"; // Update 'email' to 'username'
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $username, $token);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            // Valid reset link, display the password reset form
            ?>
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <link rel="stylesheet" type="text/css" href="styles.css">

                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Password</title>
                <!-- Include your CSS stylesheets here -->
        
                </style>
            </head>
            <body>
                <h2>Reset Your Password</h2>
                <form class="form-group" action="update_password.php" method="post">
                    <input type="hidden" name="username" value="<?php echo $username; ?>"> <!-- Update 'email' to 'username' -->
                    <input type="hidden" name="token" value="<?php echo $token; ?>">
                    <label for="password">New Password:</label>
                    <input type="password" name="password" required>
                    <label for="confirm_password">Confirm Password:</label>
                    <input type="password" name="confirm_password" required>
                    <button type="submit">Reset Password</button>
                </form>
            </body>
            </html>
            <?php
        } else {
            // Invalid reset link, show an error message
            echo "Invalid reset link. Please try again.";
        }
    }
}

// Close the database connection
$conn->close();
?>
