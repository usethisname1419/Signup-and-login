<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $servername = "";
    $username = "";
    $password = "";
    $dbname = "";

    // Create a new mysqli connection
    $conn = new mysqli($servername, $username, $password, $dbname);

    // Check if the connection was successful
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Capture the user's IP address
    $user_ip = $_SERVER['REMOTE_ADDR'];

    // Validate and sanitize user inputs
    $username = $_POST['username'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $recaptchaResponse = $_POST['g-recaptcha-response'];

    // Verify reCAPTCHA
    $recaptchaSecretKey = "key"; // Replace with your Secret Key

    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = array(
        'secret' => $recaptchaSecretKey,
        'response' => $recaptchaResponse
    );

    $options = array(
        'http' => array(
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        )
    );

    $context = stream_context_create($options);
    $verify = file_get_contents($url, false, $context);
    $captcha_success = json_decode($verify);

    if ($captcha_success->success) {
        // CAPTCHA verification passed

        if (!filter_var($username, FILTER_VALIDATE_EMAIL)) {
            echo "Must be a valid Email address.";
        } elseif ($password !== $confirm_password) {
            echo "Passwords do not match.";
        } elseif (strlen($password) < 8 || !preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
            echo "Password must be at least 8 characters and contain at least one special character.";
        } else {
            $hashedPassword = $password;

            // Insert user data into the database
            $stmt = $conn->prepare("INSERT INTO users (username, password, registration_ip) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $hashedPassword, $user_ip);

            if ($stmt->execute()) {
                echo "Registration successful. You can now <a href='login.html'>log in</a>.";
            } else {
                echo "Error: " . $stmt->error;
            }
            $stmt->close();
        }
    } else {
        // CAPTCHA verification failed
        echo "CAPTCHA verification failed. Please try again.";
    }

    // Close the database connection
    $conn->close();
}
?>
