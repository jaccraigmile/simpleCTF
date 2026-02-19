<?php
session_start();
include("db.php");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'] ?? '';
    $pass = $_POST['password'] ?? '';

    $stmt = $conn->prepare(
        "SELECT username, role FROM users
         WHERE username = ? AND password = MD5(?)
         LIMIT 1"
    );
    $stmt->bind_param("ss", $user, $pass);
    $stmt->execute();
    $res = $stmt->get_result();

    $success = 0;
    if ($res && $res->num_rows === 1) {
        $row = $res->fetch_assoc();
        $_SESSION['user'] = $row['username'];
        $_SESSION['role'] = $row['role'];
        $success = 1;
        header("Location: dashboard.php");
        exit;
    } else {
        $error = "Invalid credentials.";
    }
    $stmt->close();

    // Logging block
       $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';

    $stmt = $conn->prepare(
        "INSERT INTO login_attempts (username, attempt_time, success, ip_address, user_agent)
         VALUES (?, NOW(), ?, ?, ?)"
    );
    if ($stmt) {
        $stmt->bind_param("siss", $user, $success, $ip, $ua);
        $stmt->execute();
        $stmt->close();
    }
}
?>

<?php include("public_theme.php"); ?>

<h2>Employee Login</h2>

<?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>

<form method="post">
  <label>Username</label><br>
  <input type="text" name="username" autocomplete="off"><br>
<label>Password</label><br>
  <input type="password" name="password" autocomplete="off"><br>
  <button type="submit" class="btn">Login</button>
</form>

<?php include("public_footer.php"); ?>
