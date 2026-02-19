<?php
if (session_status() === PHP_SESSION_NONE) session_start();
if (!isset($_SESSION['user'])) {
    header("Location: login.php");
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>BankingAI Internal</title>
  <link rel="stylesheet" href="style.css">
</head>
<body class="internal">
<nav class="topnav">
  <a href="dashboard.php">Dashboard</a>
  <a href="lookup.php">Staff Lookup</a>
  <a href="ittools.php">IT Tools</a>
  <?php if ($_SESSION['role'] === 'admin'): ?>
    <a href="admin.php">Admin Panel</a>
  <?php endif; ?>
  <a href="logout.php">Logout (<?php echo htmlspecialchars($_SESSION['user']); ?>)</a>
</nav>
<div class="container">
