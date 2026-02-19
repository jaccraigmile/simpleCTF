<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>BankingAI Cloud</title>
  <link rel="stylesheet" href="style.css">
</head>
<body class="public">
<?php
  // highlight active page
  $current = basename($_SERVER['PHP_SELF']);
?>
<nav class="topnav">
  <a href="index.php" class="<?php if($current=='index.php') echo 'active'; ?>">Home</a>
  <a href="solutions.php" class="<?php if($current=='solutions.php') echo 'active'; ?>">Solutions</a>
  <a href="products.php" class="<?php if($current=='products.php') echo 'active'; ?>">Products</a>
  <a href="about.php" class="<?php if($current=='about.php') echo 'active'; ?>">About</a>
  <a href="contact.php" class="<?php if($current=='contacts.php') echo 'active'; ?>">Contacts</a>
</nav>
<div class="container">
