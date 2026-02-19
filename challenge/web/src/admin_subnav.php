<nav class="subnav">
  <a href="admin.php">Dashboard</a>
  <a href="admin_users.php">User Management</a>
  <a href="admin_logs.php">Login Logs</a>
  <a href="admin_uploads.php">File Uploads</a>
  <a href="logout.php"><?php echo getenv('FLAG_ADMIN_ACCESS'); ?></a>
</nav>
