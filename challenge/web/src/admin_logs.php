<?php
session_start();
if ($_SESSION['role'] !== 'admin') { 
    echo "Access denied."; 
    exit; 
}
include("internal_theme.php");
include("db.php");
?>

<h2>Login Attempts</h2>
<nav class="subnav">
  <a href="admin.php">Dashboard</a>
  <a href="admin_users.php">User Management</a>
  <a href="admin_logs.php">Login Logs</a>
  <a href="admin_uploads.php">File Uploads</a>
</nav>

<?php
$res = $conn->query("SELECT username, attempt_time, success, ip_address, user_agent 
                     FROM login_attempts 
                     ORDER BY attempt_time DESC 
                     LIMIT 20");

if ($res && $res->num_rows > 0): ?>
  <table class="table">
    <tr>
      <th>User</th>
      <th>Time</th>
      <th>Success</th>
      <th>IP</th>
      <th>User Agent</th>
    </tr>
    <?php while ($row = $res->fetch_assoc()): ?>
      <tr>
        <td><?php echo htmlspecialchars($row['username']); ?></td>
        <td><?php echo htmlspecialchars($row['attempt_time']); ?></td>
        <td><?php echo $row['success'] ? "✔" : "✖"; ?></td>
        <td><?php echo htmlspecialchars($row['ip_address']); ?></td>
        <td><?php echo htmlspecialchars($row['user_agent']); ?></td>
      </tr>
    <?php endwhile; ?>
  </table>
<?php else: ?>
  <p>No login attempts recorded.</p>
<?php endif; ?>

<?php include("internal_footer.php"); ?>
