<?php
session_start();
if ($_SESSION['role'] !== 'admin') { echo "Access denied."; exit; }
include("internal_theme.php");
?>

<h2>Admin Dashboard</h2>
<?php include("admin_subnav.php"); ?> <!-- or paste subnav directly -->

<div class="card">
  <h3>System Overview</h3>
  <p>Users: 42<br> Active Sessions: 5<br> Pending Tickets: 3</p>
</div>

<div class="card">
  <h3>Quick Links</h3>
  <ul>
    <li><a href="admin_users.php">Manage Users</a></li>
    <li><a href="admin_logs.php">View Login Logs</a></li>
    <li><a href="admin_uploads.php">File Uploads</a></li>
  </ul>
</div>

<?php include("internal_footer.php"); ?>
