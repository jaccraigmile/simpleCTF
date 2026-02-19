<?php
session_start();
if ($_SESSION['role'] !== 'admin') { echo "Access denied."; exit; }
include("internal_theme.php");
include("db.php");
?>

<h2>User Management</h2>
<?php include("admin_subnav.php"); ?>

<?php
$res = $conn->query("SELECT id, username, role FROM users ORDER BY role, username");
if ($res && $res->num_rows > 0): ?>
  <table class="table">
    <tr><th>ID</th><th>Username</th><th>Role</th></tr>
    <?php while ($row = $res->fetch_assoc()): ?>
      <tr>
        <td><?php echo $row['id']; ?></td>
        <td><?php echo htmlspecialchars($row['username']); ?></td>
        <td><?php echo htmlspecialchars($row['role']); ?></td>
      </tr>
    <?php endwhile; ?>
  </table>
<?php else: ?>
  <p>No users found.</p>
<?php endif; ?>

<?php include("internal_footer.php"); ?>
