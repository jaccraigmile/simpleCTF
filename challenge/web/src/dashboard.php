<?php
session_start();
if (!isset($_SESSION['user'])) {
    header("Location: login.php");
    exit;
}

include("internal_theme.php");
include("db.php");

$user = $_SESSION['user'];

$sql = "SELECT attempt_time, success, ip_address
        FROM login_attempts
        WHERE username=?
        ORDER BY attempt_time DESC
        LIMIT 10";

$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $user);
$stmt->execute();
$result = $stmt->get_result();
?>
<h2>Welcome, <?php echo htmlspecialchars($user); ?></h2>
<p>Your role: <?php echo htmlspecialchars($_SESSION['role']); ?></p>

<div class="card">
  <h3>System Notice</h3>
  <p>Login token: <code><?php echo getenv('FLAG_LOGIN'); ?></code></p>
</div>

<div class="card">
  <h3>Recent Login Attempts</h3>
  <table class="table">
    <tr><th>Time</th><th>Status</th><th>IP Address</th></tr>
    <?php while($row = $result->fetch_assoc()): ?>
      <tr>
        <td><?php echo htmlspecialchars($row['attempt_time']); ?></td>
        <td>
          <?php 
            echo $row['success'] 
              ? "<span class='status success'>Success</span>" 
              : "<span class='status failed'>Failed</span>"; 
          ?>
        </td>
        <td><?php echo htmlspecialchars($row['ip_address']); ?></td>
      </tr>
    <?php endwhile; ?>
  </table>
</div>

<div class="card">
  <h3>Quick Links</h3>
  <ul>
    <li><a href="lookup.php">Staff Lookup</a></li>
    <li><a href="ittools.php">IT Tools</a></li>
    <?php if($_SESSION['role'] === 'admin'): ?>
      <li><a href="admin.php">Admin Panel</a></li>
    <?php endif; ?>
  </ul>
</div>

<?php 
$stmt->close();
include("internal_footer.php"); 
?>
