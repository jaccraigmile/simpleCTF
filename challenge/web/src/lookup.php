<?php
include("internal_theme.php");
include("db.php");

// Show errors while testing
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
error_reporting(E_ALL);
ini_set('display_errors', 1);
$results = null;
$sql = '';

if (isset($_GET['search']) && trim($_GET['search']) !== '') {
    $search = $_GET['search'];

    // Base query
    $sql = "
        SELECT 
            full_name,
            email,
            department,
            role_title,
            phone
        FROM staff_directory
        WHERE full_name LIKE '%$search%'
    ";
	
    // Debug: shows the exact SQL being executed
    $results = $conn->query($sql);
}
?>
<h2>Staff Directory Lookup</h2>
<form method="get">
  <input type="text" name="search" placeholder="Search by name">
  <button type="submit" class="btn">Search</button>
</form>

<?php if ($results && $results->num_rows > 0): ?>
  <table class="table">
    <tr>
      <?php
      // Dynamically print column headers
      $fields = $results->fetch_fields();
      foreach ($fields as $field) {
          echo "<th>" . htmlspecialchars($field->name) . "</th>";
      }
      ?>
    </tr>
    <?php
    // Reset pointer since we already fetched field info
    $results->data_seek(0);
    while ($row = $results->fetch_assoc()): ?>
      <tr>
        <?php foreach ($row as $value): ?>
          <td><?php echo htmlspecialchars((string)$value); ?></td>
        <?php endforeach; ?>
      </tr>
    <?php endwhile; ?>
  </table>
<?php elseif (isset($_GET['search'])): ?>
  <p>No results found.</p>
<?php else: ?>
  <p>Please enter a search term above.</p>
<?php endif; ?>

<?php include("internal_footer.php"); ?>
