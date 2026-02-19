<?php
session_start();
if ($_SESSION['role'] !== 'admin') {
    echo "Access denied.";
    exit;
}

include("internal_theme.php");

$uploadDir = __DIR__ . "/uploads";
if (!is_dir($uploadDir)) {
    mkdir($uploadDir, 0777, true); // world-writable for challenge realism
}

$message = null;

// Handle upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $target = $uploadDir . "/" . basename($file['name']);

    if (move_uploaded_file($file['tmp_name'], $target)) {
        $message = "Uploaded: " . htmlspecialchars($file['name']);
    } else {
        $message = "Upload failed.";
    }
}
?>

<h2>File Uploads</h2>
<?php include("admin_subnav.php"); ?>

<?php if ($message): ?>
  <p class="notice"><?php echo $message; ?></p>
<?php endif; ?>

<form method="post" enctype="multipart/form-data">
  <input type="file" name="file" required>
  <button type="submit" class="btn">Upload</button>
</form>

<h3>Uploaded Files</h3>
<ul>
<?php
$files = array_diff(scandir($uploadDir), ['.', '..']);
foreach ($files as $fn) {
    echo "<li><a href='uploads/" . rawurlencode($fn) . "' target='_blank'>" . htmlspecialchars($fn) . "</a></li>";
}
?>
</ul>

<?php include("internal_footer.php"); ?>
