<?php
require __DIR__ . '/config.php';
require_login();
app_log('page_view', ['page' => 'dashboard']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Dashboard — Meridian Corp Employee Portal</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="topbar">
    <a href="/">Meridian Corp Intranet</a>
    <nav class="topnav">
        <a href="/search.php">Directory Search</a>
        <?php if (($_SESSION['role'] ?? '') === 'admin'): ?>
        <a href="/admin.php">Admin</a>
        <?php endif; ?>
        <a href="/logout.php">Log Out</a>
    </nav>
</header>
<main>
    <h1>Welcome, <?= htmlspecialchars($_SESSION['username']) ?></h1>
    <p>This is your employee dashboard. From here you can search the
    employee directory and access company policy documents.</p>
    <ul>
        <li><a href="/search.php">Employee Directory Search</a></li>
        <li><a href="/docs.php">Policy Documents</a></li>
        <li><a href="/contact.php">Contact IT</a></li>
    </ul>
</main>
<footer>Meridian Corp — Internal Use Only</footer>
</body>
</html>
