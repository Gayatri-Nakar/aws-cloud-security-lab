<?php
require __DIR__ . '/config.php';

// Log every hit to this endpoint regardless of auth state — unauthenticated
// or unauthorized requests here are exactly the enumeration/forced-browsing
// signal this page exists to capture.
app_log('admin_page_access_attempt', [
    'authenticated' => is_logged_in(),
    'role'          => $_SESSION['role'] ?? null,
]);

if (!is_logged_in() || ($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>Forbidden</title><link rel="stylesheet" href="style.css"></head>
    <body>
    <header class="topbar"><a href="/">Meridian Corp Intranet</a></header>
    <main><h1>403 Forbidden</h1><p>You do not have permission to access this page.</p></main>
    </body>
    </html>
    <?php
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin — Meridian Corp Employee Portal</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="topbar">
    <a href="/">Meridian Corp Intranet</a>
    <nav class="topnav"><a href="/dashboard.php">Dashboard</a> <a href="/logout.php">Log Out</a></nav>
</header>
<main>
    <h1>Administration</h1>
    <p>System administration tools would appear here in a production
    deployment. This is a placeholder page.</p>
</main>
<footer>Meridian Corp — Internal Use Only</footer>
</body>
</html>
