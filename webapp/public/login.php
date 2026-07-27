<?php
require __DIR__ . '/config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Deliberately not length/charset-restricted beyond a sane cap — the
    // point of this form is to observe what gets submitted to it, not to
    // aggressively pre-filter input before it's logged.
    $username = substr((string)($_POST['username'] ?? ''), 0, 255);
    $password = substr((string)($_POST['password'] ?? ''), 0, 255);

    $db = get_db();
    $stmt = $db->prepare('SELECT * FROM employees WHERE username = :u');
    $stmt->execute([':u' => $username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    $success = $user && password_verify($password, $user['password_hash']);

    // Record every attempt in the database...
    $logStmt = $db->prepare(
        'INSERT INTO login_attempts (ts, source_ip, username_attempted, success, user_agent)
         VALUES (:ts, :ip, :username, :success, :ua)'
    );
    $logStmt->execute([
        ':ts'       => gmdate('c'),
        ':ip'       => client_ip(),
        ':username' => $username,
        ':success'  => $success ? 1 : 0,
        ':ua'       => $_SERVER['HTTP_USER_AGENT'] ?? '',
    ]);

    // ...and in the structured application log used for later analysis.
    // Note: password value itself is intentionally NOT logged in plaintext
    // to app.log; only whether the attempt succeeded and which username
    // was tried. This keeps the raw log safer to handle even before the
    // sanitization pass.
    app_log('login_attempt', [
        'username_attempted' => $username,
        'success'             => $success,
    ]);

    if ($success) {
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        header('Location: /dashboard.php');
        exit;
    } else {
        $error = 'Invalid username or password.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login — Meridian Corp Employee Portal</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="topbar">
    <a href="/">Meridian Corp Intranet</a>
    <nav class="topnav"><a href="/">Home</a></nav>
</header>
<main>
    <h1>Employee Login</h1>
    <?php if ($error): ?><p class="error"><?= htmlspecialchars($error) ?></p><?php endif; ?>
    <form method="post" action="/login.php">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" autocomplete="username">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password">
        <input type="submit" value="Log In">
    </form>
</main>
<footer>Meridian Corp — Internal Use Only</footer>
</body>
</html>
