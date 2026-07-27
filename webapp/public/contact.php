<?php
require __DIR__ . '/config.php';

$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name    = substr((string)($_POST['name'] ?? ''), 0, 255);
    $email   = substr((string)($_POST['email'] ?? ''), 0, 255);
    $message = substr((string)($_POST['message'] ?? ''), 0, 2000);

    // No email is actually sent and nothing is stored beyond the log —
    // this form exists purely to attract spam-bot and injection probing
    // traffic against a public input field.
    app_log('contact_form_submission', [
        'name'    => $name,
        'email'   => $email,
        'message' => $message,
    ]);

    $submitted = true;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Contact IT — Meridian Corp Employee Portal</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="topbar">
    <a href="/">Meridian Corp Intranet</a>
    <nav class="topnav"><a href="/">Home</a></nav>
</header>
<main>
    <h1>Contact IT</h1>
    <?php if ($submitted): ?>
        <p class="notice">Thanks — your message has been submitted.</p>
    <?php endif; ?>
    <form method="post" action="/contact.php">
        <label for="name">Name</label>
        <input type="text" id="name" name="name">
        <label for="email">Email</label>
        <input type="text" id="email" name="email">
        <label for="message">Message</label>
        <textarea id="message" name="message" rows="5"></textarea>
        <input type="submit" value="Submit">
    </form>
</main>
<footer>Meridian Corp — Internal Use Only</footer>
</body>
</html>
