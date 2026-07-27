<?php
require __DIR__ . '/config.php';
require_login();

$query = trim((string)($_GET['q'] ?? ''));
$results = [];

if ($query !== '') {
    app_log('directory_search', ['query' => $query]);

    // Parameterized query — the search *feature* is real and safe from
    // SQL injection by design. This is intentional: the point of this
    // endpoint is to observe injection *attempts* in the logs (they show
    // up in app.log as the raw query string regardless of whether they
    // succeed), not to actually be exploitable.
    $db = get_db();
    $stmt = $db->prepare(
        "SELECT full_name, department, role FROM employees
         WHERE full_name LIKE :q OR department LIKE :q"
    );
    $stmt->execute([':q' => '%' . $query . '%']);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Directory Search — Meridian Corp Employee Portal</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="topbar">
    <a href="/">Meridian Corp Intranet</a>
    <nav class="topnav"><a href="/dashboard.php">Dashboard</a> <a href="/logout.php">Log Out</a></nav>
</header>
<main>
    <h1>Employee Directory Search</h1>
    <form method="get" action="/search.php">
        <label for="q">Search by name or department</label>
        <input type="text" id="q" name="q" value="<?= htmlspecialchars($query) ?>">
        <input type="submit" value="Search">
    </form>

    <?php if ($query !== ''): ?>
        <table>
            <tr><th>Name</th><th>Department</th><th>Role</th></tr>
            <?php foreach ($results as $row): ?>
            <tr>
                <td><?= htmlspecialchars($row['full_name']) ?></td>
                <td><?= htmlspecialchars($row['department']) ?></td>
                <td><?= htmlspecialchars($row['role']) ?></td>
            </tr>
            <?php endforeach; ?>
            <?php if (!$results): ?>
            <tr><td colspan="3">No results found.</td></tr>
            <?php endif; ?>
        </table>
    <?php endif; ?>
</main>
<footer>Meridian Corp — Internal Use Only</footer>
</body>
</html>
