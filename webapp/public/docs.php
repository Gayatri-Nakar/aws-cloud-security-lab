<?php
require __DIR__ . '/config.php';

$docsDir = realpath(__DIR__ . '/policy_documents');
$availableDocs = array_values(array_filter(scandir($docsDir), fn($f) => $f !== '.' && $f !== '..'));

$requestedFile = $_GET['file'] ?? null;

if ($requestedFile !== null) {
    // Log the raw, unmodified value the client sent — this is deliberate.
    // Even though the download itself is constrained below, the *attempt*
    // (e.g. "../../etc/passwd" or "....//....//etc/passwd") is exactly
    // the signal this endpoint exists to capture, and it's also already
    // visible in the Apache access log via the raw request URI.
    app_log('doc_download_attempt', ['requested_file' => $requestedFile]);

    // Constrain resolution to basename only, then confirm the resolved
    // path is still inside the docs directory. This intentionally makes
    // the endpoint *look* like a naive file-serving parameter (which is
    // what attracts the traversal probing) while remaining safe: no
    // request can actually escape the policy_documents directory.
    $safeName = basename($requestedFile);
    $resolvedPath = realpath($docsDir . '/' . $safeName);

    if ($resolvedPath !== false && str_starts_with($resolvedPath, $docsDir) && is_file($resolvedPath)) {
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="' . $safeName . '"');
        readfile($resolvedPath);
        exit;
    }

    http_response_code(404);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Policy Documents — Meridian Corp Employee Portal</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="topbar">
    <a href="/">Meridian Corp Intranet</a>
    <nav class="topnav"><a href="/">Home</a></nav>
</header>
<main>
    <h1>Policy Documents</h1>
    <?php if ($requestedFile !== null): ?>
        <p class="error">Requested file not found.</p>
    <?php endif; ?>
    <ul>
        <?php foreach ($availableDocs as $doc): ?>
        <li><a href="/docs.php?file=<?= urlencode($doc) ?>"><?= htmlspecialchars($doc) ?></a></li>
        <?php endforeach; ?>
    </ul>
</main>
<footer>Meridian Corp — Internal Use Only</footer>
</body>
</html>
