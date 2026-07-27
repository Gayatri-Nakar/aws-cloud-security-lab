<?php
/**
 * Shared bootstrap: database connection, session start, and the custom
 * application-level logger used across all pages.
 */

session_start();

function get_db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . __DIR__ . '/../db/portal.sqlite');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    return $pdo;
}

/**
 * Returns the visitor's source IP, respecting a trusted reverse proxy
 * header if one is present (not required for a direct-to-Apache setup,
 * but harmless to keep).
 */
function client_ip(): string
{
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/**
 * Custom application-level logger. Distinct from the Apache access log:
 * this captures *what* was submitted (e.g. which username was tried),
 * not just that a request happened.
 *
 * Writes newline-delimited JSON to logs/app.log for easy parsing later.
 */
function app_log(string $event, array $data = []): void
{
    $entry = array_merge([
        'ts'        => gmdate('c'),
        'event'     => $event,
        'source_ip' => client_ip(),
        'user_agent'=> $_SERVER['HTTP_USER_AGENT'] ?? '',
        'uri'       => $_SERVER['REQUEST_URI'] ?? '',
        'method'    => $_SERVER['REQUEST_METHOD'] ?? '',
    ], $data);

    $logFile = __DIR__ . '/../logs/app.log';
    file_put_contents($logFile, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);
}

function is_logged_in(): bool
{
    return !empty($_SESSION['username']);
}

function require_login(): void
{
    if (!is_logged_in()) {
        header('Location: /login.php');
        exit;
    }
}
