<?php
/**
 * One-time setup script: creates the SQLite database and seeds it with
 * fictional employee accounts. Run this once from the command line:
 *
 *   php scripts/init_db.php
 *
 * Safe to re-run; uses INSERT OR IGNORE so it won't duplicate rows.
 */

$dbPath = __DIR__ . '/../db/portal.sqlite';
$schemaPath = __DIR__ . '/../db/schema.sql';

$pdo = new PDO('sqlite:' . $dbPath);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$schema = file_get_contents($schemaPath);
$pdo->exec($schema);

// Fictional accounts only. Passwords are intentionally simple — this is a
// disposable honeypot instance with no real data, not a production system.
$seedAccounts = [
    ['jsmith', 'Summer2024!', 'John Smith',   'Finance', 'employee'],
    ['agreen', 'Welcome123',  'Amy Green',    'HR',      'employee'],
    ['rpatel', 'ChangeMe1',   'Raj Patel',    'IT',      'employee'],
    ['admin',  'Admin@123',   'System Admin', 'IT',      'admin'],
];

$stmt = $pdo->prepare(
    'INSERT OR IGNORE INTO employees (username, password_hash, full_name, department, role)
     VALUES (:username, :password_hash, :full_name, :department, :role)'
);

foreach ($seedAccounts as [$username, $plainPassword, $fullName, $department, $role]) {
    $stmt->execute([
        ':username'      => $username,
        ':password_hash' => password_hash($plainPassword, PASSWORD_BCRYPT),
        ':full_name'     => $fullName,
        ':department'    => $department,
        ':role'          => $role,
    ]);
}

echo "Database initialized at {$dbPath}\n";
echo "Seed accounts created (fictional, for honeypot use only):\n";
foreach ($seedAccounts as [$username, $plainPassword]) {
    echo "  {$username} / {$plainPassword}\n";
}
