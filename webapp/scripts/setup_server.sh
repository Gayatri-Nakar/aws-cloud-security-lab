#!/usr/bin/env bash
#
# Run this on a fresh Ubuntu EC2 instance to install Apache/PHP/SQLite and
# deploy the application. Assumes the app/ folder has already been copied
# to the instance (e.g. via scp) into ~/app.
#
# Usage: sudo bash setup_server.sh

set -euo pipefail

echo "Updating packages..."
apt-get update -y
apt-get upgrade -y

echo "Installing Apache, PHP, and SQLite support..."
apt-get install -y apache2 php php-sqlite3 sqlite3 libapache2-mod-php

echo "Deploying application files..."
APP_SRC="$HOME/app"
WEB_ROOT="/var/www/html"

# Clear default Apache placeholder content
rm -f "$WEB_ROOT/index.html"

# Copy the public web root
cp -r "$APP_SRC/public/." "$WEB_ROOT/"

# db/ and logs/ live outside the public web root so they are never
# directly downloadable over HTTP
mkdir -p /var/www/portal-data/db /var/www/portal-data/logs
cp "$APP_SRC/db/schema.sql" /var/www/portal-data/db/

# Point config.php's relative paths at the non-public data directory
sed -i "s|__DIR__ . '/../db/portal.sqlite'|'/var/www/portal-data/db/portal.sqlite'|" "$WEB_ROOT/config.php"
sed -i "s|__DIR__ . '/../logs/app.log'|'/var/www/portal-data/logs/app.log'|" "$WEB_ROOT/config.php"

echo "Initializing the database..."
php "$APP_SRC/scripts/init_db.php" > /tmp/init_db_output.txt || true
# Re-run init logic pointed at the deployed schema location
php -r "
\$dbPath = '/var/www/portal-data/db/portal.sqlite';
\$schema = file_get_contents('/var/www/portal-data/db/schema.sql');
\$pdo = new PDO('sqlite:' . \$dbPath);
\$pdo->exec(\$schema);
\$accounts = [
    ['jsmith','Summer2024!','John Smith','Finance','employee'],
    ['agreen','Welcome123','Amy Green','HR','employee'],
    ['rpatel','ChangeMe1','Raj Patel','IT','employee'],
    ['admin','Admin@123','System Admin','IT','admin'],
];
\$stmt = \$pdo->prepare('INSERT OR IGNORE INTO employees (username,password_hash,full_name,department,role) VALUES (?,?,?,?,?)');
foreach (\$accounts as \$a) {
    \$stmt->execute([\$a[0], password_hash(\$a[1], PASSWORD_BCRYPT), \$a[2], \$a[3], \$a[4]]);
}
echo \"Seeded \" . count(\$accounts) . \" accounts\n\";
"

echo "Setting permissions..."
chown -R www-data:www-data "$WEB_ROOT" /var/www/portal-data
chmod -R 750 /var/www/portal-data

echo "Restarting Apache..."
systemctl restart apache2
systemctl enable apache2

echo "Setup complete. The portal should now be reachable over HTTP on this instance's public IP."
