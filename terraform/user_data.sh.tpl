#!/usr/bin/env bash
# Runs automatically on first boot (via EC2 user-data / cloud-init).
# Installs Apache/PHP/SQLite, pulls the webapp package from S3, deploys
# it, seeds the database, and sets up continuous log shipping to S3.

set -euo pipefail
exec > /var/log/user-data.log 2>&1

echo "=== Updating packages ==="
apt-get update -y
apt-get install -y apache2 php php-sqlite3 sqlite3 libapache2-mod-php unzip awscli

echo "=== Downloading webapp package from S3 ==="
aws s3 cp "s3://${bucket_name}/deploy/webapp.zip" /root/webapp.zip
mkdir -p /root/app
unzip -o /root/webapp.zip -d /root/app

# The zip contains a top-level "webapp/" folder; normalize the path.
APP_SRC="/root/app/webapp"

echo "=== Deploying application files ==="
WEB_ROOT="/var/www/html"
rm -f "$WEB_ROOT/index.html"
cp -r "$APP_SRC/public/." "$WEB_ROOT/"

mkdir -p /var/www/portal-data/db /var/www/portal-data/logs
cp "$APP_SRC/db/schema.sql" /var/www/portal-data/db/

sed -i "s|__DIR__ . '/../db/portal.sqlite'|'/var/www/portal-data/db/portal.sqlite'|" "$WEB_ROOT/config.php"
sed -i "s|__DIR__ . '/../logs/app.log'|'/var/www/portal-data/logs/app.log'|" "$WEB_ROOT/config.php"

echo "=== Initializing database ==="
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
"

echo "=== Setting permissions ==="
chown -R www-data:www-data "$WEB_ROOT" /var/www/portal-data
chmod -R 750 /var/www/portal-data

echo "=== Enforcing key-based SSH auth only ==="
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

echo "=== Setting up continuous log shipping to S3 ==="
cat > /usr/local/bin/log_sync.sh << EOF
#!/usr/bin/env bash
set -euo pipefail
BUCKET="s3://${bucket_name}"
LABEL="${instance_label}"
aws s3 sync /var/log/apache2/          "\$BUCKET/\$LABEL/apache2/" --only-show-errors
aws s3 cp   /var/log/auth.log          "\$BUCKET/\$LABEL/auth/auth.log" --only-show-errors
aws s3 sync /var/www/portal-data/logs/ "\$BUCKET/\$LABEL/app/" --only-show-errors
EOF
chmod +x /usr/local/bin/log_sync.sh

# Run every 5 minutes so data survives even if the instance becomes
# unstable or needs to be terminated early.
echo "*/5 * * * * root /usr/local/bin/log_sync.sh >> /var/log/log_sync.log 2>&1" > /etc/cron.d/log_sync
chmod 0644 /etc/cron.d/log_sync

echo "=== Restarting Apache ==="
systemctl restart apache2
systemctl enable apache2

echo "=== Deployment complete ==="
