#!/usr/bin/env bash
# Runs automatically on first boot (via EC2 user-data / cloud-init).
# Installs Apache/PHP/SQLite, pulls the webapp package from S3, deploys
# it, seeds the database, schedules automatic self-termination, and sets
# up near-continuous log shipping to S3.

set -euo pipefail
exec > /var/log/user-data.log 2>&1

echo "=== Scheduling automatic termination (${auto_shutdown_minutes} minutes from now) ==="
# This is the PRIMARY teardown mechanism for the observation window, done
# first and unconditionally so it's guaranteed to be scheduled even if a
# later step in this script fails. Combined with
# instance_initiated_shutdown_behavior = "terminate" on the aws_instance
# resource, this OS-level shutdown command results in AWS fully
# TERMINATING the instance (not just stopping it) -- it deletes itself,
# closing the public exposure and stopping compute billing automatically.
shutdown -P +${auto_shutdown_minutes} "Automatic teardown after the planned observation window" || true

echo "=== Updating packages ==="
apt-get update -y
apt-get install -y apache2 php php-sqlite3 sqlite3 libapache2-mod-php unzip awscli

echo "=== Downloading webapp package from S3 ==="
aws s3 cp "s3://${bucket_name}/deploy/webapp.zip" /root/webapp.zip
mkdir -p /root/app

# Windows' Compress-Archive embeds backslash path separators even for a
# single-level folder, which is harmless (Linux unzip still extracts
# every file correctly) but makes unzip return exit code 1 for the
# warning it prints about it. Under `set -e` that would otherwise kill
# the whole script right here. We tolerate that specific non-fatal exit
# code, then explicitly verify a known file actually landed where
# expected -- so a genuine extraction failure still stops the script.
unzip -o /root/webapp.zip -d /root/app || true

if [ ! -f /root/app/webapp/public/index.php ]; then
    echo "ERROR: webapp extraction failed -- expected file not found at /root/app/webapp/public/index.php"
    exit 1
fi

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

echo "=== Setting up near-continuous log shipping to S3 ==="
cat > /usr/local/bin/log_sync.sh << EOF
#!/usr/bin/env bash
set -euo pipefail
BUCKET="s3://${bucket_name}"
LABEL="${instance_label}"
aws s3 sync /var/log/apache2/          "\$BUCKET/\$LABEL/apache2/" --only-show-errors
aws s3 cp   /var/log/auth.log          "\$BUCKET/\$LABEL/auth/auth.log" --only-show-errors
aws s3 sync /var/www/portal-data/logs/ "\$BUCKET/\$LABEL/app/" --only-show-errors
aws s3 cp   /var/log/user-data.log     "\$BUCKET/\$LABEL/boot/user-data.log" --only-show-errors
aws s3 cp   /var/www/portal-data/db/portal.sqlite "\$BUCKET/\$LABEL/db/portal.sqlite" --only-show-errors
EOF
chmod +x /usr/local/bin/log_sync.sh

# Runs every minute -- the tightest practical interval for a cron-based
# sync, so logs land in S3 within roughly 60 seconds of being written
# rather than sitting on the instance. True sub-second real-time delivery
# would require a streaming agent (e.g. the CloudWatch unified agent
# tailing the files continuously) instead of periodic sync; every-minute
# cron is the appropriate tradeoff of simplicity vs. freshness for this
# project's scale.
echo "* * * * * root /usr/local/bin/log_sync.sh >> /var/log/log_sync.log 2>&1" > /etc/cron.d/log_sync
chmod 0644 /etc/cron.d/log_sync

echo "=== Restarting Apache ==="
systemctl restart apache2
systemctl enable apache2

echo "=== Deployment complete ==="
