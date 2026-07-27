# Simulated Employee Portal ("Meridian Corp")

A minimal Apache/PHP/SQLite web application built to serve as a realistic,
low-effort target for the Cloud Attack Surface Analysis project. It is not
meant to be a production-quality app — every page exists to attract a
specific, well-documented category of automated internet probing, and to
log it in a form useful for later analysis.

## Pages

| File | Purpose |
|---|---|
| `index.php` | Landing page |
| `login.php` | Fake employee login; every attempt (username + success/fail) is logged |
| `dashboard.php` | Session-gated placeholder landing page after login |
| `admin.php` | High-value target path; every hit is logged regardless of auth state |
| `search.php` | Employee directory search (parameterized query — safe by design, but logs the raw query so injection *attempts* are still captured) |
| `docs.php` | Serves fictional "policy documents"; logs the raw requested filename so path-traversal attempts are captured, while safely constraining actual file access to `policy_documents/` |
| `contact.php` | Public contact form; attracts spam bots and injection probing |
| `logout.php` | Destroys the session |
| `config.php` | Shared DB connection, session bootstrap, and the `app_log()` custom logger |

## Why the app is intentionally *not* actually vulnerable

The search and document-download pages are built to **look** like naive,
probeable endpoints (an unsanitized-looking search box, a filename query
parameter), which is what attracts SQL-injection and path-traversal
scanning traffic in the first place. But both are implemented safely
underneath — parameterized queries for search, and `basename()` +
`realpath()` containment for file downloads. The *attempt* is what gets
logged (both in Apache's access log, which records the raw request, and
in the custom `app_log()` calls), regardless of whether the underlying
code is actually exploitable. This preserves the telemetry value of the
project without introducing a real vulnerability into a public-facing box.

The only genuinely weak point in the whole environment is the one the
project is designed to study: the exposed SSH port on the intentionally
misconfigured security group.

## Setup

1. Copy this folder to the EC2 instance (e.g. `scp -r webapp ubuntu@<INSTANCE_IP>:~/app`).
2. SSH in and run: `sudo bash ~/app/scripts/setup_server.sh`
3. This installs Apache/PHP/SQLite, deploys the app to `/var/www/html`,
   initializes the database with fictional seed accounts (see script
   output), and restarts Apache.
4. Edit `scripts/log_sync.sh`, filling in `<LOG_BUCKET_NAME>` and
   `<INSTANCE_LABEL>`, then add it to cron (see comment in that file) so
   logs are continuously shipped to S3 during the observation window.

## Logs produced

- Apache access/error logs: `/var/log/apache2/`
- Linux auth log: `/var/log/auth.log`
- Custom application log (newline-delimited JSON): `/var/www/portal-data/logs/app.log`

The `db/` and `logs/` directories are deployed outside the public web root
(`/var/www/portal-data/`, not `/var/www/html/`) so the SQLite database and
raw application log are never directly downloadable over HTTP.
