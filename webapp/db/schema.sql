-- Schema for the simulated employee portal.
-- All data below is entirely fictional. No real names, emails, or credentials.

CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    department TEXT NOT NULL,
    role TEXT NOT NULL
);

-- Employee accounts are seeded by scripts/init_db.php (not hardcoded here)
-- so that password_hash() generates valid, properly-salted bcrypt hashes
-- at setup time rather than embedding a placeholder hash in source control.

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    username_attempted TEXT,
    success INTEGER NOT NULL,
    user_agent TEXT
);
