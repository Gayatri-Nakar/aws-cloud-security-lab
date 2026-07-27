#!/usr/bin/env python3
"""
analyze_logs.py -- Cloud Attack Surface Analysis pipeline.

Runs the five-phase plan against the logs pulled down from S3:
  1. Sanitize   -- redact known-own IPs from raw log copies
  2. Parse       -- turn each log format into a common row shape
  3. Correlate   -- group by source IP, build per-actor timelines
  4. Map         -- tag observed behavior with MITRE ATT&CK technique IDs
  5. Report      -- write a Markdown findings report

Usage:
    python analyze_logs.py --input collected-logs --output analysis_output

Before running against your real data, edit OWN_IPS below to include
every IP address that was you (your laptop's public IP, and the
instance's own IP) -- these get redacted, not treated as attacker
activity.
"""

import argparse
import csv
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# CONFIG -- edit this before running against your real collected-logs folder
# ---------------------------------------------------------------------------
OWN_IPS = [
    "10.0.1.x",   # your laptop's public IP (from api.ipify.org)
          
]

# Known scanner/legitimate-infra user agents worth noting in the report,
# not excluding -- just flagged. Extend as you notice patterns.
KNOWN_SCANNER_UA_HINTS = ["nmap", "masscan", "zgrab", "python-requests", "curl/", "go-http-client"]

# Paths that don't exist on the real site -- any request to these is
# reconnaissance/enumeration by definition, not a real user action.
NONEXISTENT_PATH_HINTS = [
    "wp-login", "wp-admin", ".env", "phpmyadmin", ".git", "xmlrpc.php",
    "config.php.bak", ".aws", "id_rsa", "server-status",
]

# ---------------------------------------------------------------------------
# Redaction: HMAC-keyed rather than plain SHA-256. IPv4 space is only ~4.3
# billion addresses, small enough that plain, unsalted SHA-256 could be
# brute-forced end-to-end on an ordinary laptop to reverse a redacted tag
# back to the real IP. Keying the hash with a private, locally-generated
# secret (never committed to git) closes that off while keeping the same
# property that made plain hashing useful in the first place: the same
# input always redacts to the same tag, so patterns stay visible.
# ---------------------------------------------------------------------------

_REDACTION_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".redaction_key")
_redaction_key_cache = None


def get_redaction_key() -> bytes:
    """Loads the HMAC key from $LOG_REDACTION_KEY if set, otherwise from
    (or generates and saves to) a local .redaction_key file next to this
    script. That file must never be committed to git -- add it to
    .gitignore. Using the same key across runs is what keeps redacted
    tags consistent between report versions."""
    global _redaction_key_cache
    if _redaction_key_cache is not None:
        return _redaction_key_cache

    env_key = os.environ.get("LOG_REDACTION_KEY")
    if env_key:
        _redaction_key_cache = env_key.encode()
        return _redaction_key_cache

    if os.path.exists(_REDACTION_KEY_PATH):
        with open(_REDACTION_KEY_PATH, "r") as f:
            key_text = f.read().strip()
        if not key_text:
            raise RuntimeError(f"{_REDACTION_KEY_PATH} exists but is empty")
        _redaction_key_cache = key_text.encode()
        return _redaction_key_cache

    new_key = secrets.token_hex(32)
    with open(_REDACTION_KEY_PATH, "w") as f:
        f.write(new_key)
    try:
        os.chmod(_REDACTION_KEY_PATH, 0o600)
    except OSError:
        pass  # best-effort; Windows filesystems don't honor this the same way
    print(f"(generated a new local redaction key at {_REDACTION_KEY_PATH} -- "
          f"do not commit this file to git; add it to .gitignore)")
    _redaction_key_cache = new_key.encode()
    return _redaction_key_cache


def pseudonymize(value: str, label: str) -> str:
    """General-purpose HMAC-keyed pseudonymization for any sensitive
    string, not just IPs -- used for CloudTrail identity fields (account
    ID, IAM username, access key ID, principal ID)."""
    if not value:
        return ""
    digest = hmac.new(get_redaction_key(), value.encode(), hashlib.sha256).hexdigest()[:10]
    return f"{label}-{digest}"


def redact_ip(ip: str) -> str:
    """Consistent, one-way redaction: same IP always redacts to the same
    tag, so patterns ("same actor did X and Y") stay visible even after
    redaction, without exposing the real address."""
    digest = hmac.new(get_redaction_key(), ip.encode(), hashlib.sha256).hexdigest()[:8]
    return f"REDACTED-{digest}"


def is_own_ip(ip: str) -> bool:
    return ip in OWN_IPS


# ---------------------------------------------------------------------------
# PHASE 1: SANITIZE
# ---------------------------------------------------------------------------

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def sanitize_text_file(src_path: str, dst_path: str) -> None:
    """Redact any OWN_IPS occurrence in a plain-text log file, leaving
    everything else (including other IPs -- those are the data) intact."""
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(src_path, "r", errors="replace") as f_in:
        content = f_in.read()

    def _replace(match):
        ip = match.group(0)
        return redact_ip(ip) if is_own_ip(ip) else ip

    sanitized = IP_PATTERN.sub(_replace, content)
    with open(dst_path, "w") as f_out:
        f_out.write(sanitized)


def sanitize_jsonlines_file(src_path: str, dst_path: str) -> None:
    """Redact the source_ip field specifically in our custom app.log."""
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(src_path, "r", errors="replace") as f_in, open(dst_path, "w") as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                f_out.write(line + "\n")
                continue
            if "source_ip" in obj and is_own_ip(obj["source_ip"]):
                obj["source_ip"] = redact_ip(obj["source_ip"])
            f_out.write(json.dumps(obj) + "\n")


def run_sanitize(input_dir: str, sanitized_dir: str) -> None:
    print("=== Phase 1: Sanitize ===")
    count = 0
    for root, _dirs, files in os.walk(input_dir):
        for fname in files:
            src = os.path.join(root, fname)
            rel = os.path.relpath(src, input_dir)
            dst = os.path.join(sanitized_dir, rel)
            parts = root.split(os.sep)

            # .gz (CloudTrail, Flow Logs) are redacted inline at parse
            # time instead -- not copied here. .sqlite/.zip are binary,
            # not text logs, so regex-based redaction doesn't apply.
            if fname.endswith(".gz") or fname.endswith(".sqlite") or fname.endswith(".zip"):
                continue
            if not fname.endswith(".log"):
                continue
            if os.path.getsize(src) > 20_000_000:
                continue  # defensively skip anything unexpectedly huge

            try:
                if "app" in parts:
                    sanitize_jsonlines_file(src, dst)
                else:
                    sanitize_text_file(src, dst)
            except UnicodeDecodeError:
                continue
            count += 1
    print(f"Sanitized {count} text-based log files into {sanitized_dir}")
    print("(.gz, .sqlite, and .zip files are read directly at parse time, not copied)")


# ---------------------------------------------------------------------------
# PHASE 2: PARSE / NORMALIZE
# Every parser yields dicts shaped: {ts, source_ip, source, event, detail}
# ts is an ISO8601 string in UTC.
# ---------------------------------------------------------------------------

APACHE_LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:\\.|[^"])*)" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>(?:\\.|[^"])*)" '
    r'"(?P<ua>(?:\\.|[^"])*)"'
)

_VALID_HTTP_METHOD = re.compile(r"[A-Z!#$%&'*+.^_`|~-]+")
_VALID_HTTP_PROTOCOL = re.compile(r"HTTP/\d(?:\.\d+)?")


def parse_apache_access(path: str) -> list:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = APACHE_LINE.match(line.strip())
            if not m:
                continue
            ip = m.group("ip")
            if is_own_ip(ip):
                ip = redact_ip(ip)
            try:
                ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
            except ValueError:
                continue

            # Split the request line ourselves rather than requiring the
            # regex to match "METHOD PATH PROTOCOL" directly. Scanners
            # regularly send malformed or non-HTTP payloads (raw TLS
            # handshake bytes, other protocols' probe strings) that don't
            # have that shape at all -- the old regex silently dropped
            # every one of those lines instead of recording them.
            #
            # A three-space-separated request isn't automatically valid
            # HTTP though -- a scanner payload could coincidentally
            # contain two spaces and look like METHOD/PATH/PROTOCOL by
            # accident. Check the method and protocol actually look like
            # real HTTP tokens before calling it well-formed.
            request = m.group("request")
            request_parts = request.split(" ", 2)
            if len(request_parts) == 3:
                method, path_val, protocol = request_parts
                valid_method = bool(_VALID_HTTP_METHOD.fullmatch(method))
                valid_protocol = bool(_VALID_HTTP_PROTOCOL.fullmatch(protocol))
                malformed = not (valid_method and valid_protocol)
            else:
                method, path_val, protocol = "UNKNOWN", request, ""
                malformed = True

            flagged = any(h in path_val.lower() for h in NONEXISTENT_PATH_HINTS)
            traversal = ".." in path_val
            size_raw = m.group("size")

            rows.append({
                "ts": ts.isoformat(),
                "source_ip": ip,
                "source": "apache_access",
                "event": "http_malformed_request" if malformed else "http_request",
                "detail": json.dumps({
                    "method": method,
                    "path": path_val,
                    "protocol": protocol,
                    "status": int(m.group("status")),
                    "response_bytes": None if size_raw == "-" else int(size_raw),
                    "referer": m.group("referer"),
                    "user_agent": m.group("ua"),
                    "malformed_request": malformed,
                    "enumeration_hint": flagged,
                    "traversal_hint": traversal,
                }),
            })
    return rows


IP_OR_REDACTED = r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|REDACTED-[0-9a-f]{8})"

AUTH_FAILED = re.compile(
    r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<msg>Failed password for(?: invalid user)? (?P<user>\S+) from (?P<ip>" + IP_OR_REDACTED + r") port \d+.*|"
    r"Invalid user (?P<user2>\S+) from (?P<ip2>" + IP_OR_REDACTED + r") port \d+.*|"
    r"Accepted (?:password|publickey) for (?P<user3>\S+) from (?P<ip3>" + IP_OR_REDACTED + r") port \d+.*)"
)

# Pre-authentication SSH events: the connection reached sshd but never
# completed a real login attempt with a username/password. These are
# banner-grabbing/fingerprinting scanners, protocol-confused generic
# scanners (e.g. an HTTP probe sent at port 22), and aborted login
# attempts -- genuinely different behavior from Failed-password brute
# forcing, and easy to miss if you only look for that one pattern.
AUTH_PREAUTH_PATTERNS = [
    (re.compile(r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
                r"Connection closed by (?:authenticating user \S+ )?(?P<ip>" + IP_OR_REDACTED + r") port \d+ ?\[preauth\]"),
     "ssh_preauth_disconnect"),
    (re.compile(r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
                r"error: kex_exchange_identification: .*"),
     "ssh_kex_error"),
    (re.compile(r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
                r"Connection closed by (?P<ip>" + IP_OR_REDACTED + r") port \d+"),
     "ssh_connection_closed"),
    (re.compile(r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
                r"banner exchange: Connection from (?P<ip>" + IP_OR_REDACTED + r") port \d+: (?P<reason>.*)"),
     "ssh_banner_exchange_failure"),
]


def parse_auth_log(path: str, year_hint: int) -> list:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = AUTH_FAILED.match(line)
            if m:
                ip = m.group("ip") or m.group("ip2") or m.group("ip3")
                user = m.group("user") or m.group("user2") or m.group("user3")
                if not ip:
                    continue
                if is_own_ip(ip):
                    ip = redact_ip(ip)
                try:
                    ts = datetime.strptime(f"{year_hint} {m.group('mon')} {m.group('day')} {m.group('time')}",
                                            "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

                # Extract only what's needed for analysis -- not the raw
                # line, which also contains the SSH key fingerprint on
                # successful logins, the internal hostname, and the
                # ephemeral source port, none of which belong in a
                # database you might publish.
                if "Accepted publickey" in line:
                    auth_method = "publickey"
                elif "password" in line.lower():
                    auth_method = "password"
                else:
                    auth_method = None

                rows.append({
                    "ts": ts.isoformat(),
                    "source_ip": ip,
                    "source": "auth_log",
                    "event": "ssh_login_success" if "Accepted" in line else "ssh_login_attempt",
                    "detail": json.dumps({
                        "username": user,
                        "authentication_method": auth_method,
                        "invalid_user": "invalid user" in line.lower(),
                    }),
                })
                continue

            # Not a Failed/Invalid/Accepted line -- check pre-auth patterns
            # (banner grabbing, protocol confusion, aborted logins).
            for pattern, event_name in AUTH_PREAUTH_PATTERNS:
                pm = pattern.match(line)
                if not pm:
                    continue
                groups = pm.groupdict()
                ip = groups.get("ip", "unknown") or "unknown"
                if ip != "unknown" and is_own_ip(ip):
                    ip = redact_ip(ip)
                try:
                    ts = datetime.strptime(f"{year_hint} {groups['mon']} {groups['day']} {groups['time']}",
                                            "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
                except (ValueError, KeyError):
                    continue
                rows.append({
                    "ts": ts.isoformat(),
                    "source_ip": ip,
                    "source": "auth_log",
                    "event": event_name,
                    "detail": json.dumps({"reason": groups.get("reason", "")}),
                })
                break
    return rows


APACHE_ERROR_LINE = re.compile(
    r"\[(?P<time>[^\]]+)\]\s+\[(?P<level>[\w:]+)\]\s+\[pid \d+(?::tid \d+)?\]\s+"
    r"(?:\[client (?P<ip>[\d.]+):\d+\]\s+)?(?P<msg>.*)"
)


def parse_apache_error_time(value: str) -> str:
    """Apache's default ErrorLogFormat timestamp is a fixed, parseable
    format, not locale-dependent as originally assumed here. Tries with
    and without fractional seconds, since both appear depending on the
    Apache build."""
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return ""


def parse_apache_error(path: str) -> list:
    """Apache error.log doesn't always include a client IP (some entries
    are server-level, not request-level) -- those are still recorded,
    just with source_ip='unknown', so they show up in event counts even
    though they can't be correlated to an actor."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = APACHE_ERROR_LINE.match(line)
            if not m:
                continue
            ip = m.group("ip") or "unknown"
            if ip != "unknown" and is_own_ip(ip):
                ip = redact_ip(ip)
            rows.append({
                "ts": parse_apache_error_time(m.group("time")),
                "source_ip": ip,
                "source": "apache_error",
                "event": "server_error",
                "detail": json.dumps({"level": m.group("level"), "message": m.group("msg")}),
            })
    return rows


def parse_sqlite_snapshot(path: str) -> list:
    """Reads the login_attempts table from the synced portal.sqlite
    snapshot -- a second, queryable record of every web login attempt,
    independent of app.log's flat-file version. Opened read-only so this
    never risks modifying your evidence copy."""
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        uri = f"file:{path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT ts, source_ip, username_attempted, success, user_agent FROM login_attempts")
        for r in cur:
            ip = r["source_ip"] or "unknown"
            if is_own_ip(ip):
                ip = redact_ip(ip)
            rows.append({
                "ts": r["ts"] or "",
                "source_ip": ip,
                "source": "sqlite_snapshot",
                "event": "login_attempt_db",
                "detail": json.dumps({
                    "username_attempted": r["username_attempted"],
                    "success": bool(r["success"]),
                    "user_agent": r["user_agent"],
                }),
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"  (warning: could not read {path}: {e})")
    return rows


def parse_app_log(path: str) -> list:
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = obj.get("source_ip", "unknown")
            rows.append({
                "ts": obj.get("ts", ""),
                "source_ip": ip,
                "source": "app_log",
                "event": obj.get("event", "unknown"),
                "detail": json.dumps(obj),
            })
    return rows


def parse_optional_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_epoch(value):
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def parse_flow_logs(dir_path: str) -> list:
    rows = []
    if not os.path.isdir(dir_path):
        return rows
    for root, _d, files in os.walk(dir_path):
        for fname in files:
            if not fname.endswith(".log.gz") and not fname.endswith(".log"):
                continue
            full = os.path.join(root, fname)
            opener = gzip.open if fname.endswith(".gz") else open
            try:
                with opener(full, "rt", errors="replace") as f:
                    header = None
                    for line in f:
                        parts = line.strip().split()
                        if not parts:
                            continue
                        if parts[0] == "version":
                            header = parts
                            continue
                        if header is None or len(parts) < len(header):
                            continue
                        rec = dict(zip(header, parts))
                        src_ip = rec.get("srcaddr", "unknown")
                        dst_ip = rec.get("dstaddr", "unknown")

                        # Determine direction before redacting either side,
                        # since redaction would otherwise make it
                        # impossible to tell which end was "us".
                        if src_ip in OWN_IPS:
                            direction = "outbound"
                        elif dst_ip in OWN_IPS:
                            direction = "inbound"
                        else:
                            direction = "unknown"

                        if is_own_ip(src_ip):
                            src_ip = redact_ip(src_ip)
                        if is_own_ip(dst_ip):
                            dst_ip = redact_ip(dst_ip)

                        # Some records have "-" for start/end (AWS's
                        # NODATA/SKIPDATA case, usually meaning Flow Logs
                        # hit a delivery capacity limit). Rather than
                        # letting int("-") raise and silently dropping
                        # the whole record via the old try/except+continue,
                        # keep the record with a blank timestamp -- that's
                        # itself informative (it can mean the instance saw
                        # enough traffic to exceed logging capacity).
                        start_epoch = parse_optional_int(rec.get("start"))
                        ts = datetime.fromtimestamp(start_epoch, tz=timezone.utc).isoformat() if start_epoch is not None else ""

                        action = rec.get("action")
                        event_name = f"flow_{action.lower()}" if action in ("ACCEPT", "REJECT") else "flow_unavailable"

                        rows.append({
                            "ts": ts,
                            "source_ip": src_ip,
                            "source": "vpc_flow_log",
                            "event": event_name,
                            "detail": json.dumps({
                                "destination_ip": dst_ip,
                                "source_port": parse_optional_int(rec.get("srcport")),
                                "destination_port": parse_optional_int(rec.get("dstport")),
                                "protocol": parse_optional_int(rec.get("protocol")),
                                "packets": parse_optional_int(rec.get("packets")),
                                "bytes": parse_optional_int(rec.get("bytes")),
                                "flow_start": parse_epoch(rec.get("start")),
                                "flow_end": parse_epoch(rec.get("end")),
                                "action": action,
                                "log_status": rec.get("log-status"),
                                "direction": direction,
                            }),
                        })
            except (OSError, gzip.BadGzipFile):
                continue
    return rows


def sanitize_cloudtrail_identity(identity: dict) -> dict:
    """The 'type' field (IAMUser, AssumedRole, AWSService) is kept as-is
    since it's useful for analysis and isn't sensitive on its own. The
    specific identifying fields underneath it are pseudonymized -- your
    real IAM username and access key ID have no business sitting in
    plain text in a database you might publish."""
    if not isinstance(identity, dict):
        return {}
    return {
        "type": identity.get("type"),
        "account": pseudonymize(identity.get("accountId", ""), "ACCOUNT"),
        "username": pseudonymize(identity.get("userName", ""), "IAMUSER"),
        "access_key": pseudonymize(identity.get("accessKeyId", ""), "ACCESSKEY"),
        "principal": pseudonymize(identity.get("principalId", ""), "PRINCIPAL"),
    }


def parse_cloudtrail(dir_path: str) -> list:
    rows = []
    if not os.path.isdir(dir_path):
        return rows
    for root, _d, files in os.walk(dir_path):
        for fname in files:
            if "digest" in fname.lower() or not (fname.endswith(".json.gz") or fname.endswith(".json")):
                continue
            full = os.path.join(root, fname)
            opener = gzip.open if fname.endswith(".gz") else open
            try:
                with opener(full, "rt", errors="replace") as f:
                    data = json.load(f)
            except (OSError, gzip.BadGzipFile, json.JSONDecodeError):
                continue
            for rec in data.get("Records", []):
                ip = rec.get("sourceIPAddress", "unknown")
                if is_own_ip(ip):
                    ip = redact_ip(ip)
                rows.append({
                    "ts": rec.get("eventTime", ""),
                    "source_ip": ip,
                    "source": "cloudtrail",
                    "event": rec.get("eventName", "unknown"),
                    "detail": json.dumps({
                        "eventSource": rec.get("eventSource"),
                        "aws_region": rec.get("awsRegion"),
                        "event_type": rec.get("eventType"),
                        "read_only": rec.get("readOnly"),
                        "user_agent": rec.get("userAgent"),
                        "error_code": rec.get("errorCode"),
                        "error_message": rec.get("errorMessage"),
                        "userIdentity": sanitize_cloudtrail_identity(rec.get("userIdentity", {})),
                    }),
                })
    return rows


def run_parse(sanitized_dir: str, raw_dir: str, db_path: str, log_year: int) -> None:
    print("=== Phase 2: Parse and normalize ===")
    all_rows = []

    # Apache/auth/app come from the sanitized text copies (own IPs already
    # redacted in the file itself).
    for root, _dirs, files in os.walk(sanitized_dir):
        for fname in files:
            full = os.path.join(root, fname)
            parts = root.split(os.sep)
            if fname == "access.log" and "apache2" in parts:
                all_rows.extend(parse_apache_access(full))
            elif fname == "error.log" and "apache2" in parts:
                all_rows.extend(parse_apache_error(full))
            elif fname == "auth.log" and "auth" in parts:
                all_rows.extend(parse_auth_log(full, year_hint=log_year))
            elif fname == "app.log" and "app" in parts:
                all_rows.extend(parse_app_log(full))

    # portal.sqlite is binary and was skipped by the sanitize step -- read
    # it directly from the raw directory; the parser redacts OWN_IPS
    # inline, same pattern as Flow Logs/CloudTrail below.
    for root, _dirs, files in os.walk(raw_dir):
        for fname in files:
            if fname == "portal.sqlite":
                all_rows.extend(parse_sqlite_snapshot(os.path.join(root, fname)))

    # VPC Flow Logs and CloudTrail are gzipped and were skipped by the
    # sanitize step -- read them from the original raw directory instead;
    # both parsers redact OWN_IPS inline as each row is built.
    all_rows.extend(parse_flow_logs(os.path.join(raw_dir, "vpc-flow-logs")))
    all_rows.extend(parse_cloudtrail(os.path.join(raw_dir, "cloudtrail")))

    conn = sqlite3.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS events")
    conn.execute("""
        CREATE TABLE events (
            ts TEXT, source_ip TEXT, source TEXT, event TEXT, detail TEXT
        )
    """)
    conn.executemany(
        "INSERT INTO events (ts, source_ip, source, event, detail) VALUES (?, ?, ?, ?, ?)",
        [(r["ts"], r["source_ip"], r["source"], r["event"], r["detail"]) for r in all_rows],
    )
    conn.commit()
    conn.close()
    print(f"Parsed {len(all_rows)} normalized events into {db_path}")


# ---------------------------------------------------------------------------
# PHASE 3: CORRELATE
# ---------------------------------------------------------------------------

def run_correlate(db_path: str):
    print("=== Phase 3: Correlate ===")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    # REDACTED-% is always the analyst's own activity (own IP or own
    # instance across its various launches). It's excluded here because
    # this table is meant to surface attacker actors -- your own access
    # showing up as the #1 "cross-source finding" (which it did, in an
    # earlier run of this pipeline) is confusing, not a real finding.
    ip_counts = conn.execute("""
        SELECT source_ip, COUNT(*) as n, COUNT(DISTINCT source) as sources
        FROM events
        WHERE source_ip != 'unknown' AND source_ip NOT LIKE 'REDACTED-%'
        GROUP BY source_ip
        ORDER BY sources DESC, n DESC
    """).fetchall()

    own_activity = conn.execute("""
        SELECT COUNT(*) FROM events WHERE source_ip LIKE 'REDACTED-%'
    """).fetchone()[0]

    print(f"{len(ip_counts)} distinct external source IPs seen across all logs.")
    print(f"({own_activity} events belong to the analyst's own redacted IP(s), excluded from this count)")
    cross_source = [r for r in ip_counts if r["sources"] > 1]
    print(f"{len(cross_source)} IPs appear in more than one log source (most interesting to review first).")

    conn.close()
    return ip_counts


# ---------------------------------------------------------------------------
# PHASE 4: MAP TO MITRE ATT&CK
# Heuristic, rule-based tagging -- meant as a starting point for your own
# review, not a final authoritative classification.
# ---------------------------------------------------------------------------

def map_attck(db_path: str) -> dict:
    print("=== Phase 4: Map to MITRE ATT&CK ===")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    findings = defaultdict(set)  # technique_id -> set of source_ips

    # REDACTED-% is always the analyst's own activity. Excluded from
    # every query below, same reasoning as run_correlate: this dict is
    # meant to represent attacker behavior, and testing your own site
    # can incidentally trip these same heuristics (e.g. checking a path
    # that happens to match an enumeration hint).
    OWN_FILTER = "AND source_ip NOT LIKE 'REDACTED-%'"

    # T1595 -- Active Scanning (web enumeration hits on nonexistent paths)
    for row in conn.execute(f"SELECT source_ip, detail FROM events WHERE source='apache_access' {OWN_FILTER}"):
        detail = json.loads(row["detail"])
        if detail.get("enumeration_hint"):
            findings["T1595.003 - Active Scanning (Wordlist Scanning)"].add(row["source_ip"])
        if detail.get("traversal_hint"):
            findings["T1190 - Exploit Public-Facing Application (Path Traversal attempt)"].add(row["source_ip"])

    # T1110.001 -- Brute Force: Password Guessing (repeated SSH failures)
    ssh_fail_counts = defaultdict(int)
    for row in conn.execute(f"SELECT source_ip FROM events WHERE source='auth_log' AND event='ssh_login_attempt' {OWN_FILTER}"):
        ssh_fail_counts[row["source_ip"]] += 1
    for ip, n in ssh_fail_counts.items():
        if n >= 2:
            findings["T1110.001 - Brute Force: Password Guessing (SSH)"].add(ip)

    # T1078 -- Valid Accounts. Only genuinely alarming for a source IP
    # that ISN'T you -- your own successful logins are expected and were
    # previously showing up here too, which made this finding say
    # "verify this was expected" about an IP that was always going to be
    # you. Excluded from the finding entirely now, rather than flagged.
    for row in conn.execute(f"""
        SELECT source_ip FROM events
        WHERE source='auth_log' AND event='ssh_login_success' {OWN_FILTER}
    """):
        findings["T1078 - Valid Accounts (successful SSH login from an EXTERNAL source -- investigate immediately)"].add(row["source_ip"])

    # T1110 -- application-layer credential guessing
    for row in conn.execute(f"SELECT source_ip, detail FROM events WHERE source='app_log' AND event='login_attempt' {OWN_FILTER}"):
        findings["T1110 - Brute Force (web application login form)"].add(row["source_ip"])

    # T1083 / T1005 -- data/file discovery via the docs endpoint
    for row in conn.execute(f"SELECT source_ip FROM events WHERE source='app_log' AND event='doc_download_attempt' {OWN_FILTER}"):
        findings["T1083 - File and Directory Discovery (docs endpoint probing)"].add(row["source_ip"])

    conn.close()
    return findings


# ---------------------------------------------------------------------------
# PHASE 5: REPORT
# ---------------------------------------------------------------------------

def run_report(db_path: str, ip_counts, attck_findings: dict, report_path: str):
    print("=== Phase 5: Write findings report ===")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    lines = []
    lines.append("# Attack Surface Analysis -- Findings Report\n")
    lines.append(f"Generated {datetime.now(timezone.utc).isoformat()}\n")

    lines.append("## Summary\n")
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    lines.append(f"- Total normalized events: {total}")
    lines.append(f"- Distinct source IPs: {len(ip_counts)}")
    lines.append(f"- IPs seen across multiple log sources: {len([r for r in ip_counts if r['sources'] > 1])}\n")

    lines.append("## Top source IPs (by number of log sources touched, then event count)\n")
    lines.append("| Source IP | Sources touched | Event count |")
    lines.append("|---|---|---|")
    for r in ip_counts[:15]:
        lines.append(f"| {r['source_ip']} | {r['sources']} | {r['n']} |")
    lines.append("")

    lines.append("## MITRE ATT&CK technique mapping (heuristic -- review before citing)\n")
    lines.append("| Technique | Source IPs observed |")
    lines.append("|---|---|")
    for technique, ips in sorted(attck_findings.items()):
        lines.append(f"| {technique} | {', '.join(sorted(ips))} |")
    lines.append("")

    lines.append("## Per-actor timelines (top 5 multi-source IPs)\n")
    multi = [r["source_ip"] for r in ip_counts if r["sources"] > 1][:5]
    for ip in multi:
        lines.append(f"### {ip}\n")
        rows = conn.execute(
            "SELECT ts, source, event, detail FROM events WHERE source_ip = ? ORDER BY ts", (ip,)
        ).fetchall()
        for row in rows:
            lines.append(f"- `{row['ts']}` **[{row['source']}]** {row['event']} -- {row['detail']}")
        lines.append("")

    conn.close()

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"Report written to {report_path}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Cloud Attack Surface Analysis pipeline")
    parser.add_argument("--input", required=True, help="Path to the collected-logs folder")
    parser.add_argument("--output", required=True, help="Path to write analysis output")
    parser.add_argument("--log-year", type=int, required=True,
                         help="Year to assign to auth.log entries, which don't include a year "
                              "in their own timestamp. Use the actual year the logs were collected.")
    args = parser.parse_args()

    sanitized_dir = os.path.join(args.output, "sanitized")
    db_path = os.path.join(args.output, "events.db")
    report_path = os.path.join(args.output, "findings_report.md")

    run_sanitize(args.input, sanitized_dir)
    run_parse(sanitized_dir, args.input, db_path, args.log_year)
    ip_counts = run_correlate(db_path)
    attck_findings = map_attck(db_path)
    run_report(db_path, ip_counts, attck_findings, report_path)

    print("\nDone. Review:")
    print(f"  - Sanitized logs: {sanitized_dir}")
    print(f"  - SQLite database (queryable): {db_path}")
    print(f"  - Findings report: {report_path}")


if __name__ == "__main__":
    main()