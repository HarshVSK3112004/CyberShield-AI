import sqlite3
import os
from datetime import datetime, timedelta

from utils.helper import hash_password, verify_password

DB_PATH = os.path.join(os.path.dirname(__file__), "database.db")

# Account lockout policy
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 1


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS predictions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        prediction TEXT,
        probability REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Security-monitoring log: every login attempt, success or failure.
    # Kept separate from the general app logger (utils.helper.get_logger)
    # since this is queryable auth history, not free-text log lines.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        success INTEGER NOT NULL,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


# ---------------- USERS ---------------- #

def register_user(username, email, password):
    """Create a new user. Passwords are hashed with Argon2id (see
    utils.helper.hash_password) before being written to the database — the
    plaintext password is never stored."""
    conn = get_connection()
    cur = conn.cursor()

    hashed = hash_password(password)

    try:
        cur.execute(
            "INSERT INTO users(username,email,password) VALUES(?,?,?)",
            (username, email, hashed),
        )
        conn.commit()
        conn.close()
        return True, "Registration Successful."

    except sqlite3.IntegrityError as e:
        conn.close()
        if "username" in str(e):
            return False, "That username is already taken."
        return False, "Email already exists."


def _log_auth_event(cur, email, success, reason=None):
    cur.execute(
        "INSERT INTO auth_logs(email, success, reason) VALUES(?,?,?)",
        (email, 1 if success else 0, reason),
    )


def verify_user(email, password):
    """Attempt to log in, enforcing account lockout and logging every
    attempt for security monitoring.

    Returns a dict, one of:
      {"status": "ok", "user": <sqlite3.Row>}
      {"status": "locked", "retry_after": <seconds remaining>}
      {"status": "invalid"}   # unknown email OR wrong password (deliberately
                               # not distinguished, to avoid leaking which
                               # emails are registered)
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cur.fetchone()

    if not user:
        _log_auth_event(cur, email, success=False, reason="no_such_account")
        conn.commit()
        conn.close()
        return {"status": "invalid"}

    # ---- Lockout check ----
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.utcnow() < locked_until:
            remaining = int((locked_until - datetime.utcnow()).total_seconds())
            _log_auth_event(cur, email, success=False, reason="locked_out")
            conn.commit()
            conn.close()
            return {"status": "locked", "retry_after": max(remaining, 1)}
        else:
            # Lock window has passed; clear it before evaluating this attempt
            cur.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
                (user["id"],),
            )

    # ---- Password check ----
    if verify_password(password, user["password"]):
        cur.execute(
            "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
            (user["id"],),
        )
        _log_auth_event(cur, email, success=True)
        conn.commit()
        conn.close()
        return {"status": "ok", "user": user}

    # ---- Wrong password: bump the counter, lock if threshold reached ----
    new_failures = user["failed_attempts"] + 1

    if new_failures >= MAX_FAILED_ATTEMPTS:
        locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        cur.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
            (new_failures, locked_until.isoformat(), user["id"]),
        )
        _log_auth_event(cur, email, success=False, reason="locked_after_max_attempts")
    else:
        cur.execute(
            "UPDATE users SET failed_attempts=? WHERE id=?",
            (new_failures, user["id"]),
        )
        _log_auth_event(cur, email, success=False, reason="wrong_password")

    conn.commit()
    conn.close()
    return {"status": "invalid"}


def reset_password(email, username, new_password):
    """Reset a user's password after verifying email + username match an
    existing account. Also clears any active lockout, since a successful
    reset is a legitimate proof-of-identity moment to let the user back in.

    Note: this is a demo-appropriate verification method (email + username,
    no separate email-delivered token) since the project has no SMTP/email
    sending configured. A production system should send a time-limited
    reset link to the registered email instead of resetting on the spot.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM users WHERE email=? AND username=?",
        (email, username),
    )
    user = cur.fetchone()

    if not user:
        _log_auth_event(cur, email, success=False, reason="reset_identity_mismatch")
        conn.commit()
        conn.close()
        return False, "No account matches that email and username combination."

    hashed = hash_password(new_password)
    cur.execute(
        "UPDATE users SET password=?, failed_attempts=0, locked_until=NULL WHERE id=?",
        (hashed, user["id"]),
    )
    _log_auth_event(cur, email, success=True, reason="password_reset")
    conn.commit()
    conn.close()
    return True, "Password reset successfully. You can now log in with your new password."


def get_auth_logs(email=None, limit=50):
    """Return recent auth log entries, optionally filtered to one email.
    Used for the security-monitoring view (e.g. Profile page)."""
    conn = get_connection()
    cur = conn.cursor()

    if email:
        cur.execute(
            "SELECT * FROM auth_logs WHERE email=? ORDER BY created_at DESC LIMIT ?",
            (email, limit),
        )
    else:
        cur.execute(
            "SELECT * FROM auth_logs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )

    rows = cur.fetchall()
    conn.close()
    return rows


# ---------------- HISTORY ---------------- #

def add_scan_history(user_id, url, prediction, probability):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO predictions(user_id,url,prediction,probability)
        VALUES(?,?,?,?)
        """,
        (user_id, url, prediction, probability),
    )

    conn.commit()
    conn.close()


def get_history(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT *
        FROM predictions
        WHERE user_id=?
        ORDER BY created_at DESC
        """,
        (user_id,),
    )

    rows = cur.fetchall()
    conn.close()

    return rows


def get_user_stats(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT COUNT(*) FROM predictions WHERE user_id=?",
        (user_id,),
    )
    total = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM predictions
        WHERE user_id=? AND prediction='Phishing'
        """,
        (user_id,),
    )
    phishing = cur.fetchone()[0]

    cur.execute(
        """
        SELECT COUNT(*)
        FROM predictions
        WHERE user_id=? AND prediction='Legitimate'
        """,
        (user_id,),
    )
    safe = cur.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "phishing": phishing,
        "safe": safe,
    }
