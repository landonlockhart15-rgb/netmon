"""
auth.py — Authentication helpers for NetMon.

Design decisions:
  - Passwords are bcrypt-hashed and stored in .env (never in the DB).
    bcrypt is intentionally slow so brute-force is hard even on a LAN.

  - Sessions are random 32-byte URL-safe tokens stored in a server-side
    dict. The token is sent to the browser as an HttpOnly cookie, which
    means JavaScript cannot read it (XSS can't steal it).

  - "Server-side sessions" means the server controls validity. If you
    want to force-log-out all sessions, just restart the server (or call
    revoke_all_sessions()). A JWT approach would not give you this.

  - Sessions expire after SESSION_DURATION_S (default 7 days). Each
    validate_session() call checks the expiry in real time.

  - This is intentionally single-user. APP_USERNAME + APP_PASSWORD_HASH
    come from .env. No user table needed.
"""

import os
import secrets
import threading
import time

import bcrypt

# ── Session store ──────────────────────────────────────────────────────────────
# Maps token string → Unix expiry timestamp (float).
# Simple dict is fine for a single-user home app.
_sessions: dict[str, float] = {}

SESSION_DURATION_S = 7 * 24 * 3600   # 7 days
COOKIE_NAME        = "netmon_session"

# ── Login rate limiter (per source IP, sliding window) ────────────────────────
# In-memory, no extra deps. Lock guards updates because uvicorn dispatches
# requests across multiple worker threads. Bound is generous enough that a
# real user typo won't trip it, tight enough to neuter LAN brute force.
_LOGIN_WINDOW_S      = 60
_LOGIN_MAX_ATTEMPTS  = 5
_login_attempts: dict[str, list[float]] = {}
_login_lock = threading.Lock()


def check_login_rate_limit(ip: str) -> bool:
    """
    Record an attempt from `ip` and return True if it's allowed.
    Anyone exceeding _LOGIN_MAX_ATTEMPTS within _LOGIN_WINDOW_S gets False
    and the route should respond 429 instead of running bcrypt.
    """
    if not ip:
        return True
    now = time.time()
    cutoff = now - _LOGIN_WINDOW_S
    with _login_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if t > cutoff]
        if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
            _login_attempts[ip] = attempts  # keep pruned list for next check
            return False
        attempts.append(now)
        _login_attempts[ip] = attempts
    return True


def reset_login_attempts(ip: str) -> None:
    """Call after a successful login so the user isn't penalized for typos."""
    if not ip:
        return
    with _login_lock:
        _login_attempts.pop(ip, None)


def verify_password(plain: str, hashed: str) -> bool:
    """Check a plaintext password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def check_credentials(username: str, password: str) -> bool:
    """
    Validate username + password against values in .env.
    Returns True only if both match.
    Always runs verify_password even if the username is wrong —
    this prevents timing attacks that could reveal valid usernames.
    """
    expected_user = os.getenv("APP_USERNAME", "")
    expected_hash = os.getenv("APP_PASSWORD_HASH", "")

    if not expected_user or not expected_hash:
        return False  # not configured — fail closed

    # Always call verify so the response time is consistent
    # (bcrypt takes the same time regardless of username correctness)
    password_ok = verify_password(password, expected_hash)
    username_ok = secrets.compare_digest(username, expected_user)

    return username_ok and password_ok


def create_session() -> str:
    """
    Create a new session and return its token.
    secrets.token_urlsafe(32) gives 256 bits of randomness —
    effectively impossible to guess.
    """
    token  = secrets.token_urlsafe(32)
    expiry = time.time() + SESSION_DURATION_S
    _sessions[token] = expiry
    return token


def validate_session(token: str | None) -> bool:
    """Return True if the token exists and hasn't expired."""
    if not token:
        return False
    expiry = _sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        # Clean up expired token
        _sessions.pop(token, None)
        return False
    return True


def revoke_session(token: str) -> None:
    """Invalidate a specific session (used on logout)."""
    _sessions.pop(token, None)
