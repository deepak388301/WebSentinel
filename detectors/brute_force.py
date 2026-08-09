"""
detectors/brute_force.py

Brute Force detector — tracks failed login attempts per IP in the database
(fixed across all Gunicorn workers/processes). Flags once a threshold is
crossed within a time window.

Contract (unchanged from v1):
    detect(data) -> dict | None
    should_preblock(url, ip) -> bool

Configuration (environment variables):
    WEBSENTINEL_BRUTE_FORCE_STATUS_CODES  Comma-separated HTTP status codes
                                          that count as a failed login attempt.
                                          Default: 401,403
    WEBSENTINEL_BRUTE_FORCE_LOGIN_PATHS   Comma-separated URL path substrings
                                          that identify login endpoints.
                                          Default: login,signin,auth,admin
"""

import os
from datetime import datetime, timedelta, timezone

FAILURE_THRESHOLD = 5      # attempts
TIME_WINDOW_SECONDS = 60   # within this many seconds


def _get_failure_status_codes():
    raw = os.environ.get("WEBSENTINEL_BRUTE_FORCE_STATUS_CODES", "401,403")
    try:
        return tuple(int(c.strip()) for c in raw.split(",") if c.strip())
    except (ValueError, TypeError):
        return (401, 403)


def _get_login_paths():
    raw = os.environ.get("WEBSENTINEL_BRUTE_FORCE_LOGIN_PATHS", "login,signin,auth,admin")
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def _is_login_endpoint(url: str) -> bool:
    login_markers = _get_login_paths()
    url_lower = url.lower()
    return any(marker in url_lower for marker in login_markers)


def _cleanup_expired():
    """Remove attempts older than the time window to avoid unbounded growth."""
    from database.models import db, LoginAttempt
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=TIME_WINDOW_SECONDS)
    LoginAttempt.query.filter(LoginAttempt.timestamp < cutoff).delete()
    db.session.commit()


def _count_recent(ip: str) -> int:
    """Count failed attempts from this IP within the rolling window."""
    from database.models import LoginAttempt
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=TIME_WINDOW_SECONDS)
    return LoginAttempt.query.filter(
        LoginAttempt.ip == ip,
        LoginAttempt.timestamp >= cutoff,
    ).count()


def should_preblock(url: str, ip: str) -> bool:
    """
    Pre-forward check — used BEFORE the request is sent upstream.
    Checks the already-recorded history (no new attempt is logged here)
    so attempt 6, 7, 8... can be blocked before ever reaching upstream.
    """
    if not _is_login_endpoint(url):
        return False

    _cleanup_expired()
    return _count_recent(ip) >= FAILURE_THRESHOLD


def detect(data: dict):
    """
    Expects data to contain: url, ip, status_code.
    A "failed attempt" is any request to a login-like endpoint that
    returned a status code matching WEBSENTINEL_BRUTE_FORCE_STATUS_CODES
    (default: 401, 403).
    """
    from database.models import db, LoginAttempt

    url = data.get("url", "") or ""
    ip = data.get("ip", "unknown")
    status_code = data.get("status_code")

    if not _is_login_endpoint(url):
        return None

    if status_code not in _get_failure_status_codes():
        return None

    # Record the failed attempt
    attempt = LoginAttempt(ip=ip, url=url)
    db.session.add(attempt)
    db.session.commit()

    _cleanup_expired()
    count = _count_recent(ip)

    if count >= FAILURE_THRESHOLD:
        return {
            "attack_type": "Brute Force",
            "confidence": "Very High",
            "evidence": f"{count} failed login attempts from {ip} "
                        f"within {TIME_WINDOW_SECONDS} seconds",
            "mitre_technique": "T1110",
            "recommendation": (
                "Implement account lockout or exponential backoff after repeated "
                "failures, add CAPTCHA after N attempts, and enforce rate limiting "
                "per IP on authentication endpoints."
            ),
        }
    return None
