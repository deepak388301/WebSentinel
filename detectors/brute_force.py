"""
detectors/brute_force.py

Brute Force detector — different shape from the other detectors because
brute force isn't a single-request pattern, it's a BEHAVIOR over multiple
requests. So instead of regex on one payload, we track failed attempts
per IP in memory and flag once a threshold is crossed within a time window.

Note: an in-memory dict resets when the Flask process restarts. That's an
acceptable v1 limitation (documented) — Redis would fix this in the
"Future Enhancements" phase (Section 16 of the project doc).
"""

import time

FAILURE_THRESHOLD = 5      # attempts
TIME_WINDOW_SECONDS = 60   # within this many seconds

# { ip: [timestamp1, timestamp2, ...] }  — only failed login timestamps are stored
_failed_attempts = {}


def _is_login_endpoint(url: str) -> bool:
    # No leading slash on purpose — matches "/login", "/test-login",
    # "/api/v1/auth" etc. Tighten this if it over-matches in your real app
    # (e.g. a route like "/plugin-authors" would false-positive on "auth").
    login_markers = ["login", "signin", "auth", "admin"]
    return any(marker in url.lower() for marker in login_markers)


def detect(data: dict):
    """
    Expects data to contain: url, ip, status_code.
    A "failed attempt" is treated as any request to a login-like endpoint
    that returned 401/403/redirect-to-login. Adjust to your app's real
    failure signal once you wire this to an actual /login route.
    """
    url = data.get("url", "") or ""
    ip = data.get("ip", "unknown")
    status_code = data.get("status_code")

    if not _is_login_endpoint(url):
        return None

    if status_code not in (401, 403):
        return None  # only count failed attempts, not successful logins

    now = time.time()
    timestamps = _failed_attempts.setdefault(ip, [])
    timestamps.append(now)

    # Drop timestamps outside the rolling window before counting
    _failed_attempts[ip] = [t for t in timestamps if now - t <= TIME_WINDOW_SECONDS]

    if len(_failed_attempts[ip]) >= FAILURE_THRESHOLD:
        return {
            "attack_type": "Brute Force",
            "confidence": "High",
            "evidence": f"{len(_failed_attempts[ip])} failed login attempts from {ip} "
                        f"within {TIME_WINDOW_SECONDS} seconds",
            "mitre_technique": "T1110",  # Brute Force
            "recommendation": (
                "Implement account lockout or exponential backoff after repeated "
                "failures, add CAPTCHA after N attempts, and enforce rate limiting "
                "per IP on authentication endpoints."
            ),
        }
    return None
