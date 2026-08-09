"""Minimal in-memory sliding-window rate limiter (no Redis, no threads).

Every request from an IP — including ones that are rejected with 429 — is
counted in the window. Once the limit is exceeded, the IP stays limited
until its oldest counted request ages out of the window, then requests are
allowed again automatically (it never permanently blocks).

State is process-local: keep a single Gunicorn worker per instance (the
default) so the counter is shared across requests. Thread-safe via a single
lock; stale IPs are swept lazily so memory stays bounded.

Public API:
    is_rate_limited(ip, limit, window_seconds) -> bool
    seconds_until_reset(ip, window_seconds) -> int   # for Retry-After
    reset_rate_limits()                              # tests only
"""

import threading
import time

_hits = {}
_lock = threading.Lock()

# When the tracked-IP dict exceeds this size, stale entries are swept.
_MAX_TRACKED_IPS = 10000


def is_rate_limited(ip, limit=100, window_seconds=60):
    """Record a request from `ip` and return True if it is over the limit.

    The current request is counted before the limit check, so `limit`
    requests are allowed per window and every request after that is
    rejected until the window slides past the oldest request.
    Returns False when `limit <= 0` (rate limiting disabled).
    """
    if limit <= 0:
        return False
    now = time.monotonic()
    cutoff = now - window_seconds
    with _lock:
        timestamps = _hits.get(ip)
        if timestamps is None:
            timestamps = _hits[ip] = []
        # Drop timestamps outside the window (oldest first — list is ordered).
        while timestamps and timestamps[0] <= cutoff:
            timestamps.pop(0)
        timestamps.append(now)  # count every request, allowed or rejected
        # Periodically sweep stale IPs to bound memory.
        if len(_hits) > _MAX_TRACKED_IPS:
            keep = {k: v for k, v in _hits.items() if v and v[-1] > cutoff}
            _hits.clear()
            _hits.update(keep)
        return len(timestamps) > limit


def seconds_until_reset(ip, window_seconds=60):
    """Seconds until the IP's oldest counted request leaves the window.

    Used for the Retry-After header on 429 responses. Returns 0 when the
    IP is not currently tracked.
    """
    now = time.monotonic()
    with _lock:
        timestamps = _hits.get(ip) or []
    if not timestamps:
        return 0
    oldest = timestamps[0]
    return max(1, int(window_seconds - (now - oldest)))


def reset_rate_limits():
    """Clear all tracked state (used by tests)."""
    with _lock:
        _hits.clear()
