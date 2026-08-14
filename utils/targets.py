"""
utils/targets.py

Manual Target Management — add, view, edit, enable/disable, activate, and
delete the protected backend targets that the WebSentinel proxy forwards
traffic to.

The ``Target`` table may hold many *configured* targets, but AT MOST ONE
is ever ``active`` at a time. ``enabled`` gates eligibility to be
activated; ``active`` marks the single one currently forwarded to. The
proxy reads the active target from the database on every request and
falls back to ``WEBSENTINEL_TARGET`` / ``DEFAULT_TARGET_URL`` when none
exists (section 18 of the feature spec). No per-request multi-target
routing is built here.

Public API:
    normalize_target_url(url) -> str         # validate + normalize
    is_private_target(url) -> bool           # informational SSRF notice
    set_active_target(target_id) -> Target   # clear others, set one
    get_active_target() -> Target | None
    get_active_target_url() -> str           # active+enabled target, else env fallback
    bootstrap_target_from_env() -> None      # seed initial row from env var
    test_target_connection(url) -> (bool, str)
    audit(action, target, username) -> None  # log management events
"""

import logging
import re
from urllib.parse import urlsplit, urlunsplit

import requests as upstream_requests
from requests.exceptions import RequestException as UpstreamRequestError
from flask import current_app

from database.models import db, Target
from detectors.ssrf import _is_dangerous_ip

logger = logging.getLogger("websentinel.targets")

# Only http/https targets are meaningful as upstream backends.
ALLOWED_SCHEMES = {"http", "https"}

# DNS hostnames must be alphanumeric labels joined by dots/hyphens.
HOSTNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)*$"
)

# Test-connection timeout (seconds) — short on purpose (section 11).
CONNECTION_TEST_TIMEOUT = 4.0


def _sanitize_url(url: str) -> str:
    """Strip any userinfo (credentials) from a URL for safe logging."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    if parts.username is None and parts.password is None:
        return url
    host = parts.hostname or ""
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _valid_hostname(host: str) -> bool:
    """Accept DNS hostnames and IP literals; reject whitespace or invalid
    netloc characters. IPv6 literals are handled by ipaddress."""
    if not host:
        return False
    if re.search(r"\s", host):
        return False
    if ":" in host:
        try:
            from ipaddress import ip_address
            ip_address(host)
            return True
        except ValueError:
            return False
    return bool(HOSTNAME_RE.fullmatch(host))


def normalize_target_url(raw_url: str) -> str:
    """Validate and normalize a target URL.

    Requirements (section 2):
      - absolute http/https URL with a hostname
      - reject malformed URLs and embedded credentials
      - strip trailing slashes (same convention as the env-var fallback)

    Returns the normalized URL, or raises ValueError with a user-facing
    message on invalid input. Never stores credentials.
    """
    raw = (raw_url or "").strip()
    if not raw:
        raise ValueError("Target URL is required.")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        raise ValueError("Target URL is malformed.")

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Target URL must use http or https.")
    if not parsed.hostname:
        raise ValueError("Target URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Target URL must not contain embedded credentials.")
    try:
        parsed.port  # raises ValueError for out-of-range ports
    except ValueError:
        raise ValueError("Target URL contains an invalid port.")
    if not _valid_hostname(parsed.hostname):
        raise ValueError("Target URL contains an invalid hostname.")

    # Normalize the netloc: lowercase hostname, keep the port, drop any
    # query string / fragment so equivalent URLs dedupe consistently.
    host = parsed.hostname
    netloc = f"[{host}]" if ":" in host else host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def is_private_target(raw_url: str) -> bool:
    """Informational check: does the target's host sit in the SSRF-sensitive
    range (loopback/private/link-local/...) or is it ``localhost``?

    This is a NON-BLOCKING notice — internal/localhost backends are a
    legitimate, common deployment (this project itself was tested against
    ``localhost:5173`` throughout its development). The UI shows a warning
    asking the admin to confirm the choice; the target is still accepted.
    Reuses detectors/ssrf.py's own IP classification so the two never drift.
    """
    try:
        host = urlsplit(raw_url or "").hostname
    except ValueError:
        return False
    if not host:
        return False
    return _is_dangerous_ip(host)


def set_active_target(target_id: int) -> Target:
    """Promote one target to active, clearing active on every other row.

    Done as a SINGLE UPDATE statement (``active = (id == target_id)``)
    inside one transaction, so two concurrent admin requests can never
    leave two rows active (section 0). A disabled target cannot be made
    active (section 7).
    """
    target = db.session.get(Target, target_id)
    if target is None:
        raise ValueError("Target not found.")
    if not target.enabled:
        raise ValueError("A disabled target cannot be set active.")

    Target.query.update({Target.active: (Target.id == target_id)})
    target.active = True
    db.session.commit()
    return target


def get_active_target():
    """The single active Target row, or None."""
    return Target.query.filter_by(active=True).first()


def get_active_target_url() -> str:
    """URL the proxy forwards to: the active+enabled target if one exists,
    otherwise the WEBSENTINEL_TARGET/DEFAULT_TARGET_URL fallback (section 18).

    After the one-time startup bootstrap, the database is the sole source
    of truth for the active target; the env var is only the fallback for
    the no-active-target state.
    """
    fallback = current_app.config.get("WEBSENTINEL_TARGET") or ""
    active = get_active_target()
    if active is None:
        logger.warning(
            "No target is active — falling back to WEBSENTINEL_TARGET (%s).",
            fallback,
        )
        return fallback
    if not active.enabled:
        logger.warning(
            "Active target %r is disabled — falling back to WEBSENTINEL_TARGET (%s).",
            active.name, fallback,
        )
        return fallback
    return active.target_url


def bootstrap_target_from_env() -> None:
    """Section 18: on startup, if the targets table is empty, auto-create one
    row from WEBSENTINEL_TARGET/DEFAULT_TARGET_URL, marked both enabled and
    active.

    After this one-time bootstrap the database is the sole source of truth;
    the env var only seeds the initial row and is not re-read per request.
    Idempotent — a no-op once any target row exists.
    """
    if Target.query.count() > 0:
        return
    raw_url = current_app.config.get("WEBSENTINEL_TARGET") or ""
    try:
        url = normalize_target_url(raw_url)
    except ValueError:
        url = raw_url.rstrip("/")
    db.session.add(Target(
        name="Default target",
        target_url=url,
        description="Seeded automatically from WEBSENTINEL_TARGET on first startup.",
        enabled=True,
        active=True,
    ))
    db.session.commit()
    logger.info("Bootstrapped initial target %r from WEBSENTINEL_TARGET.", url)


def test_target_connection(url: str, timeout: float = CONNECTION_TEST_TIMEOUT):
    """Check whether a *stored* target URL is reachable.

    - Uses the already-validated stored URL (lower SSRF risk than an
      endpoint that fetches arbitrary input at request time).
    - Short timeout (default 4s).
    - ``allow_redirects=False`` explicitly: a redirect to an internal
      address is a classic SSRF bypass of validation performed only on
      the original URL, so redirects are never followed.
    - Purely informational: never affects proxy behavior (section 11).
    """
    try:
        resp = upstream_requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
        resp.close()
        return True, f"Reachable — HTTP {resp.status_code}"
    except UpstreamRequestError as e:
        return False, f"Unreachable — {type(e).__name__}"
    except Exception as e:  # pragma: no cover - defensive, never leak internals
        return False, f"Unreachable — {type(e).__name__}"


def audit(action: str, target, username: str = "unknown") -> None:
    """Log a target-management event through the standard logging module.

    Includes the authenticated admin's username. URLs are sanitized so
    credentials are never written to logs.
    """
    if isinstance(target, dict):
        tid = target.get("id")
        name = target.get("name")
        url = target.get("target_url")
    else:
        tid = getattr(target, "id", None)
        name = getattr(target, "name", None)
        url = getattr(target, "target_url", None)
    logger.info(
        "admin=%s action=%s target_id=%s name=%r url=%s",
        username or "unknown", action, tid, name, _sanitize_url(url or ""),
    )
