"""
utils/ip_blocklist.py

IP blocklist — auto-block repeat offenders and manual block/unblock.

Public API:
    is_blocked(ip) -> bool          # checked first in proxy pipeline
    maybe_auto_block(ip) -> None    # called after Critical/High incident persisted
    block_ip(ip, reason, blocked_by="manual") -> None
    unblock_ip(ip) -> None
"""

import os
import logging
from datetime import datetime, timedelta, timezone

from database.models import db, BlockedIP, Incident, Request

logger = logging.getLogger("websentinel.blocklist")


# ------------------------------------------------------------------
# Configuration helpers (same pattern as utils/alerting.py)
# ------------------------------------------------------------------

def _is_auto_block_enabled() -> bool:
    return os.environ.get("WEBSENTINEL_AUTOBLOCK_ENABLED", "true").lower() == "true"


def _threshold() -> int:
    try:
        return max(1, int(os.environ.get("WEBSENTINEL_AUTOBLOCK_THRESHOLD", "5")))
    except (ValueError, TypeError):
        return 5


def _window_minutes() -> int:
    try:
        return max(1, int(os.environ.get("WEBSENTINEL_AUTOBLOCK_WINDOW_MINUTES", "10")))
    except (ValueError, TypeError):
        return 10


def _duration_minutes():
    """Return auto-block duration in minutes, or None for permanent."""
    raw = os.environ.get("WEBSENTINEL_AUTOBLOCK_DURATION_MINUTES", "1440")
    if raw in ("", "0", "none", "null"):
        return None
    try:
        val = int(raw)
        return val if val > 0 else None
    except (ValueError, TypeError):
        return 1440


# ------------------------------------------------------------------
# Core helpers
# ------------------------------------------------------------------

def is_blocked(ip: str) -> bool:
    """Return True if this IP is currently blocked.

    Single indexed DB lookup — cheap enough to run on every request.
    An IP is blocked if:
      - a BlockedIP row exists, AND
      - its expires_at is null (permanent) or in the future.
    """
    record = BlockedIP.query.filter_by(ip=ip).first()
    if record is None:
        return False
    if record.expires_at is not None:
        expires = record.expires_at
        now = datetime.now(timezone.utc)
        # SQLite returns naive datetimes; normalize for comparison.
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            return False
    return True


def maybe_auto_block(ip: str, force: bool = False) -> None:
    """Auto-block this IP if it has crossed the Critical/High incident threshold.

    Called after a Critical/High incident is persisted (same trigger point
    as maybe_alert). When force=True (request was blocked), the IP is
    blocked immediately without needing the threshold count. When force=False
    (request was logged but forwarded), the IP is only blocked after
    accumulating the configured number of Critical/High incidents within
    the time window.
    """
    if not _is_auto_block_enabled():
        return

    if is_blocked(ip):
        return  # already blocked, no-op

    if not force:
        window = timedelta(minutes=_window_minutes())
        cutoff = datetime.now(timezone.utc) - window

        count = (
            db.session.query(db.func.count(Incident.id))
            .join(Request, Incident.request_id == Request.id)
            .filter(
                Request.ip == ip,
                Incident.severity.in_(["Critical", "High"]),
                Incident.created_at >= cutoff,
            )
            .scalar()
        )

        if count < _threshold():
            return

    duration = _duration_minutes()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=duration)
        if duration is not None
        else None
    )

    block_ip(
        ip=ip,
        reason=f"Auto: request was blocked"
        if force
        else f"Auto: {count} Critical/High incidents in {_window_minutes()} min",
        blocked_by="auto",
        expires_at=expires_at,
    )
    logger.info("Auto-blocked IP %s (force=%s)", ip, force)


def block_ip(ip: str, reason: str, blocked_by: str = "manual",
             expires_at=None) -> None:
    """Insert or update a BlockedIP row for the given IP.

    If the IP is already blocked, refreshes the reason and expiry.
    Safe to call multiple times — idempotent.
    """
    existing = BlockedIP.query.filter_by(ip=ip).first()
    if existing:
        existing.reason = reason
        existing.blocked_by = blocked_by
        existing.blocked_at = datetime.now(timezone.utc)
        existing.expires_at = expires_at
    else:
        db.session.add(BlockedIP(
            ip=ip,
            reason=reason,
            blocked_by=blocked_by,
            expires_at=expires_at,
        ))
    db.session.commit()


def unblock_ip(ip: str) -> None:
    """Remove the block for the given IP.

    Safe to call even if the IP is not blocked — no-op in that case.
    """
    BlockedIP.query.filter_by(ip=ip).delete()
    db.session.commit()
