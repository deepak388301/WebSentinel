"""
database/models.py

Defines the tables WebSentinel writes to:
  - Request   : every HTTP request that hits the app (the raw evidence log)
  - Incident  : created only when a detector flags a request as malicious
  - AlertedIP : tracks which attacker IPs have already been emailed to
                enforce the one-email-per-IP-per-cooldown rule.

Kept in one file for a 20-day project scope — split into request.py / incident.py
later if the schema grows.
"""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask_sqlalchemy import SQLAlchemy

IST = ZoneInfo("Asia/Kolkata")

def _utc_to_ist(dt):
    """Convert a UTC datetime to IST (Indian Standard Time, UTC+5:30)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)

# db is created here and imported by app.py — this avoids circular imports
# between app.py and the detector/route modules that also need db access.
db = SQLAlchemy()


class Request(db.Model):
    """One row per HTTP request received by the monitored application."""
    __tablename__ = "requests"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    ip = db.Column(db.String(45), nullable=False)          # IPv4/IPv6-safe length
    method = db.Column(db.String(10), nullable=False)      # GET, POST, etc.
    url = db.Column(db.String(500), nullable=False)
    headers = db.Column(db.Text)                            # stored as JSON string
    payload = db.Column(db.Text)                             # query string + body combined
    user_agent = db.Column(db.String(300))
    status_code = db.Column(db.Integer)

    # One request can trigger multiple incidents (rare, but possible if a
    # payload matches more than one detector) — backref lets an Incident
    # look up its parent Request easily.
    incidents = db.relationship("Incident", backref="request", lazy=True)

    def to_dict(self):
        ts = _utc_to_ist(self.timestamp)
        return {
            "id": self.id,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None,
            "ip": self.ip,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
        }


class Incident(db.Model):
    """One row per detected attack. Created by the Incident Generator."""
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_code = db.Column(db.String(20), unique=True, nullable=False)  # e.g. INC-00125
    request_id = db.Column(db.Integer, db.ForeignKey("requests.id"), nullable=False)

    attack_type = db.Column(db.String(50), nullable=False)   # SQL Injection, XSS, etc.
    severity = db.Column(db.String(20), nullable=False)      # Critical/High/Medium/Low
    confidence = db.Column(db.String(20))                    # High/Medium/Low
    risk_score = db.Column(db.Integer)                       # 0-100
    evidence = db.Column(db.Text)                             # what specifically matched
    recommendation = db.Column(db.Text)
    mitre_technique = db.Column(db.String(20))                # e.g. T1190
    status = db.Column(db.String(20), default="Open")         # Open (detected, forwarded) / Blocked (403'd)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        ts = _utc_to_ist(self.created_at)
        return {
            "incident_code": self.incident_code,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "mitre_technique": self.mitre_technique,
            "status": self.status,
            "created_at": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else None,
        }


class AlertedIP(db.Model):
    """Tracks IPs that have already received an alert email.

    One row per attacker IP. The cooldown logic in utils/alerting.py
    checks first_alerted_at against WEBSENTINEL_ALERT_COOLDOWN_MINUTES
    to decide whether a new alert is warranted.
    """
    __tablename__ = "alerted_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)
    first_alerted_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class LoginAttempt(db.Model):
    """Tracks failed login attempts for brute-force detection.

    Replaces the old in-memory _failed_attempts dict so that attempt
    counts are shared across multiple Gunicorn workers/processes.
    """
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

    __table_args__ = (
        db.Index("ix_login_attempts_ip_timestamp", "ip", "timestamp"),
    )


class BlockedIP(db.Model):
    """Tracks IPs that have been blocked from accessing the proxy.

    Two sources:
      - auto: inserted by utils/ip_blocklist.py when an IP exceeds the
        Critical/High incident threshold within a time window.
      - manual: inserted via the dashboard's blocklist management page.

    A null expires_at means the block is permanent until manually unblocked.
    """
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(500), nullable=False)
    blocked_by = db.Column(db.String(10), nullable=False)       # "auto" or "manual"
    blocked_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)  # null = permanent


class Setting(db.Model):
    """Key-value settings that can be edited from the dashboard.

    Currently stores the email alerting configuration (alert_email,
    alert_cooldown_minutes, alert_enabled). Values saved
    here take precedence over the equivalent environment variables.
    """
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False, default="")


class Target(db.Model):
    """A protected backend target that the proxy can forward traffic to.

    The table may hold many *configured* targets, but AT MOST ONE is ever
    ``active`` at a time. ``enabled`` controls whether a target is eligible
    to be activated at all; ``active`` marks the single one currently in
    use. The proxy reads whichever target is ``active`` from the database
    on each request and forwards only to that one (never multiple targets
    simultaneously). When no target is active, forwarding falls back to
    ``WEBSENTINEL_TARGET`` / ``DEFAULT_TARGET_URL``.

    ``target_url`` is validated at save time (http/https, hostname
    required, no embedded credentials) and normalized by stripping
    trailing slashes — the same convention the env-var fallback uses.
    """
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target_url = db.Column(db.String(500), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False, default="")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    active = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_targets_active", "active"),
    )
