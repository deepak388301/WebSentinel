"""
proxy_app.py — WebSentinel Reverse Proxy WAF.

WebSentinel runs as an INDEPENDENT service that sits in front of the real
site and inspects every request before it reaches it — the same
architectural position as an Nginx-based WAF or Cloudflare.

    Visitor → WebSentinel Proxy → forwards clean traffic → Real Website
                    │
              inspect / log / score / BLOCK
                    │
              Dashboard at /websentinel/*

Requests are blocked (403) if:
  * A single finding has "Very High" confidence, OR
  * Two or more independent detectors flag the same request.

 --------------------------------------------------------------------------
 CONFIGURATION (environment variables)
 --------------------------------------------------------------------------
 WEBSENTINEL_TARGET   URL of the real website being protected.
                      Default: http://127.0.0.1:9000  (the demo victim site)
 WEBSENTINEL_PORT     Port the proxy + dashboard listen on. Default 8080.
 WEBSENTINEL_DB_URI   Database URL. Defaults to SQLite (instance/websentinel.db)
                      for local runs; docker-compose sets PostgreSQL.

 --------------------------------------------------------------------------
 RUN
 --------------------------------------------------------------------------
     WEBSENTINEL_TARGET=http://127.0.0.1:9000 python proxy_app.py

 Then send traffic to the PROXY's port (8080), not the real site's port —
 the proxy forwards it onward after inspection. TLS is terminated by a
 reverse proxy in production, not by this app (see README).
 """

import os
import json
import gzip
import logging
import secrets
import requests as upstream_requests
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit
from functools import wraps
from dotenv import load_dotenv

# Load .env (if present) so `cp .env.example .env` actually works for every
# run mode: `python proxy_app.py`, gunicorn, `flask db upgrade`, init_db.py.
# Existing environment variables always win (override=False), so tests that
# set env vars first are unaffected.
load_dotenv()

from flask import Flask, Blueprint, request, Response, render_template, jsonify, current_app, session, redirect, url_for, flash
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from database.models import db, Request as RequestModel, Incident, _utc_to_ist
from detectors import run_pre_forward_detectors, brute_force
from utils.risk_engine import calculate_risk
from utils.reference_helpers import get_mitre_info, get_owasp_info
from utils.alerting import maybe_alert
from utils.ip_blocklist import is_blocked, maybe_auto_block
from utils.rate_limit import is_rate_limited, seconds_until_reset
from utils.targets import (
    normalize_target_url,
    is_private_target,
    set_active_target,
    get_active_target_url,
    bootstrap_target_from_env,
    test_target_connection,
    audit as audit_target_event,
)

logger = logging.getLogger("websentinel")

# CSRFProtect instance — created at module level so proxy() can use @csrf.exempt,
# then initialized against the app in create_app().
csrf = CSRFProtect()

# Critical and High severity findings are ALWAYS blocked (403 Forbidden).
# Medium/Low are logged but still forwarded, since blocking on
# low-confidence findings would hurt real users more than it helps (a
# classic WAF false-positive problem you'll want to tune per deployment).
BLOCK_SEVERITIES = {"Critical", "High"}

DEFAULT_TARGET_URL = "http://127.0.0.1:9000"
APP_STARTED_AT = datetime.now(timezone.utc)

# Headers that must NOT be relayed as-is between proxy and client —
# these are connection-level headers that don't survive proxying correctly.
HOP_BY_HOP_HEADERS = {
    "content-encoding", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
}

websentinel_bp = Blueprint("websentinel", __name__, url_prefix="/websentinel")


def login_required(f):
    """Decorator that redirects unauthenticated users to the login page."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("websentinel.login"))
        return f(*args, **kwargs)
    return decorated_function


def rewrite_location_header(location: str, target_url: str) -> str:
    """
    If upstream's Location header points at the backend itself (same
    scheme+host as WEBSENTINEL_TARGET), rewrite it to point at the proxy
    instead — so the client's next request goes back through inspection
    rather than hitting the real backend directly (closes an open-redirect
    style bypass of the WAF).
    Relative Locations are left untouched (browsers resolve those against
    the proxy's own origin already, which is what we want).
    """
    parsed_loc = urlsplit(location)
    if not parsed_loc.scheme and not parsed_loc.netloc:
        return location  # relative — already safe, resolves against the proxy

    parsed_target = urlsplit(target_url)
    if (parsed_loc.scheme, parsed_loc.netloc) != (parsed_target.scheme, parsed_target.netloc):
        return location  # points elsewhere entirely — leave it, not our concern here

    proxy_scheme = request.scheme
    proxy_netloc = request.host  # includes port if non-default
    return urlunsplit((proxy_scheme, proxy_netloc, parsed_loc.path,
                        parsed_loc.query, parsed_loc.fragment))


migrate = Migrate()


def _load_suppression_config():
    """Load suppression rules from WEBSENTINEL_SUPPRESSION_FILE if set.

    The JSON file may contain:
      - ips: list of IP addresses/prefixes to never block
      - paths: list of URL path prefixes to never block
      - attack_types: list of attack type strings to never block

    Returns a dict with defaults for missing keys.
    """
    path = os.environ.get("WEBSENTINEL_SUPPRESSION_FILE", "")
    if not path:
        return {"ips": [], "paths": [], "attack_types": []}
    try:
        with open(path) as f:
            cfg = json.load(f)
        return {
            "ips": cfg.get("ips", []),
            "paths": cfg.get("paths", []),
            "attack_types": cfg.get("attack_types", []),
        }
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to load suppression config from %s: %s", path, e)
        return {"ips": [], "paths": [], "attack_types": []}


def init_app(app, database_uri=None, target_url=None):
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        database_uri
        or os.environ.get("WEBSENTINEL_DB_URI", "sqlite:///websentinel.db")
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
    }
    # pool_size/max_overflow are only valid for non-SQLite backends.
    db_uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if db_uri and not db_uri.startswith("sqlite"):
        app.config["SQLALCHEMY_ENGINE_OPTIONS"]["pool_size"] = 10
        app.config["SQLALCHEMY_ENGINE_OPTIONS"]["max_overflow"] = 20
    app.config["WEBSENTINEL_TARGET"] = (
        (target_url or os.environ.get("WEBSENTINEL_TARGET", DEFAULT_TARGET_URL))
        .rstrip("/")
    )
    app.config["WEBSENTINEL_SUPPRESSION"] = _load_suppression_config()
    db.init_app(app)
    migrate.init_app(app, db)


def create_app(database_uri=None, target_url=None):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("WEBSENTINEL_SECRET_KEY", secrets.token_hex(32))
    init_app(app, database_uri, target_url)

    # Session cookie security flags
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("WEBSENTINEL_SSL", "").lower() == "true"

    # Reject oversized request bodies before they are buffered (413).
    # Configure with WEBSENTINEL_MAX_BODY_SIZE (bytes); default 1 MiB.
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get("WEBSENTINEL_MAX_BODY_SIZE", str(1024 * 1024))
    )

    # Simple in-memory rate limit per client IP (requests per window).
    # Set WEBSENTINEL_RATE_LIMIT=0 to disable. Default 100 req / 60 s.
    app.config["WEBSENTINEL_RATE_LIMIT"] = int(os.environ.get("WEBSENTINEL_RATE_LIMIT", "100"))
    app.config["WEBSENTINEL_RATE_LIMIT_WINDOW"] = int(
        os.environ.get("WEBSENTINEL_RATE_LIMIT_WINDOW", "60")
    )

    # CSRF: enabled by default; tests set WTF_CSRF_ENABLED=false to skip token checks
    app.config["WTF_CSRF_ENABLED"] = os.environ.get("WTF_CSRF_ENABLED", "true").lower() != "false"

    # Store admin credentials (hashed) for dashboard login.
    _admin_user = os.environ.get("WEBSENTINEL_ADMIN_USER", "admin")
    _admin_pass = os.environ.get("WEBSENTINEL_ADMIN_PASS", "")
    if not _admin_pass:
        raise RuntimeError(
            "WEBSENTINEL_ADMIN_PASS must be set — refusing to start with the default password."
        )
    app.config["WEBSENTINEL_ADMIN_USER"] = _admin_user
    app.config["WEBSENTINEL_ADMIN_HASH"] = generate_password_hash(_admin_pass)

    app.register_blueprint(websentinel_bp)

    # CSRF protection for dashboard routes — proxy() is explicitly exempted.
    csrf.init_app(app)

    # The catch-all proxy route can't use a decorator like the dashboard
    # routes above, because it needs to bind to THIS specific app instance
    # (create_app() may be called more than once, e.g. once per test).
    # Registered after the blueprint, but Werkzeug matches by rule
    # specificity regardless of registration order, so /websentinel/* is
    # never shadowed by this catch-all.
    app.add_url_rule(
        "/", defaults={"path": ""}, view_func=proxy,
        methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )
    app.add_url_rule(
        "/<path:path>", view_func=proxy,
        methods=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )

    # Schema is managed by Flask-Migrate (alembic), not db.create_all().
    # Run `flask db upgrade` to apply migrations.

    # Run retention cleanup on startup (configurable via env vars).
    # Wrapped in try/except because tables may not exist yet during
    # testing or first-time setup before migrations are applied.
    with app.app_context():
        try:
            cleanup_old_data(app)
        except Exception:
            pass  # tables not yet created — skip cleanup

        # Section 18: seed the initial active target from
        # WEBSENTINEL_TARGET/DEFAULT_TARGET_URL when the targets table is
        # empty. Skipped silently when the table doesn't exist yet (e.g.
        # first boot before `flask db upgrade`); the __main__ block below
        # re-runs it right after upgrade().
        try:
            bootstrap_target_from_env()
        except Exception:
            db.session.rollback()
            pass  # targets table not yet created — bootstrap runs after upgrade

    @app.template_filter("ist")
    def fmt_ist(dt):
        """Jinja2 filter: convert UTC datetime to IST formatted string."""
        if dt is None:
            return "N/A"
        return _utc_to_ist(dt).strftime("%Y-%m-%d %H:%M:%S IST")

    @app.context_processor
    def inject_reference_helpers():
        from flask import g
        return dict(get_mitre_info=get_mitre_info, get_owasp_info=get_owasp_info, csp_nonce=getattr(g, 'csp_nonce', ''))

    @app.before_request
    def generate_csp_nonce():
        import base64
        from flask import g
        g.csp_nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")

    @app.after_request
    def set_security_headers(response):
        from flask import g
        nonce = getattr(g, 'csp_nonce', '')
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.path.startswith("/websentinel"):
            response.headers["Content-Security-Policy"] = (
                f"default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                f"font-src 'self'; "
                f"img-src 'self' data:; "
                f"connect-src 'self'"
            )
        return response

    return app

# Initialize module-level app for runtime and gunicorn use.
# Register the blueprint after all route decorators are defined.

def format_uptime(start_time):
    elapsed = datetime.now(timezone.utc) - start_time
    days, remainder = divmod(int(elapsed.total_seconds()), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


# Rolling window for security score — only incidents from the last N hours
# count toward the penalty.  This means the score naturally recovers as
# old incidents age out, instead of being permanently depressed by
# historical traffic.
SCORE_WINDOW_HOURS = 24

# Penalty weights per severity level.
SEVERITY_PENALTY = {
    "Critical": 15,
    "High": 8,
    "Medium": 3,
    "Low": 0,
}


def compute_security_score(window_hours=None):
    """Compute security_score over a rolling time window.

    Returns 100 (perfect) when no incidents fall within the window,
    decaying toward 0 as recent incidents accumulate.
    """
    hours = window_hours or SCORE_WINDOW_HOURS
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.session.query(Incident.severity, func.count(Incident.id))
        .filter(Incident.created_at >= cutoff)
        .group_by(Incident.severity)
        .all()
    )
    penalty = sum(SEVERITY_PENALTY.get(sev, 0) * count for sev, count in rows)
    return max(0, 100 - penalty)


# ------------------------------------------------------------------
# Data retention — configurable cleanup of old rows.
# ------------------------------------------------------------------
DEFAULT_RETENTION_REQUESTS_DAYS = 30
DEFAULT_RETENTION_INCIDENTS_DAYS = 90


def cleanup_old_data(app=None):
    """Delete rows older than the configured retention period.

    Runs inside an app context.  Incidents are deleted before requests
    because of the foreign-key dependency.  Also cleans up stale
    login_attempts and alerted_ips.
    """
    from database.models import Request, Incident, AlertedIP, LoginAttempt

    req_days = int(os.environ.get(
        "WEBSENTINEL_RETENTION_REQUESTS_DAYS", DEFAULT_RETENTION_REQUESTS_DAYS))
    inc_days = int(os.environ.get(
        "WEBSENTINEL_RETENTION_INCIDENTS_DAYS", DEFAULT_RETENTION_INCIDENTS_DAYS))

    now = datetime.now(timezone.utc)

    # Delete incidents older than inc_days
    inc_cutoff = now - timedelta(days=inc_days)
    old_incidents = Incident.query.filter(Incident.created_at < inc_cutoff).count()
    if old_incidents:
        # Delete associated incidents first (they reference requests)
        Incident.query.filter(Incident.created_at < inc_cutoff).delete(synchronize_session=False)

    # Delete requests older than req_days (incidents referencing them are already gone)
    req_cutoff = now - timedelta(days=req_days)
    old_requests = Request.query.filter(Request.timestamp < req_cutoff).count()
    if old_requests:
        Request.query.filter(Request.timestamp < req_cutoff).delete(synchronize_session=False)

    # Clean up old login_attempts (older than max retention)
    max_days = max(req_days, inc_days)
    login_cutoff = now - timedelta(days=max_days)
    old_logins = LoginAttempt.query.filter(LoginAttempt.timestamp < login_cutoff).count()
    if old_logins:
        LoginAttempt.query.filter(LoginAttempt.timestamp < login_cutoff).delete(synchronize_session=False)

    # Clean up old alerted_ips (older than max retention)
    old_alerts = AlertedIP.query.filter(AlertedIP.first_alerted_at < login_cutoff).count()
    if old_alerts:
        AlertedIP.query.filter(AlertedIP.first_alerted_at < login_cutoff).delete(synchronize_session=False)

    db.session.commit()

    total = old_incidents + old_requests + old_logins + old_alerts
    if total:
        logger.info("Retention cleanup: removed %d rows (incidents=%d, requests=%d, logins=%d, alerts=%d)",
                     total, old_incidents, old_requests, old_logins, old_alerts)
    return total


def build_trend(days=7):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days - 1)
    rows = (
        db.session.query(Incident.created_at)
        .filter(Incident.created_at >= cutoff)
        .all()
    )
    row_map = {}
    for (created_at,) in rows:
        if created_at is None:
            continue
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        day = created_at.date().isoformat()
        row_map[day] = row_map.get(day, 0) + 1
    labels = []
    counts = []
    for i in range(days - 1, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).date().isoformat()
        labels.append(day)
        counts.append(row_map.get(day, 0))
    return labels, counts


def request_to_dict(req):
    attacks = [incident.attack_type for incident in req.incidents]
    severity = req.incidents[0].severity if req.incidents else None
    return {
        "timestamp": _utc_to_ist(req.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
        "ip": req.ip,
        "method": req.method,
        "path": req.url,
        "status_code": req.status_code,
        "attack": bool(attacks),
        "attack_type": attack_types_to_label(attacks),
        "severity": severity,
    }


def attack_types_to_label(attacks):
    if not attacks:
        return None
    return ", ".join(sorted(set(attacks)))


# ---------------------------------------------------------------------
# Core inspection logic — shared by every proxied request
# ---------------------------------------------------------------------
# Decompressed bodies larger than this are not decompressed at all — the
# original (compressed) body is forwarded instead, keeping memory and the
# stored payload column bounded.
MAX_BODY_BYTES = 4 * 1024 * 1024


def get_client_ip():
    """The real client IP: the socket peer, never a spoofable header.

    X-Forwarded-For is ignored on input (it is rewritten before forwarding),
    so an attacker can't spoof their identity to the WAF by setting it.

    When the app runs behind a single trusted reverse proxy (Nginx, Traefik,
    Cloudflare, ...), set WEBSENTINEL_TRUST_PROXY=true. The real client IP is
    then taken from the RIGHT-MOST X-Forwarded-For entry — the one appended by
    the trusted proxy itself, which clients cannot forge (a spoofed
    X-Forwarded-For is simply prepended and ignored).
    """
    if os.environ.get("WEBSENTINEL_TRUST_PROXY", "false").lower() == "true":
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            ip = xff.split(",")[-1].strip()
            if ip:
                return ip
    return request.remote_addr or "127.0.0.1"


def get_request_body():
    """Return (body_bytes, content_encoding) for the current request.

    A gzip-encoded body is decompressed so detectors inspect real content
    and so the stripped Content-Encoding hop-by-hop header doesn't corrupt
    the forwarded request. If decompression fails or the result is too large,
    the original (compressed) body is returned together with its
    Content-Encoding header so the upstream can still decode it.
    """
    raw = request.get_data()
    encoding = request.headers.get("Content-Encoding", "").strip().lower()
    if encoding != "gzip":
        return raw, None
    try:
        decompressed = gzip.decompress(raw)
    except (OSError, EOFError):
        logger.warning(
            "Failed to decompress gzip request body from %s — forwarding as-is.",
            get_client_ip(),
        )
        return raw, encoding
    if len(decompressed) > MAX_BODY_BYTES:
        logger.warning(
            "Gzip body from %s decompresses beyond %d bytes — forwarding compressed.",
            get_client_ip(), MAX_BODY_BYTES,
        )
        return raw, encoding
    return decompressed, None


def inspect_request():
    """Builds the same 'data' dict shape the detectors already expect
    (see detectors/*.py), runs the PRE-FORWARD Detection Engine
    (request-only detectors for early blocking), and returns (data, findings).
    Post-response detectors (brute_force) run separately after upstream response."""
    query_payload = request.query_string.decode("utf-8", errors="ignore")
    body_payload, _ = get_request_body()
    try:
        body_payload = body_payload.decode("utf-8", errors="ignore")
    except Exception:
        body_payload = ""

    data = {
        "ip": get_client_ip(),
        "method": request.method,
        "url": request.path,
        "headers": json.dumps(dict(request.headers)),
        "payload": f"{query_payload} {body_payload}".strip(),
        "user_agent": request.headers.get("User-Agent", ""),
    }

    findings = run_pre_forward_detectors(data)
    return data, findings


def persist_request_and_incidents(data, findings, status_code, blocked):
    req_record = RequestModel(
        ip=data["ip"], method=data["method"], url=data["url"],
        headers=data["headers"], payload=data["payload"],
        user_agent=data["user_agent"], status_code=status_code,
    )
    db.session.add(req_record)
    db.session.commit()

    persisted = []
    for idx, finding in enumerate(findings):
        if "risk_score" not in finding:
            finding = calculate_risk(finding)
        incident = Incident(
            incident_code=f"INC-{req_record.id:05d}-{idx}",
            request_id=req_record.id,
            attack_type=finding["attack_type"],
            severity=finding["severity"],
            confidence=finding["confidence"],
            risk_score=finding["risk_score"],
            evidence=finding["evidence"],
            recommendation=finding["recommendation"],
            mitre_technique=finding["mitre_technique"],
            status="Blocked" if blocked else "Open",
        )
        db.session.add(incident)
        persisted.append(incident)
    if findings:
        db.session.commit()

    for incident in persisted:
        if incident.severity in BLOCK_SEVERITIES:
            maybe_alert(incident)
            req_ip = incident.request.ip if incident.request else None
            if req_ip:
                maybe_auto_block(req_ip, force=blocked)


def _is_suppressed(data, findings):
    """True if this request is suppressed by the suppression config."""
    supp = current_app.config.get("WEBSENTINEL_SUPPRESSION", {})
    ip = data.get("ip", "")
    url = data.get("url", "")
    # Check IP suppression
    for pattern in supp.get("ips", []):
        if ip == pattern or ip.startswith(pattern + "."):
            return True
    # Check path suppression
    for prefix in supp.get("paths", []):
        if url.startswith(prefix):
            return True
    # Check attack-type suppression
    suppressed_types = set(supp.get("attack_types", []))
    for f in findings:
        if f.get("attack_type") in suppressed_types:
            return True
    return False


def _should_block(data, findings, scored_findings):
    """Determine whether the current request should be blocked.

    Returns True if blocking should occur, False otherwise.
    Blocking rules:
      1. Single finding with "Very High" confidence, OR
      2. Two or more independent detector hits (different attack types).
    """
    if _is_suppressed(data, findings):
        return False

    # Rule 1: any single finding with Very High confidence triggers a block.
    for f in scored_findings:
        if f.get("confidence") == "Very High":
            return True

    # Rule 2: multiple independent detector hits (different attack types).
    attack_types = {f.get("attack_type") for f in scored_findings}
    if len(attack_types) >= 2:
        return True

    return False


# ---------------------------------------------------------------------
# Dashboard routes — namespaced under /websentinel/ so they never clash
# with the real site's own routes on the proxied path.
# ---------------------------------------------------------------------
@websentinel_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("websentinel.dashboard_home"))

    # Rate-limit: reuse the same threshold and window as detectors/brute_force.py
    _LOGIN_ATTEMPT_THRESHOLD = 5
    _LOGIN_WINDOW_SECONDS = 60

    error = None
    if request.method == "POST":
        from database.models import LoginAttempt
        client_ip = request.remote_addr or "127.0.0.1"
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_LOGIN_WINDOW_SECONDS)
        recent_fails = LoginAttempt.query.filter(
            LoginAttempt.ip == client_ip,
            LoginAttempt.url == "/websentinel/login",
            LoginAttempt.timestamp >= cutoff,
        ).count()
        if recent_fails >= _LOGIN_ATTEMPT_THRESHOLD:
            error = "Too many failed attempts. Please try again in 60 seconds."
            return render_template("login.html", error=error), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if (username == current_app.config["WEBSENTINEL_ADMIN_USER"]
                and check_password_hash(current_app.config["WEBSENTINEL_ADMIN_HASH"], password)):
            session["authenticated"] = True
            session["username"] = username
            return redirect(url_for("websentinel.dashboard_home"))

        # Record failed attempt
        attempt = LoginAttempt(ip=client_ip, url="/websentinel/login")
        db.session.add(attempt)
        db.session.commit()
        error = "Invalid credentials."

    return render_template("login.html", error=error)


@websentinel_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("websentinel.login"))


@websentinel_bp.route("/")
@login_required
def dashboard_home():
    total_requests = RequestModel.query.count()
    total_incidents = Incident.query.count()
    critical = Incident.query.filter_by(severity="Critical").count()
    high = Incident.query.filter_by(severity="High").count()
    medium = Incident.query.filter_by(severity="Medium").count()
    low = Incident.query.filter_by(severity="Low").count()
    blocked = Incident.query.filter_by(status="Blocked").count()
    security_score = compute_security_score()

    trend_labels, trend_counts = build_trend(days=7)
    recent_incidents = Incident.query.order_by(Incident.created_at.desc()).limit(10).all()

    top_attacks = [
        {"attack_type": row[0], "count": row[1]}
        for row in db.session.query(Incident.attack_type, func.count(Incident.id))
        .group_by(Incident.attack_type)
        .order_by(func.count(Incident.id).desc())
        .limit(5)
        .all()
    ]

    severity_rows = (
        db.session.query(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
        .all()
    )
    severity_counts = {row[0]: row[1] for row in severity_rows}

    return render_template(
        "home.html",
        total_requests=total_requests,
        total_incidents=total_incidents,
        critical_incidents=critical,
        blocked_count=blocked,
        security_score=security_score,
        target=get_active_target_url(),
        uptime=format_uptime(APP_STARTED_AT),
        top_attacks=top_attacks,
        severity_counts=severity_counts,
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        recent_incidents=recent_incidents,
        active_page="home",
    )


@websentinel_bp.route("/live-monitor")
@login_required
def dashboard_live_monitor():
    recent = RequestModel.query.order_by(RequestModel.id.desc()).limit(50).all()
    attack_types = [row[0] for row in db.session.query(Incident.attack_type).distinct().all()]
    return render_template(
        "live_monitor.html",
        requests=recent,
        attack_types=sorted(attack_types),
        active_page="live-monitor",
        refresh_interval=3000,
    )


@websentinel_bp.route("/incidents")
@login_required
def dashboard_incidents():
    incidents = Incident.query.order_by(Incident.id.desc()).limit(200).all()
    return render_template("incidents.html", incidents=incidents, active_page="incidents")


@websentinel_bp.route("/api/stats")
@login_required
def api_stats():
    """Return aggregate dashboard statistics as JSON.

    This endpoint is **polled repeatedly** by the live-refresh JavaScript
    on the dashboard home page (via ``/websentinel/api/stats``), so every
    key in the response must always be present and JSON-serializable —
    removing, renaming, or changing the type of any field will break the
    frontend without warning.

    Response fields (stable contract — do not rename):
        total_requests   – lifetime count of logged HTTP requests
        total_incidents  – lifetime count of created incidents
        critical / high / medium / low – incident counts per severity
        blocked          – incidents where the request was blocked (403)
        security_score   – 0-100 integer; starts at 100, decays with incidents
        target           – upstream URL the proxy forwards to
        uptime           – human-readable uptime string
        last_updated     – ISO-8601 UTC timestamp of when stats were computed
    """
    total_requests = RequestModel.query.count()
    total_incidents = Incident.query.count()

    # Single grouped query instead of 5+ separate COUNT queries.
    severity_rows = (
        db.session.query(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
        .all()
    )
    severity_counts = {row[0]: row[1] for row in severity_rows}

    # Guarantee every severity key is present even when its count is zero,
    # so frontend code never has to null-check or default these keys.
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)

    blocked = Incident.query.filter_by(status="Blocked").count()

    # Rolling-window score: only incidents from the last 24 hours count.
    security_score = compute_security_score()

    return jsonify({
        "total_requests": total_requests,
        "total_incidents": total_incidents,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked": blocked,
        "security_score": security_score,
        "target": get_active_target_url(),
        "uptime": format_uptime(APP_STARTED_AT),
        "last_updated": _utc_to_ist(datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S"),
    })


@websentinel_bp.route("/api/requests")
@login_required
def api_requests():
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except (ValueError, TypeError):
        limit = 50
    recent = RequestModel.query.order_by(RequestModel.id.desc()).limit(limit).all()
    return jsonify([request_to_dict(r) for r in recent])


def _filter_incidents_query():
    """Build a filtered Incident query from request args."""
    query = Incident.query
    search = request.args.get("q")
    severity = request.args.get("severity")
    status = request.args.get("status")
    attack_type = request.args.get("attack_type")

    if search:
        safe_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.join(RequestModel).filter(
            or_(
                Incident.attack_type.ilike(f"%{safe_search}%", escape="\\"),
                Incident.evidence.ilike(f"%{safe_search}%", escape="\\"),
                RequestModel.ip.ilike(f"%{safe_search}%", escape="\\"),
                RequestModel.url.ilike(f"%{safe_search}%", escape="\\"),
            )
        )
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if attack_type:
        query = query.filter_by(attack_type=attack_type)
    return query


def _incident_to_dict(i):
    return {
        "incident_code": i.incident_code,
        "attack_type": i.attack_type,
        "severity": i.severity,
        "status": i.status,
        "confidence": i.confidence,
        "risk_score": i.risk_score,
        "ip": i.request.ip if i.request else None,
        "path": i.request.url if i.request else None,
        "timestamp": _utc_to_ist(i.created_at).strftime("%Y-%m-%d %H:%M:%S"),
        "evidence": i.evidence,
        "recommendation": i.recommendation,
        "mitre_technique": i.mitre_technique,
        "mitre_name": get_mitre_info(i.mitre_technique),
        "owasp_technique": get_owasp_info(i.mitre_technique),
    }


@websentinel_bp.route("/api/incidents")
@login_required
def api_incidents():
    incidents = _filter_incidents_query().order_by(Incident.id.desc()).limit(200).all()
    return jsonify([_incident_to_dict(i) for i in incidents])


@websentinel_bp.route("/api/incidents/export")
@login_required
def api_incidents_export():
    fmt = request.args.get("format", "csv")
    incidents = _filter_incidents_query().order_by(Incident.id.desc()).all()
    rows = [_incident_to_dict(i) for i in incidents]

    if fmt == "json":
        from flask import Response as FlaskResponse
        import json as json_lib
        payload = json_lib.dumps(rows, indent=2)
        return FlaskResponse(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=incidents.json"},
        )

    import csv, io
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=[
        "incident_code", "attack_type", "severity", "status", "confidence",
        "risk_score", "ip", "path", "timestamp", "evidence", "recommendation",
        "mitre_technique", "mitre_name", "owasp_technique",
    ])
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, "") for k in writer.fieldnames})
    from flask import Response as FlaskResponse
    return FlaskResponse(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents.csv"},
    )


@websentinel_bp.route("/api/trend")
@login_required
def api_trend():
    try:
        days = min(max(int(request.args.get("days", 7)), 1), 30)
    except (ValueError, TypeError):
        days = 7
    labels, counts = build_trend(days=days)
    return jsonify({"labels": labels, "counts": counts})


@websentinel_bp.route("/api/attack-distribution")
@login_required
def api_attack_distribution():
    rows = (
        db.session.query(Incident.attack_type, func.count(Incident.id))
        .group_by(Incident.attack_type)
        .all()
    )
    return jsonify({"labels": [r[0] for r in rows], "counts": [r[1] for r in rows]})


@websentinel_bp.route("/analytics")
@login_required
def dashboard_analytics():
    severity_rows = (
        db.session.query(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
        .all()
    )
    severity_counts = {row[0]: row[1] for row in severity_rows}

    top_sources = [
        {
            "ip": row[0],
            "count": row[1],
            "last_seen": _utc_to_ist(row[2]).strftime("%Y-%m-%d %H:%M:%S") if row[2] else "N/A",
        }
        for row in (
            db.session.query(
                RequestModel.ip,
                func.count(Incident.id),
                func.max(Incident.created_at),
            )
            .join(Incident)
            .group_by(RequestModel.ip)
            .order_by(func.count(Incident.id).desc())
            .limit(10)
            .all()
        )
    ]

    top_paths = [
        {"path": row[0], "count": row[1]}
        for row in (
            db.session.query(RequestModel.url, func.count(Incident.id))
            .join(Incident)
            .group_by(RequestModel.url)
            .order_by(func.count(Incident.id).desc())
            .limit(10)
            .all()
        )
    ]

    trend_labels, trend_counts = build_trend(days=30)

    return render_template(
        "analytics.html",
        severity_counts=severity_counts,
        top_sources=top_sources,
        top_paths=top_paths,
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        active_page="analytics",
    )


# ---------------------------------------------------------------------
# Blocklist management routes
# ---------------------------------------------------------------------

@websentinel_bp.route("/blocklist")
@login_required
def dashboard_blocklist():
    from database.models import BlockedIP
    blocked = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return render_template("blocklist.html", blocked=blocked, active_page="blocklist")


@websentinel_bp.route("/block-ip", methods=["POST"])
@login_required
def block_ip_route():
    from database.models import BlockedIP
    ip = request.form.get("ip", "").strip()
    if not ip:
        return redirect(url_for("websentinel.dashboard_blocklist"))
    reason = request.form.get("reason", "Manual: blocked by analyst").strip() or "Manual: blocked by analyst"
    from utils.ip_blocklist import block_ip as do_block_ip
    do_block_ip(ip=ip, reason=reason, blocked_by="manual")
    return redirect(url_for("websentinel.dashboard_blocklist"))


@websentinel_bp.route("/unblock-ip", methods=["POST"])
@login_required
def unblock_ip_route():
    ip = request.form.get("ip", "").strip()
    if ip:
        from utils.ip_blocklist import unblock_ip as do_unblock_ip
        do_unblock_ip(ip)
    return redirect(url_for("websentinel.dashboard_blocklist"))


# ---------------------------------------------------------------------
# Target management routes — manual add/edit/enable/disable/activate/
# delete/test of the protected backend targets (see utils/targets.py).
#
# Security model: every route is @login_required, every state change is a
# CSRF-protected POST, URLs are validated server-side (http/https, hostname,
# no embedded credentials), and a target pointing at a loopback/private/
# address is ACCEPTED with an informational notice — internal backends are a
# legitimate use case, so a private address is never a hard block (section 3).
# Only one target is ever `active` at a time (section 0); the proxy forwards
# only to that one.
# ---------------------------------------------------------------------

@websentinel_bp.route("/targets")
@login_required
def dashboard_targets():
    from database.models import Target
    targets = Target.query.order_by(Target.id.asc()).all()
    private_targets = {t.id: is_private_target(t.target_url) for t in targets}
    return render_template(
        "targets.html",
        targets=targets,
        private_targets=private_targets,
        active_page="targets",
    )


@websentinel_bp.route("/targets/add", methods=["POST"])
@login_required
def add_target():
    from database.models import Target
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    enabled = request.form.get("enabled") == "true"

    if not name:
        flash("Target name is required.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    try:
        url = normalize_target_url(request.form.get("target_url", ""))
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    if Target.query.filter_by(target_url=url).first():
        flash("A target with this URL already exists.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    target = Target(
        name=name,
        target_url=url,
        description=description,
        enabled=enabled,
        active=False,
    )
    db.session.add(target)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("A target with this URL already exists.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    audit_target_event("created", target, session.get("username"))
    if is_private_target(url):
        flash("This target resolves to a private/internal address — confirm this is intentional.", "warning")
    flash(f"Target '{name}' added.", "success")
    return redirect(url_for("websentinel.dashboard_targets"))


@websentinel_bp.route("/targets/<int:target_id>/edit", methods=["GET", "POST"])
@login_required
def edit_target(target_id):
    from database.models import Target
    target = db.session.get(Target, target_id)
    if target is None:
        flash("Target not found.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        enabled = request.form.get("enabled") == "true"

        if not name:
            flash("Target name is required.", "danger")
            return render_template("targets_edit.html", target=target, active_page="targets")

        try:
            url = normalize_target_url(request.form.get("target_url", ""))
        except ValueError as e:
            flash(str(e), "danger")
            return render_template("targets_edit.html", target=target, active_page="targets")

        duplicate = Target.query.filter(
            Target.target_url == url, Target.id != target.id
        ).first()
        if duplicate:
            flash("Another target already uses this URL.", "danger")
            return render_template("targets_edit.html", target=target, active_page="targets")

        url_changed = url != target.target_url
        target.name = name
        target.target_url = url
        target.description = description
        target.enabled = enabled
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Another target already uses this URL.", "danger")
            return render_template("targets_edit.html", target=target, active_page="targets")

        audit_target_event("updated", target, session.get("username"))
        if url_changed and is_private_target(url):
            flash("This target resolves to a private/internal address — confirm this is intentional.", "warning")
        flash(f"Target '{name}' updated.", "success")
        return redirect(url_for("websentinel.dashboard_targets"))

    return render_template("targets_edit.html", target=target, active_page="targets")


@websentinel_bp.route("/targets/<int:target_id>/toggle", methods=["POST"])
@login_required
def toggle_target(target_id):
    from database.models import Target
    target = db.session.get(Target, target_id)
    if target is None:
        flash("Target not found.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    target.enabled = not target.enabled
    db.session.commit()
    state = "enabled" if target.enabled else "disabled"
    audit_target_event(f"{state}", target, session.get("username"))
    flash(f"Target '{target.name}' {state}.", "success")
    return redirect(url_for("websentinel.dashboard_targets"))


@websentinel_bp.route("/targets/<int:target_id>/activate", methods=["POST"])
@login_required
def activate_target(target_id):
    from database.models import Target
    target = db.session.get(Target, target_id)
    if target is None:
        flash("Target not found.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))
    if not target.enabled:
        flash("A disabled target cannot be set active — enable it first.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    set_active_target(target.id)
    audit_target_event("activated", target, session.get("username"))
    flash(f"Target '{target.name}' is now the active target.", "success")
    return redirect(url_for("websentinel.dashboard_targets"))


@websentinel_bp.route("/targets/<int:target_id>/delete", methods=["POST"])
@login_required
def delete_target(target_id):
    from database.models import Target
    target = db.session.get(Target, target_id)
    if target is None:
        flash("Target not found.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    # Explicit confirmation is required server-side, not just in the UI
    # modal — a bare POST without confirm=1 is rejected (section 8).
    if request.form.get("confirm") != "1":
        flash("Deletion was not confirmed — nothing was deleted.", "warning")
        return redirect(url_for("websentinel.dashboard_targets"))

    was_active = target.active
    deleted_info = {"id": target.id, "name": target.name, "target_url": target.target_url}
    db.session.delete(target)
    db.session.commit()
    audit_target_event("deleted", deleted_info, session.get("username"))
    flash(f"Target '{deleted_info['name']}' deleted.", "success")
    if was_active:
        flash("The active target was deleted — the proxy now falls back to WEBSENTINEL_TARGET.", "warning")
    return redirect(url_for("websentinel.dashboard_targets"))


@websentinel_bp.route("/targets/<int:target_id>/test", methods=["POST"])
@login_required
def test_target(target_id):
    from database.models import Target
    target = db.session.get(Target, target_id)
    if target is None:
        flash("Target not found.", "danger")
        return redirect(url_for("websentinel.dashboard_targets"))

    ok, message = test_target_connection(target.target_url)
    audit_target_event("tested-connection", target, session.get("username"))
    flash(f"{target.name}: {message}", "success" if ok else "danger")
    return redirect(url_for("websentinel.dashboard_targets"))


@websentinel_bp.route("/settings")
@login_required
def dashboard_settings():
    from database.models import Setting
    from utils.alerting import TOKEN_FILE, alerting_issue

    def _get(key):
        s = Setting.query.filter_by(key=key).first()
        return s.value if s else ""

    return render_template("settings.html",
        alert_email=_get("alert_email"),
        alert_cooldown_minutes=_get("alert_cooldown_minutes") or "60",
        alert_enabled=_get("alert_enabled") or "false",
        token_ready=os.path.exists(TOKEN_FILE),
        alerting_issue=alerting_issue(),
        active_page="settings",
    )


@websentinel_bp.route("/settings/update", methods=["POST"])
@login_required
def update_settings():
    from database.models import Setting
    fields = ["alert_email", "alert_cooldown_minutes", "alert_enabled"]
    for key in fields:
        value = request.form.get(key, "").strip()
        setting = Setting.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            db.session.add(Setting(key=key, value=value))

    db.session.commit()
    return redirect(url_for("websentinel.dashboard_settings"))


# ---------------------------------------------------------------------
# THE PROXY — catch-all route. Registered last; Werkzeug's routing
# matches the more specific /websentinel/* rules above regardless of
# declaration order, so this never shadows the dashboard.
#
# Detection happens in two phases:
# 1. PRE-FORWARD: Request-based detectors (SQL, XSS, Traversal, Enumeration)
#    run BEFORE forwarding so blocking can happen early.
# 2. POST-RESPONSE: Response-based detectors (Brute Force) run AFTER
#    receiving upstream response with status_code.
#
# This allows early blocking while still capturing response-dependent attacks.
# ---------------------------------------------------------------------
@csrf.exempt
def proxy(path):
    # --- IP BLOCKLIST: check first, before any detection runs ---
    client_ip = get_client_ip()
    if is_blocked(client_ip):
        return Response(
            "<h1>403 Forbidden</h1><p>Your IP has been blocked by WebSentinel.</p>",
            status=403,
            mimetype="text/html",
        )

    # --- RATE LIMIT: in-memory sliding window per client IP. ---
    # This is a temporary throttle (429) and NEVER writes to the blocklist:
    # once the window slides past the oldest request the IP is allowed again.
    # Blocklist auto-blocking (403) is separate and driven only by detectors.
    rate_limit = current_app.config.get("WEBSENTINEL_RATE_LIMIT", 100)
    rate_window = current_app.config.get("WEBSENTINEL_RATE_LIMIT_WINDOW", 60)
    if rate_limit and is_rate_limited(client_ip, limit=rate_limit, window_seconds=rate_window):
        logger.warning("Rate limit exceeded for %s", client_ip)
        retry_after = seconds_until_reset(client_ip, window_seconds=rate_window)
        return Response(
            "<h1>429 Too Many Requests</h1><p>Rate limit exceeded — please try again later.</p>",
            status=429,
            mimetype="text/html",
            headers={"Retry-After": str(retry_after)},
        )

    data, findings = inspect_request()
    scored_findings = [calculate_risk(dict(f)) for f in findings]
    # Target selection replaces the static TARGET_URL lookup at the Forward
    # step only — it runs after inspection/blocking, so a request can never
    # skip the detection engine, and it forwards to the single active+enabled
    # target from the database (falling back to WEBSENTINEL_TARGET when none).
    target_url = get_active_target_url()
    should_block = _should_block(data, findings, scored_findings)

    # A known repeat brute-force offender (already over the threshold from
    # prior requests) gets blocked here, before forwarding — this is what
    # actually stops an ongoing attack rather than just logging it, since
    # the real detect() below can't run until AFTER the upstream response.
    brute_force_repeat_offender = brute_force.should_preblock(data["url"], data["ip"])

    if should_block or brute_force_repeat_offender:
        if brute_force_repeat_offender and not should_block:
            findings = findings + [calculate_risk({
                "attack_type": "Brute Force",
                "confidence": "High",
                "evidence": f"Repeat offender: {data['ip']} already exceeded the "
                             f"failed-login threshold on this endpoint",
                "mitre_technique": "T1110",
                "recommendation": (
                    "Implement account lockout or exponential backoff after repeated "
                    "failures, add CAPTCHA after N attempts, and enforce rate limiting "
                    "per IP on authentication endpoints."
                ),
            })]
        persist_request_and_incidents(data, findings, status_code=403, blocked=True)
        return Response(
            "<h1>403 Forbidden</h1><p>Request blocked by WebSentinel — "
            "classified as a potential attack.</p>",
            status=403,
            mimetype="text/html",
        )

    # --- Forward the request upstream to the real website ---
    upstream_url = f"{target_url}/{path}"
    body, content_encoding = get_request_body()
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
        and k.lower() not in ("host", "x-forwarded-for", "x-real-ip")
    }
    # Rewrite forwarded-IP headers with the real client address — never trust
    # a client-supplied X-Forwarded-For.
    forward_headers["X-Forwarded-For"] = client_ip
    forward_headers["X-Real-IP"] = client_ip
    if content_encoding:
        forward_headers["Content-Encoding"] = content_encoding

    try:
        upstream_response = upstream_requests.request(
            method=request.method,
            url=upstream_url,
            headers=forward_headers,
            params=request.args,
            data=body,
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
        )
    except upstream_requests.exceptions.RequestException as e:
        # Log the real error server-side; never leak connection/library
        # internals (timeouts, resolved hosts, etc.) to the client.
        logger.warning("Upstream request failed for %s %s: %s", data["method"], data["url"], e)
        persist_request_and_incidents(data, findings, status_code=502, blocked=False)
        return Response(
            "<h1>502 Bad Gateway</h1><p>The upstream service is currently unavailable.</p>",
            status=502, mimetype="text/html",
        )

    # --- POST-RESPONSE DETECTION: Brute Force
    # Now that we have the upstream response status code, run brute force detection.
    data_with_status = dict(data)
    data_with_status["status_code"] = upstream_response.status_code
    brute_force_finding = brute_force.detect(data_with_status)
    if brute_force_finding:
        findings.append(brute_force_finding)

    persist_request_and_incidents(data, findings, status_code=upstream_response.status_code, blocked=False)

    # Rewrite Location headers that point back at the backend itself, so a
    # redirect can't be used to bypass the proxy on the client's next hop.
    response_headers = []
    for k, v in upstream_response.raw.headers.items():
        if k.lower() in HOP_BY_HOP_HEADERS:
            continue
        if k.lower() == "location":
            v = rewrite_location_header(v, target_url)
        response_headers.append((k, v))

    return Response(upstream_response.content, upstream_response.status_code, response_headers)


# Module-level app — this is what `gunicorn proxy_app:app` imports directly,
# and what running `python proxy_app.py` below also serves. Must be created
# via create_app() so the blueprint, database, and config are all wired up —
# a bare `Flask(__name__)` here would have no routes registered at all.
app = create_app()


if __name__ == "__main__":
    # Single HTTP process on one port. TLS is terminated by a reverse proxy
    # in production (see README); `flask db upgrade` / start_websentinel.sh
    # apply schema migrations before the server starts.
    with app.app_context():
        # The targets table only exists after upgrade() on a fresh install,
        # so the startup bootstrap runs here too (section 18).
        try:
            bootstrap_target_from_env()
        except Exception:
            db.session.rollback()
            logger.exception("Target bootstrap failed — proxy will use the env-var fallback.")

    port = int(os.environ.get("WEBSENTINEL_PORT", 8080))
    host = os.environ.get("WEBSENTINEL_HOST", "127.0.0.1")

    print(f"WebSentinel Reverse Proxy starting (dev server — use Gunicorn for production)")
    print(f"  Target site : {app.config['WEBSENTINEL_TARGET']}")
    print(f"  Proxy URL   : http://{host}:{port}")
    print(f"  Dashboard   : http://{host}:{port}/websentinel/")

    if host != "127.0.0.1":
        print("WARNING: binding to a non-localhost interface; ensure this is intentional.")
    app.run(host=host, port=port, debug=False)
