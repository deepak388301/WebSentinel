"""
proxy_app.py — WebSentinel Reverse Proxy WAF mode.

This is the deployment mode that works for "any type of website," not just
Flask apps you control the source code of. WebSentinel here runs as an
INDEPENDENT service that sits in front of the real site and inspects every
request before it reaches it — the same architectural position as an
Nginx-based WAF or Cloudflare.

    Visitor → WebSentinel Proxy → forwards clean traffic → Real Website
                    │
              detect / log / score
              (optionally BLOCK)
                    │
              Dashboard at /websentinel/*

Because it operates purely on raw HTTP (method, path, headers, body), the
backend can be anything — PHP, WordPress, Node, a static site, another
Flask app. Nothing needs to be installed INTO that site's codebase.

--------------------------------------------------------------------------
CONFIGURATION (environment variables)
--------------------------------------------------------------------------
WEBSENTINEL_TARGET   URL of the real website being protected.
                     Default: http://127.0.0.1:9000  (the demo victim site)

WEBSENTINEL_MODE     "detect"  -> log and score attacks, forward everything
                                  (pure monitoring, nothing is ever blocked)
                     "protect" -> also BLOCK requests classified as
                                  Critical/High severity with a 403,
                                  instead of forwarding them
                     Default: detect

--------------------------------------------------------------------------
HTTPS / SSL
--------------------------------------------------------------------------
SSL is NOT handled inside this file. For local testing, just run it with
plain HTTP (below). For real deployments, run this app through Gunicorn
and let Gunicorn terminate SSL — pass your certificate directly on the
command line, no code changes needed:

    gunicorn --certfile=cert.pem --keyfile=key.pem \
             --bind 0.0.0.0:8443 proxy_app:app

See the README's "Running in production with Gunicorn + SSL" section for
the full setup, including how to generate a free certificate.

--------------------------------------------------------------------------
RUN
--------------------------------------------------------------------------
    WEBSENTINEL_TARGET=http://127.0.0.1:9000 WEBSENTINEL_MODE=protect \
        python proxy_app.py

Then send traffic to the PROXY's port (8080), not the real site's port —
the proxy forwards it onward after inspection.
"""

import csv
import io
import os
import json
import requests as upstream_requests
from datetime import datetime, timedelta, timezone
from flask import Flask, Blueprint, request, Response, render_template, jsonify, current_app
from sqlalchemy import func, or_

from database.models import db, Request as RequestModel, Incident
from detectors import run_pre_forward_detectors, brute_force
from utils.risk_engine import calculate_risk

# Only these severities get blocked in "protect" mode — Medium/Low are
# logged but still forwarded, since blocking on low-confidence findings
# would hurt real users more than it helps (a classic WAF false-positive
# problem you'll want to tune per deployment).
BLOCK_SEVERITIES = {"Critical", "High"}

DEFAULT_TARGET_URL = "http://127.0.0.1:9000"
DEFAULT_MODE = "detect"
APP_STARTED_AT = datetime.now(timezone.utc)

# Headers that must NOT be relayed as-is between proxy and client —
# these are connection-level headers that don't survive proxying correctly.
HOP_BY_HOP_HEADERS = {
    "content-encoding", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
}

websentinel_bp = Blueprint("websentinel", __name__, url_prefix="/websentinel")

def init_app(app, database_uri=None, mode=None, target_url=None):
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        database_uri
        or os.environ.get("WEBSENTINEL_DB_URI", "sqlite:///websentinel_proxy.db")
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["WEBSENTINEL_MODE"] = mode or os.environ.get("WEBSENTINEL_MODE", DEFAULT_MODE)
    app.config["WEBSENTINEL_TARGET"] = (
        (target_url or os.environ.get("WEBSENTINEL_TARGET", DEFAULT_TARGET_URL))
        .rstrip("/")
    )
    db.init_app(app)


def create_app(database_uri=None, mode=None, target_url=None):
    app = Flask(__name__)
    init_app(app, database_uri, mode, target_url)
    app.register_blueprint(websentinel_bp)

    # The catch-all proxy route can't use a decorator like the dashboard
    # routes above, because it needs to bind to THIS specific app instance
    # (create_app() may be called more than once, e.g. once per test).
    # Registered after the blueprint, but Werkzeug matches by rule
    # specificity regardless of registration order, so /websentinel/* is
    # never shadowed by this catch-all.
    app.add_url_rule(
        "/", defaults={"path": ""}, view_func=proxy,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    app.add_url_rule(
        "/<path:path>", view_func=proxy,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )

    with app.app_context():
        db.create_all()

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


def build_trend(days=7):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days - 1)
    rows = (
        db.session.query(func.strftime("%Y-%m-%d", Incident.created_at), func.count(Incident.id))
        .filter(Incident.created_at >= cutoff)
        .group_by(func.strftime("%Y-%m-%d", Incident.created_at))
        .order_by(func.strftime("%Y-%m-%d", Incident.created_at))
        .all()
    )
    row_map = {row[0]: row[1] for row in rows}
    labels = []
    counts = []
    for i in range(days - 1, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).date().strftime("%Y-%m-%d")
        labels.append(day)
        counts.append(row_map.get(day, 0))
    return labels, counts


def request_to_dict(req):
    attacks = [incident.attack_type for incident in req.incidents]
    severity = req.incidents[0].severity if req.incidents else None
    return {
        "timestamp": req.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
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
def inspect_request():
    """Builds the same 'data' dict shape the detectors already expect
    (see detectors/*.py), runs the PRE-FORWARD Detection Engine
    (request-only detectors for early blocking), and returns (data, findings).
    Post-response detectors (brute_force) run separately after upstream response."""
    query_payload = request.query_string.decode("utf-8", errors="ignore")
    try:
        body_payload = request.get_data(as_text=True)
    except Exception:
        body_payload = ""

    data = {
        "ip": request.remote_addr or "unknown",
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

    for finding in findings:
        finding = calculate_risk(finding)
        incident = Incident(
            incident_code=f"INC-{req_record.id:05d}",
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
    if findings:
        db.session.commit()


def is_blockable(findings):
    """protect mode blocks only if at least one finding is Critical/High."""
    for f in findings:
        scored = calculate_risk(dict(f))  # copy, since we score again below anyway
        if scored["severity"] in BLOCK_SEVERITIES:
            return True
    return False


# ---------------------------------------------------------------------
# Dashboard routes — namespaced under /websentinel/ so they never clash
# with the real site's own routes on the proxied path.
# ---------------------------------------------------------------------
@websentinel_bp.route("/")
def dashboard_home():
    total_requests = RequestModel.query.count()
    total_incidents = Incident.query.count()
    critical = Incident.query.filter_by(severity="Critical").count()
    high = Incident.query.filter_by(severity="High").count()
    medium = Incident.query.filter_by(severity="Medium").count()
    low = Incident.query.filter_by(severity="Low").count()
    blocked = Incident.query.filter_by(status="Blocked").count()
    penalty = critical * 15 + high * 8 + medium * 3
    security_score = max(0, 100 - penalty)

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
        mode=current_app.config["WEBSENTINEL_MODE"],
        target=current_app.config["WEBSENTINEL_TARGET"],
        uptime=format_uptime(APP_STARTED_AT),
        top_attacks=top_attacks,
        severity_counts=severity_counts,
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        recent_incidents=recent_incidents,
        active_page="home",
    )


@websentinel_bp.route("/live-monitor")
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
def dashboard_incidents():
    incidents = Incident.query.order_by(Incident.id.desc()).limit(200).all()
    return render_template("incidents.html", incidents=incidents, active_page="incidents")


@websentinel_bp.route("/api/stats")
def api_stats():
    total_requests = RequestModel.query.count()
    total_incidents = Incident.query.count()
    critical = Incident.query.filter_by(severity="Critical").count()
    high = Incident.query.filter_by(severity="High").count()
    medium = Incident.query.filter_by(severity="Medium").count()
    low = Incident.query.filter_by(severity="Low").count()
    blocked = Incident.query.filter_by(status="Blocked").count()
    penalty = critical * 15 + high * 8 + medium * 3
    security_score = max(0, 100 - penalty)

    return jsonify({
        "total_requests": total_requests,
        "total_incidents": total_incidents,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked": blocked,
        "security_score": security_score,
        "mode": current_app.config["WEBSENTINEL_MODE"],
        "target": current_app.config["WEBSENTINEL_TARGET"],
        "uptime": format_uptime(APP_STARTED_AT),
    })


@websentinel_bp.route("/api/requests")
def api_requests():
    limit = min(int(request.args.get("limit", 50)), 200)
    recent = RequestModel.query.order_by(RequestModel.id.desc()).limit(limit).all()
    return jsonify([request_to_dict(r) for r in recent])


@websentinel_bp.route("/api/incidents")
def api_incidents():
    query = Incident.query
    search = request.args.get("q")
    severity = request.args.get("severity")
    status = request.args.get("status")
    attack_type = request.args.get("attack_type")

    if search:
        query = query.join(RequestModel).filter(
            or_(
                Incident.attack_type.ilike(f"%{search}%"),
                Incident.evidence.ilike(f"%{search}%"),
                RequestModel.ip.ilike(f"%{search}%"),
                RequestModel.url.ilike(f"%{search}%"),
            )
        )
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if attack_type:
        query = query.filter_by(attack_type=attack_type)

    incidents = query.order_by(Incident.id.desc()).limit(200).all()
    return jsonify([
        {
            "incident_code": i.incident_code,
            "attack_type": i.attack_type,
            "severity": i.severity,
            "status": i.status,
            "confidence": i.confidence,
            "risk_score": i.risk_score,
            "ip": i.request.ip if i.request else None,
            "path": i.request.url if i.request else None,
            "timestamp": i.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "evidence": i.evidence,
            "recommendation": i.recommendation,
            "mitre_technique": i.mitre_technique,
        }
        for i in incidents
    ])


@websentinel_bp.route("/api/trend")
def api_trend():
    days = min(max(int(request.args.get("days", 7)), 1), 30)
    labels, counts = build_trend(days=days)
    return jsonify({"labels": labels, "counts": counts})


@websentinel_bp.route("/api/attack-distribution")
def api_attack_distribution():
    rows = (
        db.session.query(Incident.attack_type, func.count(Incident.id))
        .group_by(Incident.attack_type)
        .all()
    )
    return jsonify({"labels": [r[0] for r in rows], "counts": [r[1] for r in rows]})


@websentinel_bp.route("/analytics")
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
            "last_seen": row[2].strftime("%Y-%m-%d %H:%M:%S") if row[2] else "N/A",
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
def proxy(path):
    data, findings = inspect_request()
    scored_findings = [calculate_risk(dict(f)) for f in findings]
    proxy_mode = current_app.config["WEBSENTINEL_MODE"]
    target_url = current_app.config["WEBSENTINEL_TARGET"]
    should_block = proxy_mode == "protect" and any(
        f["severity"] in BLOCK_SEVERITIES for f in scored_findings
    )

    # A known repeat brute-force offender (already over the threshold from
    # prior requests) gets blocked here, before forwarding — this is what
    # actually stops an ongoing attack rather than just logging it, since
    # the real detect() below can't run until AFTER the upstream response.
    brute_force_repeat_offender = (
        proxy_mode == "protect"
        and brute_force.should_preblock(data["url"], data["ip"])
    )

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
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "host"
    }

    try:
        upstream_response = upstream_requests.request(
            method=request.method,
            url=upstream_url,
            headers=forward_headers,
            params=request.args,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
        )
    except upstream_requests.exceptions.RequestException as e:
        persist_request_and_incidents(data, findings, status_code=502, blocked=False)
        return Response(f"<h1>502 Bad Gateway</h1><p>Could not reach target: {e}</p>",
                         status=502, mimetype="text/html")

    # --- POST-RESPONSE DETECTION: Brute Force
    # Now that we have the upstream response status code, run brute force detection.
    data_with_status = dict(data)
    data_with_status["status_code"] = upstream_response.status_code
    brute_force_finding = brute_force.detect(data_with_status)
    if brute_force_finding:
        findings.append(brute_force_finding)

    persist_request_and_incidents(data, findings, status_code=upstream_response.status_code, blocked=False)

    response_headers = [
        (k, v) for k, v in upstream_response.raw.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    ]
    return Response(upstream_response.content, upstream_response.status_code, response_headers)


# Module-level app — this is what `gunicorn proxy_app:app` imports directly,
# and what running `python proxy_app.py` below also serves. Must be created
# via create_app() so the blueprint, database, and config are all wired up —
# a bare `Flask(__name__)` here would have no routes registered at all.
app = create_app()


if __name__ == "__main__":
    # Plain HTTP, for local development/testing only. For a real deployment
    # with HTTPS, don't run this file directly — use Gunicorn instead and
    # let it terminate SSL (see README: "Running in production with
    # Gunicorn + SSL"). Gunicorn imports the same `app` object above, so
    # nothing in this file needs to change between the two.
    port = int(os.environ.get("WEBSENTINEL_PORT", 8080))

    print(f"WebSentinel Reverse Proxy starting (dev server — use Gunicorn for production/SSL)")
    print(f"  Mode        : {app.config['WEBSENTINEL_MODE']}  ({'blocking Critical/High attacks' if app.config['WEBSENTINEL_MODE'] == 'protect' else 'monitoring only, nothing blocked'})")
    print(f"  Target site : {app.config['WEBSENTINEL_TARGET']}")
    print(f"  Proxy URL   : http://127.0.0.1:{port}")
    print(f"  Dashboard   : http://127.0.0.1:{port}/websentinel/")

    app.run(host="0.0.0.0", port=port, debug=False)
