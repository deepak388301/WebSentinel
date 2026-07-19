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

import os
import json
import requests as upstream_requests
from flask import Flask, request, Response, render_template, jsonify

from database.models import db, Request as RequestModel, Incident
from detectors import run_all_detectors
from utils.risk_engine import calculate_risk

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
TARGET_URL = os.environ.get("WEBSENTINEL_TARGET", "http://127.0.0.1:9000").rstrip("/")
MODE = os.environ.get("WEBSENTINEL_MODE", "detect")  # "detect" or "protect"

# Only these severities get blocked in "protect" mode — Medium/Low are
# logged but still forwarded, since blocking on low-confidence findings
# would hurt real users more than it helps (a classic WAF false-positive
# problem you'll want to tune per deployment).
BLOCK_SEVERITIES = {"Critical", "High"}

# Headers that must NOT be relayed as-is between proxy and client —
# these are connection-level headers that don't survive proxying correctly.
HOP_BY_HOP_HEADERS = {
    "content-encoding", "content-length", "transfer-encoding",
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
}

def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "WEBSENTINEL_DB_URI", "sqlite:///websentinel_proxy.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()

    return app


app = create_app()


# ---------------------------------------------------------------------
# Core inspection logic — shared by every proxied request
# ---------------------------------------------------------------------
def inspect_request():
    """Builds the same 'data' dict shape the detectors already expect
    (see detectors/*.py), runs the Detection Engine, and persists the
    Request record. Returns (data, findings)."""
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

    findings = run_all_detectors(data)
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
@app.route("/websentinel/")
def dashboard_home():
    total_requests = RequestModel.query.count()
    total_incidents = Incident.query.count()
    critical = Incident.query.filter_by(severity="Critical").count()
    blocked = Incident.query.filter_by(status="Blocked").count()
    penalty = (
        critical * 15
        + Incident.query.filter_by(severity="High").count() * 8
        + Incident.query.filter_by(severity="Medium").count() * 3
    )
    security_score = max(0, 100 - penalty)

    return render_template(
        "home.html",
        total_requests=total_requests,
        total_incidents=total_incidents,
        critical_incidents=critical,
        blocked_count=blocked,
        security_score=security_score,
        mode=MODE,
        target=TARGET_URL,
    )


@app.route("/websentinel/live-monitor")
def dashboard_live_monitor():
    recent = RequestModel.query.order_by(RequestModel.id.desc()).limit(50).all()
    return render_template("live_monitor.html", requests=recent)


@app.route("/websentinel/incidents")
def dashboard_incidents():
    all_incidents = Incident.query.order_by(Incident.id.desc()).all()
    return render_template("incidents.html", incidents=all_incidents)


@app.route("/websentinel/analytics")
def dashboard_analytics():
    return render_template("analytics.html")


@app.route("/websentinel/api/attack-distribution")
def api_attack_distribution():
    from sqlalchemy import func
    rows = (
        db.session.query(Incident.attack_type, func.count(Incident.id))
        .group_by(Incident.attack_type)
        .all()
    )
    return jsonify({"labels": [r[0] for r in rows], "counts": [r[1] for r in rows]})


# ---------------------------------------------------------------------
# THE PROXY — catch-all route. Registered last; Werkzeug's routing
# matches the more specific /websentinel/* rules above regardless of
# declaration order, so this never shadows the dashboard.
# ---------------------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path):
    data, findings = inspect_request()
    scored_findings = [calculate_risk(dict(f)) for f in findings]
    should_block = MODE == "protect" and any(
        f["severity"] in BLOCK_SEVERITIES for f in scored_findings
    )

    if should_block:
        persist_request_and_incidents(data, findings, status_code=403, blocked=True)
        return Response(
            "<h1>403 Forbidden</h1><p>Request blocked by WebSentinel — "
            "classified as a potential attack.</p>",
            status=403,
            mimetype="text/html",
        )

    # --- Forward the request upstream to the real website ---
    upstream_url = f"{TARGET_URL}/{path}"
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

    persist_request_and_incidents(data, findings, status_code=upstream_response.status_code, blocked=False)

    response_headers = [
        (k, v) for k, v in upstream_response.raw.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    ]
    return Response(upstream_response.content, upstream_response.status_code, response_headers)


if __name__ == "__main__":
    # Plain HTTP, for local development/testing only. For a real deployment
    # with HTTPS, don't run this file directly — use Gunicorn instead and
    # let it terminate SSL (see README: "Running in production with
    # Gunicorn + SSL"). Gunicorn imports the same `app` object below, so
    # nothing in this file needs to change between the two.
    port = int(os.environ.get("WEBSENTINEL_PORT", 8080))

    print(f"WebSentinel Reverse Proxy starting (dev server — use Gunicorn for production/SSL)")
    print(f"  Mode        : {MODE}  ({'blocking Critical/High attacks' if MODE == 'protect' else 'monitoring only, nothing blocked'})")
    print(f"  Target site : {TARGET_URL}")
    print(f"  Proxy URL   : http://127.0.0.1:{port}")
    print(f"  Dashboard   : http://127.0.0.1:{port}/websentinel/")

    app.run(host="0.0.0.0", port=port, debug=False)
