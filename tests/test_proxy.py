import os
import re
from unittest.mock import patch, MagicMock
from database.models import db, Request, Incident
from proxy_app import (
    create_app, format_uptime, request_to_dict, attack_types_to_label,
    rewrite_location_header, HOP_BY_HOP_HEADERS,
)
from utils.risk_engine import calculate_risk
from datetime import datetime, timezone


def _make_app(target="http://127.0.0.1:9000"):
    app = create_app(database_uri="sqlite:///:memory:", target_url=target)
    with app.app_context():
        db.create_all()
    return app


def _login(client):
    """Authenticate the test client for dashboard access."""
    client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})


def _seed_incident(app, attack_type="SQL Injection", severity="Critical"):
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/test",
                       headers="{}", payload="test", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}", request_id=req.id,
            attack_type=attack_type, severity=severity, confidence="High",
            risk_score=95, evidence="test", recommendation="test",
            mitre_technique="T1190", status="Open",
        )
        db.session.add(inc)
        db.session.commit()
        return inc


# ---- format_uptime tests ----

def test_format_uptime_minutes_only():
    start = datetime.now(timezone.utc)
    result = format_uptime(start)
    assert result.endswith("m")
    assert "d" not in result
    assert "h" not in result


def test_format_uptime_hours_and_minutes():
    from datetime import timedelta
    start = datetime.now(timezone.utc) - timedelta(hours=2, minutes=30)
    result = format_uptime(start)
    assert "2h" in result
    assert "30m" in result
    assert "d" not in result


def test_format_uptime_days_hours_minutes():
    from datetime import timedelta
    start = datetime.now(timezone.utc) - timedelta(days=3, hours=5, minutes=15)
    result = format_uptime(start)
    assert "3d" in result
    assert "5h" in result
    assert "15m" in result


# ---- attack_types_to_label tests ----

def test_attack_types_to_label_empty():
    assert attack_types_to_label([]) is None


def test_attack_types_to_label_single():
    result = attack_types_to_label(["SQL Injection"])
    assert result == "SQL Injection"


def test_attack_types_to_label_multiple():
    result = attack_types_to_label(["SQL Injection", "XSS", "SQL Injection"])
    assert result is not None
    types = [t.strip() for t in result.split(",")]
    assert len(types) == 2
    assert "SQL Injection" in types
    assert "XSS" in types


# ---- request_to_dict tests ----

def test_request_to_dict_basic():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/test",
                       headers="{}", payload="", user_agent="agent", status_code=200)
        db.session.add(req)
        db.session.commit()
        d = request_to_dict(req)
        assert d["ip"] == "10.0.0.1"
        assert d["method"] == "GET"
        assert d["path"] == "/test"
        assert d["status_code"] == 200
        assert d["attack"] is False
        assert d["attack_type"] is None
        assert d["severity"] is None


# ---- rewrite_location_header tests ----

def test_rewrite_relative_location_unchanged():
    app = _make_app(target="http://backend:8000")
    with app.test_request_context("/test"):
        result = rewrite_location_header("/other-page", "http://backend:8000")
        assert result == "/other-page"


def test_rewrite_external_location_unchanged():
    app = _make_app(target="http://backend:8000")
    with app.test_request_context("/test"):
        result = rewrite_location_header("https://evil.com/phish", "http://backend:8000")
        assert result == "https://evil.com/phish"


def test_rewrite_same_host_location_rewritten():
    app = _make_app(target="http://backend:8000")
    with app.test_request_context("/test", base_url="http://proxy:8080"):
        result = rewrite_location_header("http://backend:8000/dashboard", "http://backend:8000")
        assert "proxy" in result
        assert "backend" not in result
        assert "/dashboard" in result


# ---- Dashboard route tests ----

def test_dashboard_home_renders():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/")
    assert resp.status_code == 200
    assert b"Overview" in resp.data


def test_live_monitor_renders():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/live-monitor")
    assert resp.status_code == 200
    assert b"Live" in resp.data


def test_incidents_renders():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/incidents")
    assert resp.status_code == 200
    assert b"Incidents" in resp.data


def test_analytics_renders():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/analytics")
    assert resp.status_code == 200


# ---- API endpoint tests ----

def test_api_stats():
    app = _make_app()
    _seed_incident(app, severity="Critical")
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total_requests"] >= 1
    assert data["total_incidents"] >= 1
    assert data["critical"] >= 1
    assert "security_score" in data
    assert "target" in data
    assert "uptime" in data
    assert "last_updated" in data


def test_api_stats_empty_database():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/stats")
    assert resp.status_code == 200
    data = resp.get_json()
    for key in ("total_requests", "total_incidents", "critical", "high",
                "medium", "low", "blocked", "security_score",
                "target", "uptime", "last_updated"):
        assert key in data, f"missing key: {key}"
    assert data["total_requests"] == 0
    assert data["total_incidents"] == 0
    assert data["critical"] == 0
    assert data["high"] == 0
    assert data["medium"] == 0
    assert data["low"] == 0
    assert data["blocked"] == 0
    assert data["security_score"] == 100


def test_api_requests():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/requests")
    assert resp.status_code == 200
    assert resp.is_json


def test_api_requests_with_valid_limit():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/requests?limit=10")
    assert resp.status_code == 200


def test_api_requests_with_invalid_limit_does_not_crash():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/requests?limit=abc")
    assert resp.status_code == 200


def test_api_requests_limit_capped_at_200():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/requests?limit=999")
    assert resp.status_code == 200


def test_api_incidents():
    app = _make_app()
    _seed_incident(app)
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/incidents")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)


def test_api_incidents_filter_by_severity():
    app = _make_app()
    _seed_incident(app, severity="Critical")
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/incidents?severity=Critical")
    assert resp.status_code == 200
    data = resp.get_json()
    assert all(i["severity"] == "Critical" for i in data)


def test_api_incidents_filter_by_status():
    app = _make_app()
    _seed_incident(app)
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/incidents?status=Open")
    assert resp.status_code == 200
    data = resp.get_json()
    assert all(i["status"] == "Open" for i in data)


def test_api_incidents_search():
    app = _make_app()
    _seed_incident(app, attack_type="SQL Injection")
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/incidents?q=SQL")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) >= 1


def test_api_trend():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/trend")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "labels" in data
    assert "counts" in data
    assert len(data["labels"]) == 7


def test_api_trend_custom_days():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/trend?days=14")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["labels"]) == 14


def test_api_trend_clamped_days():
    app = _make_app()
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/trend?days=999")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["labels"]) <= 30


def test_build_trend_correctness():
    """Verify build_trend counts incidents per day correctly."""
    from proxy_app import build_trend
    app = _make_app()
    with app.app_context():
        # Seed incidents on known dates
        today = datetime.now(timezone.utc).date()
        for i in range(3):
            req = Request(ip="10.0.0.1", method="GET", url="/trend-test",
                          headers="{}", payload="t", user_agent="t", status_code=200)
            db.session.add(req)
            db.session.commit()
            inc = Incident(
                incident_code=f"INC-{req.id:05d}", request_id=req.id,
                attack_type="XSS", severity="High", confidence="High",
                risk_score=80, evidence="t", recommendation="t",
                mitre_technique="T1059", status="Open",
                created_at=datetime.now(timezone.utc),
            )
            db.session.add(inc)
        db.session.commit()

        labels, counts = build_trend(days=7)
        assert len(labels) == 7
        assert len(counts) == 7
        today_str = today.isoformat()
        assert today_str in labels
        idx = labels.index(today_str)
        assert counts[idx] >= 3


def test_api_attack_distribution():
    app = _make_app()
    _seed_incident(app, attack_type="XSS")
    client = app.test_client()
    _login(client)
    resp = client.get("/websentinel/api/attack-distribution")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "labels" in data
    assert "counts" in data


# ---- Proxy forwarding tests ----

def test_proxy_forwards_clean_request():
    app = _make_app(target="http://127.0.0.1:9000")
    with patch("proxy_app.upstream_requests") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_resp.raw.headers = {}
        mock_req.request.return_value = mock_resp
        client = app.test_client()
        resp = client.get("/hello")
        assert resp.status_code == 200
        mock_req.request.assert_called_once()


def test_proxy_blocks_attack():
    app = _make_app(target="http://127.0.0.1:9000")
    client = app.test_client()
    # UNION SELECT matches Very High confidence → blocked in enforce mode
    resp = client.get("/?id=1'+UNION+SELECT+username,password+FROM+users--")
    assert resp.status_code == 403
    assert b"blocked" in resp.data.lower() or b"403" in resp.data


def test_proxy_logs_attack():
    app = _make_app(target="http://127.0.0.1:9000")
    with patch("proxy_app.upstream_requests") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"
        mock_resp.raw.headers = {}
        mock_req.request.return_value = mock_resp
        client = app.test_client()
        # UNION SELECT matches Very High confidence → blocked in enforce mode
        resp = client.get("/?id=1'+UNION+SELECT+username,password+FROM+users--")
        assert resp.status_code == 403
        with app.app_context():
            assert Incident.query.count() >= 1


def test_proxy_returns_502_on_upstream_failure():
    import requests as req_lib
    app = _make_app(target="http://127.0.0.1:9000")
    with patch("requests.request") as mock_req:
        mock_req.side_effect = req_lib.exceptions.ConnectionError("refused")
        client = app.test_client()
        resp = client.get("/anything")
        assert resp.status_code == 502
        assert b"502" in resp.data or b"unavailable" in resp.data.lower()


def test_proxy_returns_403_for_xss():
    app = _make_app(target="http://127.0.0.1:9000")
    client = app.test_client()
    resp = client.get("/search?q=<script>alert(1)</script>")
    assert resp.status_code == 403


def test_proxy_returns_403_for_traversal():
    app = _make_app(target="http://127.0.0.1:9000")
    client = app.test_client()
    resp = client.get("/view?file=../../../etc/passwd")
    assert resp.status_code == 403


def test_proxy_stores_request_in_db():
    app = _make_app(target="http://127.0.0.1:9000")
    with patch("proxy_app.upstream_requests") as mock_req:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"
        mock_resp.raw.headers = {}
        mock_req.request.return_value = mock_resp
        client = app.test_client()
        client.get("/test-page")
        with app.app_context():
            reqs = Request.query.filter_by(url="/test-page").all()
            assert len(reqs) == 1
            assert reqs[0].method == "GET"


def test_proxy_hop_by_hop_headers_filtered():
    assert "content-encoding" in HOP_BY_HOP_HEADERS
    assert "transfer-encoding" in HOP_BY_HOP_HEADERS
    assert "connection" in HOP_BY_HOP_HEADERS
    assert "host" not in HOP_BY_HOP_HEADERS


class TestCSRFExemptProxy:
    """Proxy passthrough must NOT be blocked by CSRF protection.

    Regression: CSRFProtect(app) was catching all POST routes including the
    proxy catch-all, breaking every POST-based feature on any site behind
    WebSentinel.
    """

    def _mock_backend(self):
        """Return a started mock for proxy_app.upstream_requests."""
        patcher = patch("proxy_app.upstream_requests")
        mock_req = patcher.start()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"
        mock_resp.raw.headers = {}
        mock_req.request.return_value = mock_resp
        return mock_req, patcher

    def _make_app(self):
        app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
        with app.app_context():
            db.create_all()
        return app

    def test_benign_form_post_not_csrf_blocked(self):
        """A harmless form POST through the proxy must not get 400 CSRF error."""
        app = self._make_app()
        mock_req, patcher = self._mock_backend()
        try:
            client = app.test_client()
            resp = client.post("/submit", data={"name": "test", "value": "123"})
            assert resp.status_code != 400
            assert b"CSRF token is missing" not in resp.data
        finally:
            patcher.stop()

    def test_benign_json_post_not_csrf_blocked(self):
        """A harmless JSON POST through the proxy must not get 400 CSRF error."""
        app = self._make_app()
        mock_req, patcher = self._mock_backend()
        try:
            client = app.test_client()
            resp = client.post(
                "/api/data",
                data='{"key": "value"}',
                content_type="application/json",
            )
            assert resp.status_code != 400
            assert b"CSRF token is missing" not in resp.data
        finally:
            patcher.stop()

    def test_sqli_post_still_detected_through_proxy(self):
        """SQLi in a POST body is still detected/blocked despite CSRF exemption."""
        app = self._make_app()
        client = app.test_client()
        resp = client.post("/search", data={"q": "1' UNION SELECT * FROM users--"})
        assert resp.status_code == 403

    def test_dashboard_login_still_requires_csrf(self):
        """Dashboard login POST still requires CSRF token — exemption is proxy-only."""
        os.environ["WTF_CSRF_ENABLED"] = "true"
        try:
            app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
            with app.app_context():
                db.create_all()
            client = app.test_client()
            resp = client.post("/websentinel/login", data={
                "username": "testadmin", "password": "testpass123"
            })
            assert resp.status_code == 400
            assert b"CSRF token is missing" in resp.data
        finally:
            os.environ["WTF_CSRF_ENABLED"] = "false"

    def test_dashboard_forms_work_with_csrf_token(self):
        """Dashboard POST forms (login, block-ip) succeed when the token is sent."""
        os.environ["WTF_CSRF_ENABLED"] = "true"
        try:
            app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
            with app.app_context():
                db.create_all()
            client = app.test_client()

            def _csrf_token(path):
                page = client.get(path).data.decode()
                match = re.search(r'name="csrf_token" value="([^"]+)"', page)
                assert match, f"no csrf_token hidden input on {path}"
                return match.group(1)

            # Login with the token from the login page.
            resp = client.post("/websentinel/login", data={
                "username": "testadmin", "password": "testpass123",
                "csrf_token": _csrf_token("/websentinel/login"),
            })
            assert resp.status_code == 302

            # block-ip WITHOUT a token is rejected by CSRF protection.
            resp = client.post("/websentinel/block-ip", data={"ip": "1.2.3.4"})
            assert resp.status_code == 400

            # block-ip WITH the token succeeds. (Token is session-scoped and
            # identical across dashboard forms; the settings page always
            # renders one, unlike blocklist which only shows it when full.)
            token = _csrf_token("/websentinel/settings")
            resp = client.post(
                "/websentinel/block-ip",
                data={"ip": "1.2.3.4", "csrf_token": token},
                follow_redirects=True,
            )
            assert resp.status_code == 200
            assert b"1.2.3.4" in resp.data
        finally:
            os.environ["WTF_CSRF_ENABLED"] = "false"
