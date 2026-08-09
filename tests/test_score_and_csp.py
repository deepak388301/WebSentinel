"""
tests/test_score_and_csp.py

Tests for Phase 5:
  - Rolling-window security_score (old incidents don't affect score)
  - CSP nonces on inline scripts and styles
"""

from datetime import datetime, timedelta, timezone
from database.models import db, Request, Incident
from proxy_app import create_app, compute_security_score


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _seed_incident(app, severity="Critical", hours_ago=0):
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/test",
                       headers="{}", payload="test", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}-0",
            request_id=req.id,
            attack_type="SQL Injection",
            severity=severity,
            confidence="High",
            risk_score=95,
            evidence="test",
            recommendation="test",
            mitre_technique="T1190",
            status="Open",
            created_at=datetime.now(timezone.utc) - timedelta(hours=hours_ago),
        )
        db.session.add(inc)
        db.session.commit()
        return inc


class TestRollingWindowScore:
    def test_empty_db_score_is_100(self):
        app = _make_app()
        with app.app_context():
            assert compute_security_score() == 100

    def test_recent_critical_reduces_score(self):
        app = _make_app()
        _seed_incident(app, severity="Critical", hours_ago=1)
        with app.app_context():
            score = compute_security_score()
            assert score < 100
            assert score == 85  # 100 - 15

    def test_old_incident_does_not_affect_score(self):
        app = _make_app()
        _seed_incident(app, severity="Critical", hours_ago=48)
        with app.app_context():
            score = compute_security_score()
            assert score == 100  # outside 24h window

    def test_boundary_incident_near_24h(self):
        app = _make_app()
        _seed_incident(app, severity="High", hours_ago=23)
        with app.app_context():
            score = compute_security_score()
            # Within 24h window — counts
            assert score == 92  # 100 - 8

    def test_mixed_old_and_new(self):
        app = _make_app()
        _seed_incident(app, severity="Critical", hours_ago=1)  # counts
        _seed_incident(app, severity="High", hours_ago=48)     # doesn't count
        with app.app_context():
            score = compute_security_score()
            assert score == 85  # only the Critical counts


class TestCSPNonce:
    def test_csp_header_contains_nonce(self):
        app = _make_app()
        client = app.test_client()
        client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
        resp = client.get("/websentinel/")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "nonce-" in csp
        assert "unsafe-inline" not in csp

    def test_nonce_is_unique_per_request(self):
        app = _make_app()
        client = app.test_client()
        client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
        resp1 = client.get("/websentinel/")
        resp2 = client.get("/websentinel/")
        csp1 = resp1.headers.get("Content-Security-Policy", "")
        csp2 = resp2.headers.get("Content-Security-Policy", "")
        # Extract nonces
        import re
        nonce1 = re.search(r"nonce-([^';\s]+)", csp1).group(1)
        nonce2 = re.search(r"nonce-([^';\s]+)", csp2).group(1)
        assert nonce1 != nonce2

    def test_proxy_routes_no_csp(self):
        """CSP should only be set on /websentinel/ routes, not proxied routes."""
        app = _make_app()
        with app.test_client() as client:
            from unittest.mock import patch, MagicMock
            with patch("proxy_app.upstream_requests") as mock_req:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.content = b"OK"
                mock_resp.raw.headers = {}
                mock_req.request.return_value = mock_resp
                resp = client.get("/hello")
                assert "Content-Security-Policy" not in resp.headers
