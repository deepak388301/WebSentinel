"""
tests/test_auth.py

Tests for dashboard authentication (Phase 1 hardening):
  - Unauthenticated access is redirected to /websentinel/login
  - Valid credentials grant access
  - Invalid credentials show error
  - Logout clears session
  - Login page renders
  - Rate-limiting after repeated failures
  - CSRF protection when enabled
  - Session cookie security flags
"""

import os
import re

import pytest

from database.models import db
from proxy_app import create_app


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


class TestStartupFailFast:
    """App refuses to start when WEBSENTINEL_ADMIN_PASS is unset."""

    def test_missing_admin_password_refuses_startup(self, monkeypatch):
        monkeypatch.delenv("WEBSENTINEL_ADMIN_PASS", raising=False)
        with pytest.raises(RuntimeError, match="WEBSENTINEL_ADMIN_PASS must be set"):
            create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")

    def test_admin_password_set_starts_normally(self):
        app = _make_app()
        assert app is not None


class TestLoginRequired:
    """All dashboard routes require authentication."""

    def test_unauthenticated_home_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_live_monitor_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/live-monitor")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_incidents_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/incidents")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_analytics_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/analytics")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_api_stats_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/api/stats")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_api_requests_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/api/requests")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_api_incidents_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/api/incidents")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_api_trend_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/api/trend")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unauthenticated_api_attack_distribution_redirects(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/api/attack-distribution")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]


class TestLogin:
    def test_login_page_renders(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/login")
        assert resp.status_code == 200
        assert b"WebSentinel Login" in resp.data
        assert b"Sign In" in resp.data

    def test_valid_credentials_grant_access(self):
        app = _make_app()
        client = app.test_client()
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        assert resp.status_code == 302
        assert "/websentinel/" in resp.headers["Location"]
        # Follow redirect — should see dashboard
        resp = client.get("/websentinel/")
        assert resp.status_code == 200
        assert b"Overview" in resp.data

    def test_invalid_credentials_show_error(self):
        app = _make_app()
        client = app.test_client()
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "wrongpassword"
        })
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.data

    def test_empty_credentials_show_error(self):
        app = _make_app()
        client = app.test_client()
        resp = client.post("/websentinel/login", data={
            "username": "", "password": ""
        })
        assert resp.status_code == 200
        assert b"Invalid credentials" in resp.data


class TestLogout:
    def test_logout_clears_session(self):
        app = _make_app()
        client = app.test_client()
        # Login first
        client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        # Verify access
        resp = client.get("/websentinel/")
        assert resp.status_code == 200
        # Logout
        resp = client.get("/websentinel/logout")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]
        # Verify access is now revoked
        resp = client.get("/websentinel/")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]


class TestProxyPassthrough:
    """Proxy routes (non-dashboard) should NOT require auth."""

    def test_proxy_route_no_auth_required(self):
        from unittest.mock import patch, MagicMock
        app = _make_app()
        client = app.test_client()
        with patch("proxy_app.upstream_requests") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"<html>OK</html>"
            mock_resp.raw.headers = {}
            mock_req.request.return_value = mock_resp
            resp = client.get("/hello")
            assert resp.status_code == 200


class TestLoginRateLimit:
    """Rate-limit the dashboard's own login after repeated failures."""

    def test_6th_attempt_is_rejected(self):
        app = _make_app()
        client = app.test_client()
        for _ in range(5):
            client.post("/websentinel/login", data={
                "username": "testadmin", "password": "wrong"
            })
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "wrong"
        })
        assert resp.status_code == 429
        assert b"Too many failed attempts" in resp.data

    def test_rate_limit_rejected_before_password_check(self):
        app = _make_app()
        client = app.test_client()
        for _ in range(5):
            client.post("/websentinel/login", data={
                "username": "testadmin", "password": "wrong"
            })
        # Even with CORRECT password, still rejected
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        assert resp.status_code == 429


class TestCSRFProtection:
    """CSRF tokens are required for login POST when CSRF is enabled."""

    def _make_csrf_app(self):
        os.environ["WTF_CSRF_ENABLED"] = "true"
        try:
            app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
            with app.app_context():
                db.create_all()
            return app
        finally:
            os.environ["WTF_CSRF_ENABLED"] = "false"

    def test_post_without_csrf_token_rejected(self):
        app = self._make_csrf_app()
        client = app.test_client()
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        assert resp.status_code == 400

    def test_post_with_valid_csrf_token_succeeds(self):
        app = self._make_csrf_app()
        client = app.test_client()
        # GET the login page to obtain a CSRF token
        resp = client.get("/websentinel/login")
        assert resp.status_code == 200
        html = resp.data.decode()
        m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        assert m, "CSRF token not found in login form"
        token = m.group(1)
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123",
            "csrf_token": token,
        })
        assert resp.status_code == 302


class TestSessionCookieFlags:
    """Session cookie has secure flags set."""

    def test_cookie_flags(self):
        app = _make_app()
        client = app.test_client()
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        assert resp.status_code == 302
        cookie = None
        for h in resp.headers.getlist("Set-Cookie"):
            if "session" in h.lower():
                cookie = h
                break
        assert cookie is not None
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie
        # SECURE should NOT be set when WEBSENTINEL_SSL is not "true"
        assert "Secure" not in cookie
