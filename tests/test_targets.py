"""
tests/test_targets.py

Tests for the Manual Target Management feature:

  - Model: creation, defaults, timezone-aware timestamps, duplicate-URL rejection
  - URL validation: valid http/https, trailing-slash normalization,
    embedded-credentials rejection, malformed/invalid URLs rejected
  - Single-active-target invariant: setting one active clears the others;
    a disabled target can never become active
  - Bootstrap (section 18): empty table seeds one enabled+active row from
    WEBSENTINEL_TARGET and is idempotent
  - Auth: every target route requires login
  - CSRF: every state-changing target POST requires a valid token
  - Security: private/internal targets (http://127.0.0.1:9000,
    http://localhost:5173) are ACCEPTED, not rejected — the section-3
    informational-notice-not-block decision, proven in the DB
  - Proxy integration: active+enabled target is forwarded to; no active
    target falls back to WEBSENTINEL_TARGET; SQLi is still blocked through
    the new target-selection code path
  - detectors/ssrf.py helpers: _parse_encoded_ip / _is_dangerous_ip
"""

import os
import re
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from database.models import db, Target
from proxy_app import create_app
from utils.targets import (
    normalize_target_url, is_private_target, set_active_target,
    get_active_target_url, bootstrap_target_from_env,
    test_target_connection as check_target_connection,
)
from detectors.ssrf import _parse_encoded_ip, _is_dangerous_ip, detect


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _login(client):
    client.post("/websentinel/login", data={
        "username": "testadmin", "password": "testpass123"
    })


def _add_target(app, name="Backend", url="http://backend-a:8000", enabled=True):
    with app.app_context():
        t = Target(name=name, target_url=url, enabled=enabled, active=False)
        db.session.add(t)
        db.session.commit()
        return t.id


# ---------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------

class TestTargetModel:
    def test_create_and_read(self):
        app = _make_app()
        with app.app_context():
            t = Target(name="Prod", target_url="https://api.example.com",
                       description="prod backend", enabled=True, active=False)
            db.session.add(t)
            db.session.commit()
            loaded = db.session.get(Target, t.id)
            assert loaded.name == "Prod"
            assert loaded.target_url == "https://api.example.com"
            assert loaded.description == "prod backend"
            assert loaded.enabled is True
            assert loaded.active is False

    def test_defaults_enabled_true_active_false(self):
        app = _make_app()
        with app.app_context():
            t = Target(name="X", target_url="http://x:8080")
            db.session.add(t)
            db.session.commit()
            assert t.enabled is True
            assert t.active is False

    def test_timestamps_are_timezone_aware(self):
        app = _make_app()
        with app.app_context():
            t = Target(name="X", target_url="http://x:8080")
            db.session.add(t)
            db.session.commit()
            assert isinstance(t.created_at, datetime)
            assert isinstance(t.updated_at, datetime)

    def test_duplicate_normalized_url_rejected_at_db_level(self):
        app = _make_app()
        with app.app_context():
            db.session.add(Target(name="A", target_url="http://example.com"))
            db.session.commit()
            db.session.add(Target(name="B", target_url="http://example.com"))
            with pytest.raises(Exception):
                db.session.commit()
            db.session.rollback()

    def test_description_defaults_to_empty(self):
        app = _make_app()
        with app.app_context():
            t = Target(name="X", target_url="http://x:8080")
            db.session.add(t)
            db.session.commit()
            assert t.description == ""


# ---------------------------------------------------------------------
# URL validation tests
# ---------------------------------------------------------------------

class TestNormalizeTargetUrl:
    def test_valid_http(self):
        assert normalize_target_url("http://backend:8000") == "http://backend:8000"

    def test_valid_https(self):
        assert normalize_target_url("https://api.example.com") == "https://api.example.com"

    def test_trailing_slash_stripped(self):
        assert normalize_target_url("http://example.com/") == "http://example.com"
        assert normalize_target_url("http://example.com/path/") == "http://example.com/path"

    def test_hostname_lowercased_and_port_kept(self):
        assert normalize_target_url("HTTP://Example.COM:8080/") == "http://example.com:8080"

    def test_ipv6_literal_accepted(self):
        assert normalize_target_url("http://[::1]:9000") == "http://[::1]:9000"

    def test_reject_empty(self):
        with pytest.raises(ValueError):
            normalize_target_url("")

    def test_reject_missing_scheme(self):
        with pytest.raises(ValueError):
            normalize_target_url("not-a-url")

    def test_reject_disallowed_scheme(self):
        with pytest.raises(ValueError):
            normalize_target_url("ftp://example.com")

    def test_reject_http_only(self):
        with pytest.raises(ValueError):
            normalize_target_url("http://")

    def test_reject_missing_hostname(self):
        with pytest.raises(ValueError):
            normalize_target_url("https:///path")

    def test_reject_embedded_credentials(self):
        with pytest.raises(ValueError):
            normalize_target_url("https://user:password@example.com")

    def test_reject_whitespace_hostname(self):
        with pytest.raises(ValueError):
            normalize_target_url("http://exa mple.com")

    def test_reject_invalid_port(self):
        with pytest.raises(ValueError):
            normalize_target_url("http://example.com:99999")


class TestPrivateTargetNotice:
    def test_private_targets_classified(self):
        assert is_private_target("http://127.0.0.1:9000") is True
        assert is_private_target("http://localhost:5173") is True
        assert is_private_target("http://10.0.0.5") is True
        assert is_private_target("http://192.168.1.1") is True
        assert is_private_target("http://169.254.169.254") is True

    def test_public_targets_not_classified(self):
        assert is_private_target("http://example.com") is False
        assert is_private_target("https://8.8.8.8") is False


# ---------------------------------------------------------------------
# SSRF helper tests (detectors/ssrf.py — shared classification logic)
# ---------------------------------------------------------------------

class TestSsrfHelpers:
    def test_parse_plain_ip(self):
        from ipaddress import IPv4Address
        assert _parse_encoded_ip("127.0.0.1") == IPv4Address("127.0.0.1")

    def test_parse_encoded_decimal(self):
        from ipaddress import IPv4Address
        assert _parse_encoded_ip("2130706433") == IPv4Address("127.0.0.1")

    def test_parse_encoded_octal_and_hex(self):
        from ipaddress import IPv4Address
        assert _parse_encoded_ip("017700000001") == IPv4Address("127.0.0.1")
        assert _parse_encoded_ip("0x7f000001") == IPv4Address("127.0.0.1")

    def test_parse_hostname_returns_none(self):
        assert _parse_encoded_ip("example.com") is None

    def test_is_dangerous_ip_private_ranges(self):
        for host in ("127.0.0.1", "localhost", "10.0.0.1", "192.168.0.1",
                     "172.16.0.1", "169.254.169.254", "::1"):
            assert _is_dangerous_ip(host) is True, host

    def test_is_dangerous_ip_public(self):
        for host in ("8.8.8.8", "93.184.216.34", "example.com", ""):
            assert _is_dangerous_ip(host) is False, host

    def test_ssrf_detect_behavior_unchanged(self):
        # Regression: the new helpers must not have changed detect() itself.
        assert detect({"payload": "url=http://127.0.0.1:3000/internal"}) is not None
        assert detect({"payload": "url=https://example.com/page"}) is None
        assert detect({"payload": ""}) is None


# ---------------------------------------------------------------------
# Active-target invariant tests
# ---------------------------------------------------------------------

class TestSetActiveTarget:
    def test_setting_one_active_clears_others(self):
        app = _make_app()
        a = _add_target(app, "A", "http://a:8000")
        b = _add_target(app, "B", "http://b:8000")
        c = _add_target(app, "C", "http://c:8000")
        with app.app_context():
            set_active_target(b)
            set_active_target(a)
            active = Target.query.filter_by(active=True).all()
            assert [t.name for t in active] == ["A"]

    def test_never_two_active(self):
        app = _make_app()
        a = _add_target(app, "A", "http://a:8000")
        b = _add_target(app, "B", "http://b:8000")
        with app.app_context():
            set_active_target(a)
            set_active_target(b)
            assert Target.query.filter_by(active=True).count() == 1

    def test_disabled_target_cannot_be_activated(self):
        app = _make_app()
        a = _add_target(app, "A", "http://a:8000", enabled=True)
        off = _add_target(app, "Off", "http://off:8000", enabled=False)
        with app.app_context():
            set_active_target(a)
            with pytest.raises(ValueError):
                set_active_target(off)
            assert Target.query.filter_by(active=True).first().name == "A"


class TestGetActiveTargetUrl:
    def test_returns_active_enabled_target(self):
        app = _make_app()
        _add_target(app, "A", "http://a:8000")
        with app.app_context():
            set_active_target(Target.query.first().id)
            assert get_active_target_url() == "http://a:8000"

    def test_falls_back_when_no_active_target(self):
        app = _make_app()
        with app.app_context():
            assert get_active_target_url() == "http://127.0.0.1:9000"

    def test_falls_back_when_active_target_disabled(self):
        app = _make_app()
        _add_target(app, "A", "http://a:8000", enabled=False)
        with app.app_context():
            Target.query.filter_by(target_url="http://a:8000").update({Target.active: True})
            db.session.commit()
            assert get_active_target_url() == "http://127.0.0.1:9000"


# ---------------------------------------------------------------------
# Bootstrap tests (section 18)
# ---------------------------------------------------------------------

class TestBootstrap:
    def test_seeds_single_enabled_active_target(self):
        app = _make_app()
        with app.app_context():
            bootstrap_target_from_env()
            targets = Target.query.all()
            assert len(targets) == 1
            assert targets[0].target_url == "http://127.0.0.1:9000"
            assert targets[0].enabled is True
            assert targets[0].active is True

    def test_bootstrap_is_idempotent(self):
        app = _make_app()
        with app.app_context():
            bootstrap_target_from_env()
            bootstrap_target_from_env()
            assert Target.query.count() == 1

    def test_bootstrap_skips_when_rows_exist(self):
        app = _make_app()
        _add_target(app, "Existing", "http://existing:9000")
        with app.app_context():
            bootstrap_target_from_env()
            assert Target.query.count() == 1
            assert Target.query.first().name == "Existing"


# ---------------------------------------------------------------------
# Auth tests — every target route requires login
# ---------------------------------------------------------------------

class TestAuth:
    def test_list_requires_login(self):
        app = _make_app()
        resp = app.test_client().get("/websentinel/targets")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_add_requires_login(self):
        app = _make_app()
        resp = app.test_client().post("/websentinel/targets/add", data={
            "name": "X", "target_url": "http://x:8000"
        })
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_edit_requires_login(self):
        app = _make_app()
        resp = app.test_client().get("/websentinel/targets/1/edit")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_toggle_requires_login(self):
        app = _make_app()
        resp = app.test_client().post("/websentinel/targets/1/toggle")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_activate_requires_login(self):
        app = _make_app()
        resp = app.test_client().post("/websentinel/targets/1/activate")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_delete_requires_login(self):
        app = _make_app()
        resp = app.test_client().post("/websentinel/targets/1/delete", data={"confirm": "1"})
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_test_connection_requires_login(self):
        app = _make_app()
        resp = app.test_client().post("/websentinel/targets/1/test")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]


# ---------------------------------------------------------------------
# CSRF tests — state-changing POSTs require a valid token
# ---------------------------------------------------------------------

class TestCSRF:
    @pytest.fixture(autouse=True)
    def _csrf_env(self):
        os.environ["WTF_CSRF_ENABLED"] = "true"
        yield
        os.environ["WTF_CSRF_ENABLED"] = "false"

    def _app(self):
        return create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")

    def _token(self, client, path="/websentinel/targets"):
        page = client.get(path).data.decode()
        match = re.search(r'name="csrf_token" value="([^"]+)"', page)
        assert match, "no csrf_token on page"
        return match.group(1)

    def _login_with_token(self, client):
        token = self._token(client, "/websentinel/login")
        resp = client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123", "csrf_token": token,
        })
        assert resp.status_code == 302

    def test_add_without_token_rejected(self):
        app = self._app()
        with app.app_context():
            db.create_all()
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "X", "target_url": "http://x:8000"
        })
        assert resp.status_code == 400

    def test_add_with_token_succeeds(self):
        app = self._app()
        with app.app_context():
            db.create_all()
        client = app.test_client()
        self._login_with_token(client)
        token = self._token(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "X", "target_url": "http://x:8000",
            "enabled": "true", "csrf_token": token,
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Target.query.count() == 1

    def test_activate_without_token_rejected(self):
        app = self._app()
        with app.app_context():
            db.create_all()
            t = Target(name="X", target_url="http://x:8000", enabled=True, active=False)
            db.session.add(t)
            db.session.commit()
            tid = t.id
        client = app.test_client()
        _login(client)
        resp = client.post(f"/websentinel/targets/{tid}/activate")
        assert resp.status_code == 400


# ---------------------------------------------------------------------
# Security: private/internal targets are ACCEPTED, not rejected (section 3)
# ---------------------------------------------------------------------

class TestPrivateTargetsAccepted:
    def test_loopback_target_accepted(self):
        app = _make_app()
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "Loopback", "target_url": "http://127.0.0.1:9000", "enabled": "true"
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Target.query.filter_by(target_url="http://127.0.0.1:9000").count() == 1

    def test_localhost_target_accepted(self):
        app = _make_app()
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "Frontend", "target_url": "http://localhost:5173", "enabled": "true"
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Target.query.filter_by(target_url="http://localhost:5173").count() == 1

    def test_private_10_network_target_accepted(self):
        app = _make_app()
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "Internal", "target_url": "http://10.0.0.5:80", "enabled": "true"
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Target.query.filter_by(target_url="http://10.0.0.5:80").count() == 1

    def test_invalid_urls_rejected(self):
        app = _make_app()
        client = app.test_client()
        _login(client)
        for bad in ("http://", "not-a-url", "ftp://example.com",
                    "https://user:password@example.com"):
            client.post("/websentinel/targets/add", data={
                "name": "Bad", "target_url": bad, "enabled": "true"
            })
        with app.app_context():
            assert Target.query.count() == 0


# ---------------------------------------------------------------------
# Dashboard route integration tests
# ---------------------------------------------------------------------

class TestDashboardRoutes:
    def test_targets_page_renders(self):
        app = _make_app()
        _add_target(app, "Prod", "http://backend-a:8000")
        client = app.test_client()
        _login(client)
        resp = client.get("/websentinel/targets")
        assert resp.status_code == 200
        assert b"Protected Targets" in resp.data
        assert b"backend-a:8000" in resp.data

    def test_add_via_dashboard(self):
        app = _make_app()
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "Added", "target_url": "http://added:9000/", "enabled": "true"
        })
        assert resp.status_code == 302
        with app.app_context():
            t = Target.query.filter_by(name="Added").first()
            assert t is not None
            assert t.target_url == "http://added:9000"  # trailing slash stripped

    def test_duplicate_url_rejected_via_dashboard(self):
        app = _make_app()
        _add_target(app, "A", "http://same:8000")
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "B", "target_url": "http://same:8000", "enabled": "true"
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Target.query.count() == 1

    def test_duplicate_url_trailing_slash_variant_rejected_via_dashboard(self):
        # http://a:8000/ must be treated as the same URL as http://a:8000:
        # normalization runs before the duplicate check.
        app = _make_app()
        _add_target(app, "A", "http://same:8000")
        client = app.test_client()
        _login(client)
        resp = client.post("/websentinel/targets/add", data={
            "name": "B", "target_url": "http://same:8000/", "enabled": "true"
        })
        assert resp.status_code == 302
        with app.app_context():
            assert Target.query.count() == 1

    def test_edit_via_dashboard(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        resp = client.post(f"/websentinel/targets/{tid}/edit", data={
            "name": "Renamed", "target_url": "http://b:8000", "description": "d",
            "enabled": "true",
        })
        assert resp.status_code == 302
        with app.app_context():
            t = db.session.get(Target, tid)
            assert t.name == "Renamed"
            assert t.target_url == "http://b:8000"

    def test_edit_to_duplicate_url_rejected(self):
        app = _make_app()
        a_id = _add_target(app, "A", "http://a:8000")
        _add_target(app, "B", "http://b:8000")
        client = app.test_client()
        _login(client)
        resp = client.post(f"/websentinel/targets/{a_id}/edit", data={
            "name": "A", "target_url": "http://b:8000", "enabled": "true"
        })
        assert resp.status_code == 200  # re-renders edit form with error
        with app.app_context():
            assert db.session.get(Target, a_id).target_url == "http://a:8000"

    def test_edit_to_duplicate_url_trailing_slash_variant_rejected(self):
        app = _make_app()
        a_id = _add_target(app, "A", "http://a:8000")
        _add_target(app, "B", "http://b:8000")
        client = app.test_client()
        _login(client)
        resp = client.post(f"/websentinel/targets/{a_id}/edit", data={
            "name": "A", "target_url": "http://b:8000/", "enabled": "true"
        })
        assert resp.status_code == 200  # re-renders edit form with error
        with app.app_context():
            assert db.session.get(Target, a_id).target_url == "http://a:8000"

    def test_toggle_disable_and_enable(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        client.post(f"/websentinel/targets/{tid}/toggle")
        with app.app_context():
            assert db.session.get(Target, tid).enabled is False
        client.post(f"/websentinel/targets/{tid}/toggle")
        with app.app_context():
            assert db.session.get(Target, tid).enabled is True

    def test_activate_via_dashboard(self):
        app = _make_app()
        a_id = _add_target(app, "A", "http://a:8000")
        b_id = _add_target(app, "B", "http://b:8000")
        client = app.test_client()
        _login(client)
        client.post(f"/websentinel/targets/{a_id}/activate")
        client.post(f"/websentinel/targets/{b_id}/activate")
        with app.app_context():
            assert db.session.get(Target, b_id).active is True
            assert db.session.get(Target, a_id).active is False

    def test_activate_disabled_target_rejected_via_dashboard(self):
        app = _make_app()
        tid = _add_target(app, "Off", "http://off:8000", enabled=False)
        client = app.test_client()
        _login(client)
        client.post(f"/websentinel/targets/{tid}/activate")
        with app.app_context():
            assert db.session.get(Target, tid).active is False

    def test_delete_requires_confirm(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        client.post(f"/websentinel/targets/{tid}/delete")
        with app.app_context():
            assert db.session.get(Target, tid) is not None

    def test_delete_with_confirm(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        client.post(f"/websentinel/targets/{tid}/delete", data={"confirm": "1"})
        with app.app_context():
            assert db.session.get(Target, tid) is None

    def test_deleting_active_target_clears_active(self):
        app = _make_app()
        a_id = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        with app.app_context():
            set_active_target(a_id)
        client.post(f"/websentinel/targets/{a_id}/delete", data={"confirm": "1"})
        with app.app_context():
            assert Target.query.filter_by(active=True).count() == 0


# ---------------------------------------------------------------------
# Test Connection route (section 11)
# ---------------------------------------------------------------------

class TestTestConnection:
    def test_connection_success(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        with patch("utils.targets.upstream_requests") as mock_req:
            mock_resp = MagicMock(status_code=200)
            mock_req.get.return_value = mock_resp
            resp = client.post(f"/websentinel/targets/{tid}/test")
            assert resp.status_code == 302
            kwargs = mock_req.get.call_args
            assert kwargs[1]["allow_redirects"] is False
            assert kwargs[1]["timeout"] == 4.0

    def test_connection_failure(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://a:8000")
        client = app.test_client()
        _login(client)
        import requests as req_lib
        with patch("utils.targets.upstream_requests") as mock_req:
            mock_req.get.side_effect = req_lib.exceptions.ConnectionError("refused")
            resp = client.post(f"/websentinel/targets/{tid}/test")
            assert resp.status_code == 302

    def test_redirects_not_followed(self):
        # A 302 must be reported as reachable and never followed (a redirect
        # to an internal address is a classic SSRF bypass), so
        # allow_redirects=False is mandatory.
        with patch("utils.targets.upstream_requests") as mock_req:
            mock_resp = MagicMock(status_code=302)
            mock_req.get.return_value = mock_resp
            ok, message = check_target_connection("http://a:8000")
            assert ok is True
            assert "302" in message
            assert mock_req.get.call_args[1]["allow_redirects"] is False
            assert mock_resp.close.called


# ---------------------------------------------------------------------
# Proxy integration tests
# ---------------------------------------------------------------------

class TestProxyIntegration:
    def _mock_backend(self, content=b"OK", status=200):
        patcher = patch("proxy_app.upstream_requests")
        mock_req = patcher.start()
        mock_resp = MagicMock(status_code=status, content=content)
        mock_resp.raw.headers = {}
        mock_req.request.return_value = mock_resp
        return mock_req, patcher

    def test_forwards_to_active_target(self):
        app = _make_app()
        tid = _add_target(app, "Backend", "http://backend-a:8000")
        client = app.test_client()
        with app.app_context():
            set_active_target(tid)
        mock_req, patcher = self._mock_backend()
        try:
            resp = client.get("/hello")
            assert resp.status_code == 200
            assert mock_req.request.call_args[1]["url"].startswith("http://backend-a:8000")
        finally:
            patcher.stop()

    def test_falls_back_when_no_active_target(self):
        app = _make_app()
        client = app.test_client()
        mock_req, patcher = self._mock_backend()
        try:
            resp = client.get("/hello")
            assert resp.status_code == 200
            assert mock_req.request.call_args[1]["url"].startswith("http://127.0.0.1:9000")
        finally:
            patcher.stop()

    def test_disabled_active_target_falls_back(self):
        app = _make_app()
        tid = _add_target(app, "A", "http://backend-a:8000", enabled=False)
        client = app.test_client()
        with app.app_context():
            Target.query.filter_by(id=tid).update({Target.active: True})
            db.session.commit()
        mock_req, patcher = self._mock_backend()
        try:
            resp = client.get("/hello")
            assert resp.status_code == 200
            assert mock_req.request.call_args[1]["url"].startswith("http://127.0.0.1:9000")
        finally:
            patcher.stop()

    def test_sqli_still_blocked_through_new_code_path(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/?id=1'+UNION+SELECT+username,password+FROM+users--")
        assert resp.status_code == 403

    def test_clean_request_forwarded_to_active_private_target(self):
        app = _make_app()
        tid = _add_target(app, "Local", "http://127.0.0.1:9000")
        client = app.test_client()
        with app.app_context():
            set_active_target(tid)
        mock_req, patcher = self._mock_backend()
        try:
            resp = client.get("/page")
            assert resp.status_code == 200
            assert mock_req.request.call_args[1]["url"].startswith("http://127.0.0.1:9000")
        finally:
            patcher.stop()
