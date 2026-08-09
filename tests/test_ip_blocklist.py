"""
tests/test_ip_blocklist.py

Tests for IP blocklist feature:
  - Auto-block: IP with threshold Critical/High incidents gets blocked
  - Auto-block: below threshold not blocked
  - Auto-block: respects time window (old incidents don't count)
  - Auto-block: respects duration (expires after configured minutes)
  - Manual block: immediate 403 on next request
  - Manual block: permanent unless manually unblocked
  - Unblock: removes block, next request proceeds
  - Proxy pipeline: is_blocked checked before detectors (no detection on blocked IP)
  - Dashboard routes: require login, require CSRF token
  - WEBSENTINEL_AUTOBLOCK_ENABLED=false disables auto-blocking
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from database.models import db, Request, Incident, BlockedIP
from proxy_app import create_app
from utils.ip_blocklist import (
    is_blocked, maybe_auto_block, block_ip, unblock_ip,
    _threshold, _window_minutes, _duration_minutes,
)


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _seed_critical_incidents(app, ip, count):
    """Seed `count` Critical incidents for the given IP."""
    with app.app_context():
        for _ in range(count):
            req = Request(
                ip=ip, method="GET", url="/test",
                headers="{}", payload="test", user_agent="test", status_code=200,
            )
            db.session.add(req)
            db.session.commit()
            inc = Incident(
                incident_code=f"INC-{req.id:05d}-0",
                request_id=req.id,
                attack_type="SQL Injection",
                severity="Critical",
                confidence="Very High",
                risk_score=100,
                evidence="test",
                recommendation="test",
                mitre_technique="T1190",
                status="Blocked",
            )
            db.session.add(inc)
            db.session.commit()


class TestIsBlocked:
    def test_unblocked_ip_returns_false(self):
        app = _make_app()
        with app.app_context():
            assert is_blocked("10.0.0.1") is False

    def test_blocked_ip_returns_true(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="test", blocked_by="manual")
            assert is_blocked("10.0.0.1") is True

    def test_expired_block_returns_false(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="test", blocked_by="auto",
                     expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
            assert is_blocked("10.0.0.1") is False

    def test_permanent_block_returns_true(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="test", blocked_by="manual", expires_at=None)
            assert is_blocked("10.0.0.1") is True


class TestAutoBlock:
    def test_threshold_crossed_blocks_ip(self):
        app = _make_app()
        with app.app_context():
            _seed_critical_incidents(app, "10.0.0.1", 5)
            maybe_auto_block("10.0.0.1")
            assert is_blocked("10.0.0.1") is True
            record = BlockedIP.query.filter_by(ip="10.0.0.1").first()
            assert record.blocked_by == "auto"

    def test_below_threshold_not_blocked(self):
        app = _make_app()
        with app.app_context():
            _seed_critical_incidents(app, "10.0.0.1", 4)
            maybe_auto_block("10.0.0.1")
            assert is_blocked("10.0.0.1") is False

    def test_already_blocked_no_op(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="manual block", blocked_by="manual")
            _seed_critical_incidents(app, "10.0.0.1", 5)
            maybe_auto_block("10.0.0.1")
            # Should still be the manual block, not overwritten
            record = BlockedIP.query.filter_by(ip="10.0.0.1").first()
            assert record.blocked_by == "manual"

    def test_old_incidents_outside_window_dont_count(self):
        app = _make_app()
        with app.app_context():
            # Seed incidents that are 20 minutes old (outside 10-min window)
            for _ in range(5):
                req = Request(
                    ip="10.0.0.1", method="GET", url="/test",
                    headers="{}", payload="test", user_agent="test", status_code=200,
                )
                db.session.add(req)
                db.session.commit()
                inc = Incident(
                    incident_code=f"INC-{req.id:05d}-0",
                    request_id=req.id,
                    attack_type="SQL Injection",
                    severity="Critical",
                    confidence="Very High",
                    risk_score=100,
                    evidence="test",
                    recommendation="test",
                    mitre_technique="T1190",
                    status="Blocked",
                    created_at=datetime.now(timezone.utc) - timedelta(minutes=20),
                )
                db.session.add(inc)
                db.session.commit()
            maybe_auto_block("10.0.0.1")
            assert is_blocked("10.0.0.1") is False

    def test_duration_sets_expiry(self):
        app = _make_app()
        with app.app_context():
            os.environ["WEBSENTINEL_AUTOBLOCK_DURATION_MINUTES"] = "30"
            try:
                _seed_critical_incidents(app, "10.0.0.1", 5)
                maybe_auto_block("10.0.0.1")
                record = BlockedIP.query.filter_by(ip="10.0.0.1").first()
                assert record.expires_at is not None
                # Should be approximately 30 minutes from now
                expires = record.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                delta = expires - datetime.now(timezone.utc)
                assert 25 < delta.total_seconds() / 60 < 35
            finally:
                os.environ.pop("WEBSENTINEL_AUTOBLOCK_DURATION_MINUTES", None)

    def test_force_true_blocks_immediately(self):
        app = _make_app()
        with app.app_context():
            maybe_auto_block("10.0.0.1", force=True)
            assert is_blocked("10.0.0.1") is True

    def test_force_false_uses_threshold(self):
        app = _make_app()
        with app.app_context():
            maybe_auto_block("10.0.0.1", force=False)
            assert is_blocked("10.0.0.1") is False

    def test_disabled_via_env_var(self):
        app = _make_app()
        with app.app_context():
            os.environ["WEBSENTINEL_AUTOBLOCK_ENABLED"] = "false"
            try:
                _seed_critical_incidents(app, "10.0.0.1", 10)
                maybe_auto_block("10.0.0.1")
                assert is_blocked("10.0.0.1") is False
            finally:
                os.environ.pop("WEBSENTINEL_AUTOBLOCK_ENABLED", None)


class TestManualBlock:
    def test_manual_block_creates_record(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="manual test", blocked_by="manual")
            record = BlockedIP.query.filter_by(ip="10.0.0.1").first()
            assert record is not None
            assert record.blocked_by == "manual"
            assert record.expires_at is None

    def test_manual_block_is_permanent(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="manual test", blocked_by="manual")
            assert is_blocked("10.0.0.1") is True

    def test_unblock_removes_block(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.1", reason="test", blocked_by="manual")
            assert is_blocked("10.0.0.1") is True
            unblock_ip("10.0.0.1")
            assert is_blocked("10.0.0.1") is False

    def test_unblock_nonexistent_is_noop(self):
        app = _make_app()
        with app.app_context():
            unblock_ip("10.0.0.1")  # should not raise
            assert is_blocked("10.0.0.1") is False


class TestProxyPipeline:
    def test_blocked_ip_403_without_detection(self):
        app = _make_app()
        with app.app_context():
            block_ip("127.0.0.1", reason="test", blocked_by="manual")
        client = app.test_client()
        with patch("proxy_app.inspect_request") as mock_inspect:
            resp = client.get("/?id=1'+UNION+SELECT+*+FROM+users--")
            assert resp.status_code == 403
            assert b"blocked by WebSentinel" in resp.data
            mock_inspect.assert_not_called()

    def test_unblocked_ip_proceeds_normally(self):
        app = _make_app()
        client = app.test_client()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"
        mock_resp.raw.headers = {}
        with patch("proxy_app.upstream_requests") as mock_req:
            mock_req.request.return_value = mock_resp
            resp = client.get("/hello")
            assert resp.status_code == 200


class TestDashboardRoutes:
    def test_blocklist_requires_login(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/websentinel/blocklist")
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_block_ip_requires_login(self):
        app = _make_app()
        client = app.test_client()
        resp = client.post("/websentinel/block-ip", data={"ip": "1.2.3.4"})
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_unblock_ip_requires_login(self):
        app = _make_app()
        client = app.test_client()
        resp = client.post("/websentinel/unblock-ip", data={"ip": "1.2.3.4"})
        assert resp.status_code == 302
        assert "/websentinel/login" in resp.headers["Location"]

    def test_blocklist_page_renders(self):
        app = _make_app()
        client = app.test_client()
        # Login
        client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        resp = client.get("/websentinel/blocklist")
        assert resp.status_code == 200
        assert b"IP Blocklist" in resp.data

    def test_block_ip_via_dashboard(self):
        app = _make_app()
        client = app.test_client()
        client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        resp = client.post("/websentinel/block-ip", data={
            "ip": "10.0.0.99", "reason": "test block"
        })
        assert resp.status_code == 302
        with app.app_context():
            assert is_blocked("10.0.0.99") is True

    def test_unblock_ip_via_dashboard(self):
        app = _make_app()
        with app.app_context():
            block_ip("10.0.0.99", reason="test", blocked_by="manual")
        client = app.test_client()
        client.post("/websentinel/login", data={
            "username": "testadmin", "password": "testpass123"
        })
        resp = client.post("/websentinel/unblock-ip", data={"ip": "10.0.0.99"})
        assert resp.status_code == 302
        with app.app_context():
            assert is_blocked("10.0.0.99") is False


class TestConfigHelpers:
    def test_threshold_default(self):
        assert _threshold() == 5

    def test_window_minutes_default(self):
        assert _window_minutes() == 10

    def test_duration_minutes_default(self):
        assert _duration_minutes() == 1440

    def test_duration_minutes_zero_means_permanent(self):
        os.environ["WEBSENTINEL_AUTOBLOCK_DURATION_MINUTES"] = "0"
        try:
            assert _duration_minutes() is None
        finally:
            os.environ.pop("WEBSENTINEL_AUTOBLOCK_DURATION_MINUTES", None)
