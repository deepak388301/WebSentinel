"""
tests/test_retention.py

Tests for Phase 6: configurable data retention cleanup.
"""

import os
from datetime import datetime, timedelta, timezone

from database.models import db, Request, Incident, AlertedIP, LoginAttempt
from proxy_app import create_app, cleanup_old_data


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _seed_data(app, request_days_ago=0, incident_days_ago=0, login_days_ago=0, alert_days_ago=0):
    """Seed rows with configurable ages."""
    with app.app_context():
        now = datetime.now(timezone.utc)

        req = Request(
            ip="10.0.0.1", method="GET", url="/test",
            headers="{}", payload="test", user_agent="test", status_code=200,
            timestamp=now - timedelta(days=request_days_ago),
        )
        db.session.add(req)
        db.session.commit()

        inc = Incident(
            incident_code=f"INC-{req.id:05d}-0",
            request_id=req.id,
            attack_type="SQL Injection",
            severity="Critical",
            confidence="High",
            risk_score=95,
            evidence="test",
            recommendation="test",
            mitre_technique="T1190",
            status="Open",
            created_at=now - timedelta(days=incident_days_ago),
        )
        db.session.add(inc)
        db.session.commit()  # commit so inc.id is available for AlertedIP

        login = LoginAttempt(
            ip="10.0.0.1",
            url="/login",
            timestamp=now - timedelta(days=login_days_ago),
        )
        db.session.add(login)

        alert = AlertedIP(
            ip="10.0.0.1",
            incident_id=inc.id,
            first_alerted_at=now - timedelta(days=alert_days_ago),
        )
        db.session.add(alert)
        db.session.commit()


class TestRetentionCleanup:
    def test_old_requests_deleted(self):
        app = _make_app()
        _seed_data(app, request_days_ago=60)
        os.environ["WEBSENTINEL_RETENTION_REQUESTS_DAYS"] = "30"
        try:
            with app.app_context():
                deleted = cleanup_old_data()
                assert deleted > 0
                assert Request.query.count() == 0
        finally:
            os.environ.pop("WEBSENTINEL_RETENTION_REQUESTS_DAYS", None)

    def test_recent_requests_kept(self):
        app = _make_app()
        _seed_data(app, request_days_ago=5)
        os.environ["WEBSENTINEL_RETENTION_REQUESTS_DAYS"] = "30"
        try:
            with app.app_context():
                deleted = cleanup_old_data()
                assert Request.query.count() == 1
        finally:
            os.environ.pop("WEBSENTINEL_RETENTION_REQUESTS_DAYS", None)

    def test_old_incidents_deleted(self):
        app = _make_app()
        _seed_data(app, incident_days_ago=120)
        os.environ["WEBSENTINEL_RETENTION_INCIDENTS_DAYS"] = "90"
        try:
            with app.app_context():
                deleted = cleanup_old_data()
                assert deleted > 0
                assert Incident.query.count() == 0
        finally:
            os.environ.pop("WEBSENTINEL_RETENTION_INCIDENTS_DAYS", None)

    def test_recent_incidents_kept(self):
        app = _make_app()
        _seed_data(app, incident_days_ago=10)
        os.environ["WEBSENTINEL_RETENTION_INCIDENTS_DAYS"] = "90"
        try:
            with app.app_context():
                deleted = cleanup_old_data()
                assert Incident.query.count() == 1
        finally:
            os.environ.pop("WEBSENTINEL_RETENTION_INCIDENTS_DAYS", None)

    def test_old_login_attempts_deleted(self):
        app = _make_app()
        _seed_data(app, login_days_ago=100)
        os.environ["WEBSENTINEL_RETENTION_REQUESTS_DAYS"] = "30"
        os.environ["WEBSENTINEL_RETENTION_INCIDENTS_DAYS"] = "90"
        try:
            with app.app_context():
                cleanup_old_data()
                assert LoginAttempt.query.count() == 0
        finally:
            os.environ.pop("WEBSENTINEL_RETENTION_REQUESTS_DAYS", None)
            os.environ.pop("WEBSENTINEL_RETENTION_INCIDENTS_DAYS", None)

    def test_old_alerted_ips_deleted(self):
        app = _make_app()
        _seed_data(app, alert_days_ago=100)
        os.environ["WEBSENTINEL_RETENTION_REQUESTS_DAYS"] = "30"
        os.environ["WEBSENTINEL_RETENTION_INCIDENTS_DAYS"] = "90"
        try:
            with app.app_context():
                cleanup_old_data()
                assert AlertedIP.query.count() == 0
        finally:
            os.environ.pop("WEBSENTINEL_RETENTION_REQUESTS_DAYS", None)
            os.environ.pop("WEBSENTINEL_RETENTION_INCIDENTS_DAYS", None)

    def test_empty_db_no_error(self):
        app = _make_app()
        with app.app_context():
            deleted = cleanup_old_data()
            assert deleted == 0

    def test_default_retention_values(self):
        from proxy_app import DEFAULT_RETENTION_REQUESTS_DAYS, DEFAULT_RETENTION_INCIDENTS_DAYS
        assert DEFAULT_RETENTION_REQUESTS_DAYS == 30
        assert DEFAULT_RETENTION_INCIDENTS_DAYS == 90
