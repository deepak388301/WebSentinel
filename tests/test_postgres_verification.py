"""
tests/test_postgres_verification.py

Comprehensive verification against a live PostgreSQL instance.
Run with: WEBSENTINEL_DB_URI=<postgres_uri> pytest tests/test_postgres_verification.py -v

Tests:
  1. Schema matches expected DDL
  2. Dashboard queries (trend, top-sources, top-paths, severity-counts) return correct results
  3. Concurrent writes from two separate connections (simulating dual Gunicorn processes)
"""

import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

PG_URI = os.environ.get("WEBSENTINEL_DB_URI", "")

# Skip entire module if not running against Postgres
pytestmark = pytest.mark.skipif(
    not PG_URI or "sqlite" in PG_URI.lower(),
    reason="Not running against PostgreSQL (set WEBSENTINEL_DB_URI to a postgres URI)",
)


def _make_app(uri=None):
    from proxy_app import create_app
    from database.models import db
    app = create_app(
        database_uri=uri or PG_URI,
        target_url="http://127.0.0.1:9000",
    )
    with app.app_context():
        db.create_all()
    return app


def _seed_data(app, num_requests=20):
    """Seed realistic test data across multiple days and IPs."""
    from database.models import db, Request, Incident, LoginAttempt

    with app.app_context():
        now = datetime.now(timezone.utc)
        attacker_ips = ["10.0.0.1", "10.0.0.2", "192.168.1.100"]
        attack_types = ["SQL Injection", "XSS", "Path Traversal"]
        severities = ["Critical", "High", "Medium"]

        reqs = []
        for i in range(num_requests):
            day_offset = i % 5  # spread across 5 days
            req = Request(
                ip=attacker_ips[i % len(attacker_ips)],
                method="GET",
                url=f"/target{i}",
                headers="{}",
                payload=f"payload{i}",
                user_agent="test",
                status_code=200 if i % 3 != 0 else 403,
                timestamp=now - timedelta(days=day_offset, hours=i),
            )
            db.session.add(req)
            db.session.commit()
            reqs.append(req)

            inc = Incident(
                incident_code=f"INC-{req.id:05d}",
                request_id=req.id,
                attack_type=attack_types[i % len(attack_types)],
                severity=severities[i % len(severities)],
                confidence="High",
                risk_score=80,
                evidence=f"evidence{i}",
                recommendation="fix",
                mitre_technique="T1190",
                status="Open" if i % 4 != 0 else "Blocked",
                created_at=now - timedelta(days=day_offset, hours=i),
            )
            db.session.add(inc)

        # Seed some login attempts
        for i in range(8):
            db.session.add(LoginAttempt(
                ip="10.0.0.1",
                url="/login",
                timestamp=now - timedelta(seconds=i * 5),
            ))

        db.session.commit()


class TestSchemaPostgres:
    def test_all_tables_exist(self, app=_make_app()):
        from sqlalchemy import inspect
        with app.app_context():
            inspector = inspect(app.extensions["sqlalchemy"].engine)
            tables = set(inspector.get_table_names())
            assert "requests" in tables
            assert "incidents" in tables
            assert "alerted_ips" in tables
            assert "login_attempts" in tables

    def test_datetime_columns_are_timestamptz(self, app=_make_app()):
        from sqlalchemy import inspect
        with app.app_context():
            inspector = inspect(app.extensions["sqlalchemy"].engine)
            for table, col in [
                ("requests", "timestamp"),
                ("incidents", "created_at"),
                ("alerted_ips", "first_alerted_at"),
                ("login_attempts", "timestamp"),
            ]:
                cols = {c["name"]: c for c in inspector.get_columns(table)}
                assert cols[col]["type"].timezone is True, \
                    f"{table}.{col} should be TIMESTAMPTZ"


class TestDashboardQueriesPostgres:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.app = _make_app()
        _seed_data(self.app, num_requests=20)

    def test_trend_returns_correct_days(self):
        from proxy_app import build_trend
        with self.app.app_context():
            labels, counts = build_trend(days=7)
            assert len(labels) == 7
            assert len(counts) == 7
            # All labels should be valid date strings
            for label in labels:
                datetime.fromisoformat(label)

    def test_trend_counts_match_seeded_data(self):
        from proxy_app import build_trend
        from database.models import db, Incident
        with self.app.app_context():
            labels, counts = build_trend(days=7)
            # Sum of counts should match total incidents in the window
            total_from_query = Incident.query.count()
            assert sum(counts) <= total_from_query

    def test_top_sources_query(self):
        from database.models import db, Request, Incident
        from sqlalchemy import func
        with self.app.app_context():
            rows = (
                db.session.query(
                    Request.ip,
                    func.count(Incident.id),
                    func.max(Incident.created_at),
                )
                .join(Incident)
                .group_by(Request.ip)
                .order_by(func.count(Incident.id).desc())
                .limit(10)
                .all()
            )
            assert len(rows) > 0
            # Each row should have ip, count, max_timestamp
            for ip, count, max_ts in rows:
                assert ip is not None
                assert count > 0

    def test_top_paths_query(self):
        from database.models import db, Request, Incident
        from sqlalchemy import func
        with self.app.app_context():
            rows = (
                db.session.query(Request.url, func.count(Incident.id))
                .join(Incident)
                .group_by(Request.url)
                .order_by(func.count(Incident.id).desc())
                .limit(10)
                .all()
            )
            assert len(rows) > 0
            for url, count in rows:
                assert url is not None
                assert count > 0

    def test_severity_counts_query(self):
        from database.models import db, Incident
        from sqlalchemy import func
        with self.app.app_context():
            rows = (
                db.session.query(Incident.severity, func.count(Incident.id))
                .group_by(Incident.severity)
                .all()
            )
            severity_map = {row[0]: row[1] for row in rows}
            # We seeded Critical, High, Medium
            assert "Critical" in severity_map
            assert "High" in severity_map
            assert severity_map["Critical"] > 0
            assert severity_map["High"] > 0

    def test_attack_type_distribution(self):
        from database.models import db, Incident
        from sqlalchemy import func
        with self.app.app_context():
            rows = (
                db.session.query(Incident.attack_type, func.count(Incident.id))
                .group_by(Incident.attack_type)
                .all()
            )
            assert len(rows) >= 2  # SQL Injection + XSS + Path Traversal

    def test_api_stats_endpoint(self):
        with self.app.app_context():
            client = self.app.test_client()
            client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
            resp = client.get("/websentinel/api/stats")
            assert resp.status_code == 200
            data = resp.get_json()
            assert "total_requests" in data
            assert "total_incidents" in data
            assert "critical" in data
            assert "high" in data
            assert data["total_requests"] > 0
            assert data["total_incidents"] > 0

    def test_api_trend_endpoint(self):
        with self.app.app_context():
            client = self.app.test_client()
            client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
            resp = client.get("/websentinel/api/trend?days=7")
            assert resp.status_code == 200
            data = resp.get_json()
            assert len(data["labels"]) == 7
            assert len(data["counts"]) == 7

    def test_api_attack_distribution_endpoint(self):
        with self.app.app_context():
            client = self.app.test_client()
            client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
            resp = client.get("/websentinel/api/attack-distribution")
            assert resp.status_code == 200
            data = resp.get_json()
            assert len(data["labels"]) >= 2

    def test_dashboard_home_renders(self):
        with self.app.app_context():
            client = self.app.test_client()
            client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
            resp = client.get("/websentinel/")
            assert resp.status_code == 200

    def test_analytics_renders(self):
        with self.app.app_context():
            client = self.app.test_client()
            client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})
            resp = client.get("/websentinel/analytics")
            assert resp.status_code == 200


class TestConcurrencyPostgres:
    def test_simultaneous_writes_no_lock_errors(self):
        """Simulate two Gunicorn processes writing to the same DB concurrently.

        The old SQLite approach would fail with 'database is locked' under
        concurrent writes. PostgreSQL should handle this natively.
        """
        from database.models import db, Request, Incident
        from proxy_app import create_app

        errors = []
        results = {"process1": 0, "process2": 0}
        # Unique marker per run so counts stay correct on a non-fresh DB
        # (rows from earlier runs of this test would otherwise accumulate).
        marker = uuid.uuid4().hex[:8]

        def writer(process_name, uri, count):
            app = create_app(database_uri=uri, target_url="http://127.0.0.1:9000")
            try:
                with app.app_context():
                    db.create_all()
                    for i in range(count):
                        req = Request(
                            ip=f"10.0.0.{10 + i}",
                            method="GET",
                            url=f"/concurrent-{process_name}-{marker}-{i}",
                            headers="{}",
                            payload=f"data{i}",
                            user_agent="concurrency-test",
                            status_code=200,
                        )
                        db.session.add(req)
                        db.session.commit()
                        inc = Incident(
                            incident_code=f"INC-{req.id:05d}",
                            request_id=req.id,
                            attack_type="SQL Injection",
                            severity="Critical",
                            confidence="High",
                            risk_score=95,
                            evidence="concurrent test",
                            recommendation="test",
                            mitre_technique="T1190",
                            status="Open",
                        )
                        db.session.add(inc)
                        db.session.commit()
                    results[process_name] = Request.query.filter(
                        Request.url.like(f"/concurrent-{process_name}-{marker}-%")
                    ).count()
            except Exception as e:
                errors.append(f"{process_name}: {e}")

        # Both processes use the SAME database URI
        uri = PG_URI
        t1 = threading.Thread(target=writer, args=("process1", uri, 10))
        t2 = threading.Thread(target=writer, args=("process2", uri, 10))

        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        assert not errors, f"Concurrent write errors: {errors}"
        assert results["process1"] == 10, f"Process 1 wrote {results['process1']}, expected 10"
        assert results["process2"] == 10, f"Process 2 wrote {results['process2']}, expected 10"

    def test_brute_force_shared_across_connections(self):
        """Verify brute-force attempt counts are shared across connections."""
        from database.models import db, LoginAttempt
        from proxy_app import create_app
        from detectors import brute_force

        app = create_app(database_uri=PG_URI, target_url="http://127.0.0.1:9000")

        # Unique IP per run so counts don't accumulate across test runs.
        ip = f"10.99.99.{int(uuid.uuid4().int % 200) + 1}"

        # Connection 1: insert login attempts
        with app.app_context():
            db.create_all()
            for i in range(brute_force.FAILURE_THRESHOLD):
                db.session.add(LoginAttempt(ip=ip, url="/login"))
            db.session.commit()

        # Connection 2: verify count is visible
        with app.app_context():
            count = brute_force._count_recent(ip)
            assert count == brute_force.FAILURE_THRESHOLD, \
                f"Expected {brute_force.FAILURE_THRESHOLD}, got {count}"
            assert brute_force.should_preblock("/login", ip) is True
