"""
tests/test_blocking.py

Tests for blocking logic:
  - Single Very High confidence finding → blocked
  - Two or more independent detector hits → blocked
  - High/Medium confidence alone → NOT blocked
  - Suppression config: skips blocking for suppressed IPs/paths/attack types
"""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from database.models import db, Request, Incident
from proxy_app import create_app, _should_block, _is_suppressed
from utils.risk_engine import calculate_risk


def _make_app(suppression=None):
    """Create a test app with in-memory SQLite and tables created."""
    if suppression:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(suppression, f)
        os.environ["WEBSENTINEL_SUPPRESSION_FILE"] = path
    else:
        os.environ.pop("WEBSENTINEL_SUPPRESSION_FILE", None)
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


class TestVeryHighConfidenceBlocks:
    """Single finding with Very High confidence always blocks."""

    def test_sql_injection_union_select(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/?id=1'+UNION+SELECT+username,password+FROM+users--")
        assert resp.status_code == 403

    def test_xss_script_tag(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/search?q=<script>alert(1)</script>")
        assert resp.status_code == 403

    def test_traversal_deep_chain(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/view?file=../../../../../../etc/passwd")
        assert resp.status_code == 403

    def test_command_injection(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/api?cmd=; rm -rf /")
        assert resp.status_code == 403

    def test_ssrf_file_uri(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/fetch?url=file:///etc/passwd")
        assert resp.status_code == 403

    def test_nosql_where(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/api?filter=$where:1=1")
        assert resp.status_code == 403


class TestHighConfidenceAloneNotBlocked:
    """High confidence alone does NOT block (needs Very High or 2+ types)."""

    def test_sql_boolean_tautology_not_blocked_alone(self):
        app = _make_app()
        client = app.test_client()
        # OR 1=1 → High confidence (not Very High), single attack type
        resp = client.get("/?id=1'+OR+1=1--")
        # Only SQL comment (Medium) + boolean tautology (High) → same attack type
        # No Very High → no block
        assert resp.status_code != 403

    def test_sql_comment_not_blocked_alone(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/?q=--comment")
        assert resp.status_code != 403

    def test_xss_event_handler_not_blocked_alone(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/search?q=onclick=alert(1)")
        assert resp.status_code != 403

    def test_directory_enumeration_not_blocked_alone(self):
        app = _make_app()
        client = app.test_client()
        resp = client.get("/.env")
        assert resp.status_code != 403


class TestMultiDetectorConsensus:
    """2+ independent detector hits block."""

    def test_sql_plus_xss_triggers_block(self):
        app = _make_app()
        client = app.test_client()
        # Payload triggers both SQL Injection (boolean tautology) AND XSS (<script>)
        resp = client.get("/?id=1'+OR+1=1--&q=<script>alert(1)</script>")
        assert resp.status_code == 403

    def test_traversal_plus_ssrf_triggers_block(self):
        app = _make_app()
        client = app.test_client()
        # Path traversal + SSRF (localhost reference) = 2 attack types
        resp = client.get("/fetch?file=../../../etc/passwd&url=http://localhost/admin")
        assert resp.status_code == 403

    def test_single_attack_type_not_blocked(self):
        app = _make_app()
        client = app.test_client()
        # Multiple SQL patterns but same attack type = not blocked (no Very High)
        resp = client.get("/?id=1'+OR+1=1--+comment")
        assert resp.status_code != 403


class TestSuppressionConfig:
    """Suppression config exempts IPs, paths, and attack types from blocking."""

    def test_suppressed_ip_not_blocked(self):
        suppression = {"ips": ["10.0.0.1"], "paths": [], "attack_types": []}
        app = _make_app(suppression=suppression)
        client = app.test_client()
        resp = client.get(
            "/?id=1'+UNION+SELECT+*+FROM+users--",
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        )
        assert resp.status_code != 403

    def test_suppressed_path_not_blocked(self):
        suppression = {"ips": [], "paths": ["/health"], "attack_types": []}
        app = _make_app(suppression=suppression)
        client = app.test_client()
        resp = client.get("/health?id=1'+UNION+SELECT+*+FROM+users--")
        assert resp.status_code != 403

    def test_suppressed_attack_type_not_blocked(self):
        suppression = {"ips": [], "paths": [], "attack_types": ["Directory Enumeration"]}
        app = _make_app(suppression=suppression)
        client = app.test_client()
        # Directory Enumeration → Medium confidence, but suppressed
        resp = client.get("/.env")
        assert resp.status_code != 403

    def test_non_suppressed_ip_blocked(self):
        suppression = {"ips": ["99.99.99.99"], "paths": [], "attack_types": []}
        app = _make_app(suppression=suppression)
        client = app.test_client()
        resp = client.get(
            "/?id=1'+UNION+SELECT+*+FROM+users--",
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        )
        assert resp.status_code == 403

    def test_suppression_file_missing_uses_defaults(self):
        os.environ["WEBSENTINEL_SUPPRESSION_FILE"] = "/nonexistent/path.json"
        app = _make_app()
        client = app.test_client()
        resp = client.get("/?id=1'+UNION+SELECT+*+FROM+users--")
        assert resp.status_code == 403


class TestShouldBlockHelper:
    """Test the _should_block function directly."""

    def test_blocks_very_high(self):
        app = _make_app()
        with app.app_context():
            finding = calculate_risk({"attack_type": "SQL Injection", "confidence": "Very High", "evidence": "test"})
            data = {"ip": "10.0.0.1", "url": "/test"}
            assert _should_block(data, [finding], [finding]) is True

    def test_blocks_two_attack_types(self):
        app = _make_app()
        with app.app_context():
            f1 = calculate_risk({"attack_type": "SQL Injection", "confidence": "High", "evidence": "test"})
            f2 = calculate_risk({"attack_type": "Cross-Site Scripting (XSS)", "confidence": "High", "evidence": "test"})
            data = {"ip": "10.0.0.1", "url": "/test"}
            assert _should_block(data, [f1, f2], [f1, f2]) is True

    def test_no_block_high_only(self):
        app = _make_app()
        with app.app_context():
            finding = calculate_risk({"attack_type": "SQL Injection", "confidence": "High", "evidence": "test"})
            data = {"ip": "10.0.0.1", "url": "/test"}
            assert _should_block(data, [finding], [finding]) is False

    def test_no_block_empty_findings(self):
        app = _make_app()
        with app.app_context():
            data = {"ip": "10.0.0.1", "url": "/test"}
            assert _should_block(data, [], []) is False
