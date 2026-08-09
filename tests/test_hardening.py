"""Regression tests for the hardening fixes:

1. Logging — alembic's fileConfig must not disable app loggers.
2. Gzip — request bodies with Content-Encoding: gzip are decompressed & inspected.
3. HEAD / OPTIONS — proxied upstream instead of 405/auto-answer.
4. X-Forwarded-For — never trusted on input; rewritten with the real client IP.
5. Rate limiting — simple in-memory sliding window per IP (429).
6. MAX_CONTENT_LENGTH — oversized bodies rejected with 413.
"""

import gzip
import logging
import os
import time
from unittest.mock import patch, MagicMock

from database.models import db, Request, BlockedIP
from proxy_app import create_app
from utils.rate_limit import reset_rate_limits


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _mock_upstream(content=b"OK", status_code=200):
    """Patch proxy_app.upstream_requests with a canned 200 response."""
    mock_req = patch("proxy_app.upstream_requests").start()
    resp = MagicMock(status_code=status_code, content=content)
    resp.raw.headers = {}
    mock_req.request.return_value = resp
    return mock_req


# ---- 1. Logging ----

def test_migrations_do_not_disable_app_loggers():
    """fileConfig in migrations/env.py must not set websentinel loggers disabled."""
    _make_app()  # create_app() runs alembic's fileConfig via upgrade()
    logger = logging.getLogger("websentinel")
    assert logger.disabled is False

    records = []
    handler = logging.Handler()
    handler.emit = lambda record: records.append(record)
    logger.addHandler(handler)
    try:
        logger.warning("logging-fix-marker")
    finally:
        logger.removeHandler(handler)
    assert any(r.getMessage() == "logging-fix-marker" for r in records)


# ---- 2. Gzip ----

def test_gzip_benign_body_is_decompressed_and_forwarded():
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        body = gzip.compress(b"name=hello")
        resp = client.post(
            "/submit",
            data=body,
            headers={"Content-Encoding": "gzip"},
        )
        assert resp.status_code == 200
        kwargs = mock_req.request.call_args.kwargs
        assert kwargs["data"] == b"name=hello"  # decompressed before forwarding
        header_names = {k.lower() for k in kwargs["headers"]}
        assert "content-encoding" not in header_names
    finally:
        patch.stopall()


def test_gzip_attack_body_is_detected():
    """A gzip-encoded SQLi payload must still be seen by the detectors."""
    app = _make_app()
    client = app.test_client()
    body = gzip.compress(b"id=1' UNION SELECT * FROM users--")
    resp = client.post(
        "/search",
        data=body,
        headers={"Content-Encoding": "gzip"},
    )
    assert resp.status_code == 403


def test_corrupt_gzip_body_forwarded_as_is_with_encoding():
    """A body that fails to decompress is forwarded unchanged (with header)."""
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        resp = client.post(
            "/submit",
            data=b"not actually gzip",
            headers={"Content-Encoding": "gzip"},
        )
        assert resp.status_code == 200
        kwargs = mock_req.request.call_args.kwargs
        assert kwargs["data"] == b"not actually gzip"
        assert {k.lower(): v for k, v in kwargs["headers"].items()}.get("content-encoding") == "gzip"
    finally:
        patch.stopall()


# ---- 3. HEAD / OPTIONS ----

def test_head_request_is_proxied():
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream(content=b"")
    try:
        resp = client.open("/page", method="HEAD")
        assert resp.status_code == 200
        assert mock_req.request.call_args.kwargs["method"] == "HEAD"
    finally:
        patch.stopall()


def test_options_request_is_proxied():
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        resp = client.open("/page", method="OPTIONS")
        assert resp.status_code == 200
        assert mock_req.request.call_args.kwargs["method"] == "OPTIONS"
    finally:
        patch.stopall()


# ---- 4. X-Forwarded-For ----

def test_xff_header_is_ignored_and_overwritten():
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        resp = client.get(
            "/hello",
            headers={"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "203.0.113.9"},
        )
        assert resp.status_code == 200
        headers = {k.lower(): v for k, v in mock_req.request.call_args.kwargs["headers"].items()}
        assert headers["x-forwarded-for"] == "127.0.0.1"  # real peer, not spoofed
        assert headers["x-real-ip"] == "127.0.0.1"
    finally:
        patch.stopall()


def test_spoofed_xff_ip_is_not_persisted():
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        client.get("/hello", headers={"X-Forwarded-For": "203.0.113.9"})
        with app.app_context():
            stored = Request.query.filter_by(url="/hello").all()
            assert len(stored) == 1
            assert stored[0].ip == "127.0.0.1"
    finally:
        patch.stopall()


# ---- 5. Rate limiting ----

def _app_with_rate_limit(limit, window=60):
    os.environ["WEBSENTINEL_RATE_LIMIT"] = str(limit)
    os.environ["WEBSENTINEL_RATE_LIMIT_WINDOW"] = str(window)
    try:
        return _make_app()
    finally:
        os.environ["WEBSENTINEL_RATE_LIMIT"] = "0"


def test_rate_limiting_returns_429_after_limit():
    reset_rate_limits()
    app = _app_with_rate_limit(5)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        codes = [client.get("/r").status_code for _ in range(6)]
        assert codes[:5] == [200] * 5
        assert codes[5] == 429
    finally:
        patch.stopall()
        reset_rate_limits()


def test_429_includes_retry_after_header():
    reset_rate_limits()
    app = _app_with_rate_limit(1, window=30)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        client.get("/r")
        resp = client.get("/r")
        assert resp.status_code == 429
        retry_after = int(resp.headers["Retry-After"])
        assert 1 <= retry_after <= 30
    finally:
        patch.stopall()
        reset_rate_limits()


def test_rate_limiting_never_writes_to_blocklist():
    """A 429 is a temporary throttle — it must never auto-block the IP."""
    reset_rate_limits()
    app = _app_with_rate_limit(1)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        client.get("/a")
        for _ in range(10):
            assert client.get("/b").status_code == 429
        with app.app_context():
            assert BlockedIP.query.count() == 0
    finally:
        patch.stopall()
        reset_rate_limits()


def _app_with_trust_proxy(limit=100):
    os.environ["WEBSENTINEL_TRUST_PROXY"] = "true"
    try:
        return _app_with_rate_limit(limit)
    except Exception:
        os.environ.pop("WEBSENTINEL_TRUST_PROXY", None)
        raise


def _trust_proxy_test(limit):
    """Keep WEBSENTINEL_TRUST_PROXY set for the whole test; requests call
    get_client_ip() which reads the env var live."""
    reset_rate_limits()
    os.environ["WEBSENTINEL_TRUST_PROXY"] = "true"
    app = _app_with_rate_limit(limit)
    return app


def test_trusted_proxy_uses_right_most_xff():
    """With WEBSENTINEL_TRUST_PROXY=true the right-most XFF entry (appended
    by the trusted proxy) is used — a spoofed prefix on the left is ignored."""
    app = _trust_proxy_test(limit=100)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        resp = client.get(
            "/hello",
            headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
        )
        assert resp.status_code == 200
        with app.app_context():
            stored = Request.query.filter_by(url="/hello").first()
            assert stored is not None
            assert stored.ip == "10.0.0.1"
    finally:
        os.environ.pop("WEBSENTINEL_TRUST_PROXY", None)
        patch.stopall()
        reset_rate_limits()


def test_trusted_proxy_rate_limits_per_real_ip():
    """Two clients behind the proxy get independent buckets."""
    app = _trust_proxy_test(limit=2)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        for _ in range(2):
            assert client.get("/a", headers={"X-Forwarded-For": "10.0.0.1"}).status_code == 200
            assert client.get("/b", headers={"X-Forwarded-For": "10.0.0.2"}).status_code == 200
        assert client.get("/a", headers={"X-Forwarded-For": "10.0.0.1"}).status_code == 429
        assert client.get("/b", headers={"X-Forwarded-For": "10.0.0.2"}).status_code == 429
        assert client.get("/c", headers={"X-Forwarded-For": "10.0.0.3"}).status_code == 200
    finally:
        os.environ.pop("WEBSENTINEL_TRUST_PROXY", None)
        patch.stopall()
        reset_rate_limits()


def test_blocklist_takes_precedence_over_rate_limit():
    """A blocked IP gets 403 even under the rate limit — the two are
    independent (blocklist wins, rate limit is checked after)."""
    reset_rate_limits()
    app = _make_app()  # rate limiting off, blocklist active
    client = app.test_client()
    try:
        with app.app_context():
            db.session.add(BlockedIP(ip="127.0.0.1", reason="test", blocked_by="manual"))
            db.session.commit()
        for _ in range(5):
            assert client.get("/r").status_code == 403
    finally:
        reset_rate_limits()


def test_rate_limited_requests_are_not_persisted():
    reset_rate_limits()
    app = _app_with_rate_limit(1)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        assert client.get("/a").status_code == 200
        assert client.get("/b").status_code == 429
        with app.app_context():
            assert Request.query.count() == 1
    finally:
        patch.stopall()
        reset_rate_limits()


def test_rate_limit_window_resets():
    reset_rate_limits()
    app = _app_with_rate_limit(2, window=1)
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        assert client.get("/a").status_code == 200
        assert client.get("/b").status_code == 200
        assert client.get("/c").status_code == 429
        time.sleep(1.2)  # let the window elapse
        assert client.get("/d").status_code == 200
    finally:
        patch.stopall()
        reset_rate_limits()


# ---- 6. MAX_CONTENT_LENGTH ----

def test_oversized_request_rejected_with_413():
    app = _make_app()
    client = app.test_client()
    mock_req = _mock_upstream()
    try:
        resp = client.post("/big", data=b"x" * (2 * 1024 * 1024))
        assert resp.status_code == 413
        mock_req.request.assert_not_called()
    finally:
        patch.stopall()


def test_max_content_length_is_configurable():
    os.environ["WEBSENTINEL_MAX_BODY_SIZE"] = "64"
    try:
        app = _make_app()
        client = app.test_client()
        mock_req = _mock_upstream()
        try:
            resp = client.post("/small", data=b"y" * 100)
            assert resp.status_code == 413
            mock_req.request.assert_not_called()
        finally:
            patch.stopall()
    finally:
        os.environ.pop("WEBSENTINEL_MAX_BODY_SIZE", None)
