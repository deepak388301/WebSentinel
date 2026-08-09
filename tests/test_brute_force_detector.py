from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from database.models import db, LoginAttempt
from detectors import brute_force
from proxy_app import create_app


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _reset_db(app):
    with app.app_context():
        LoginAttempt.query.delete()
        db.session.commit()


def test_login_endpoint_detection():
    assert brute_force._is_login_endpoint("/login") is True
    assert brute_force._is_login_endpoint("/api/v1/auth") is True
    assert brute_force._is_login_endpoint("/admin/login") is True
    assert brute_force._is_login_endpoint("/signin") is True


def test_non_login_endpoint():
    assert brute_force._is_login_endpoint("/about") is False
    assert brute_force._is_login_endpoint("/api/users") is False
    assert brute_force._is_login_endpoint("/") is False


def test_detect_returns_none_for_non_login_endpoint():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        data = {"url": "/api/users", "ip": "10.0.0.1", "status_code": 401}
        result = brute_force.detect(data)
        assert result is None


def test_detect_returns_none_for_success_status():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        data = {"url": "/login", "ip": "10.0.0.1", "status_code": 200}
        result = brute_force.detect(data)
        assert result is None


def test_detect_returns_none_below_threshold():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        for i in range(brute_force.FAILURE_THRESHOLD - 1):
            data = {"url": "/login", "ip": "10.0.0.1", "status_code": 401}
            result = brute_force.detect(data)
            assert result is None


def test_detect_returns_finding_at_threshold():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        for i in range(brute_force.FAILURE_THRESHOLD):
            data = {"url": "/login", "ip": "10.0.0.1", "status_code": 403}
            result = brute_force.detect(data)
        assert result is not None
        assert result["attack_type"] == "Brute Force"
        assert result["confidence"] == "Very High"
        assert result["mitre_technique"] == "T1110"
        assert "10.0.0.1" in result["evidence"]


def test_detect_tracks_multiple_ips_independently():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        for i in range(brute_force.FAILURE_THRESHOLD):
            brute_force.detect({"url": "/login", "ip": "10.0.0.1", "status_code": 401})

        result = brute_force.detect({"url": "/login", "ip": "10.0.0.2", "status_code": 401})
        assert result is None


def test_should_preblock_below_threshold():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        for i in range(brute_force.FAILURE_THRESHOLD - 1):
            brute_force.detect({"url": "/login", "ip": "10.0.0.1", "status_code": 401})
        assert brute_force.should_preblock("/login", "10.0.0.1") is False


def test_should_preblock_at_threshold():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        for i in range(brute_force.FAILURE_THRESHOLD):
            brute_force.detect({"url": "/login", "ip": "10.0.0.1", "status_code": 401})
        assert brute_force.should_preblock("/login", "10.0.0.1") is True


def test_should_preblock_non_login_endpoint():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        assert brute_force.should_preblock("/api/data", "10.0.0.1") is False


def test_rolling_window_expiry():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        now = datetime.now(timezone.utc)
        for i in range(brute_force.FAILURE_THRESHOLD):
            attempt = LoginAttempt(
                ip="10.0.0.1", url="/login",
                timestamp=now - timedelta(seconds=brute_force.TIME_WINDOW_SECONDS + 10),
            )
            db.session.add(attempt)
        db.session.commit()

        result = brute_force.should_preblock("/login", "10.0.0.1")
        assert result is False


def test_missing_fields_handled():
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        data = {}
        result = brute_force.detect(data)
        assert result is None

        result = brute_force.should_preblock("", "unknown")
        assert result is False


def test_shared_across_connections():
    """Simulates two separate 'processes' by using different DB sessions.
    The old in-memory version could NOT share counts across processes."""
    app = _make_app()
    _reset_db(app)
    with app.app_context():
        for i in range(brute_force.FAILURE_THRESHOLD):
            brute_force.detect({"url": "/login", "ip": "10.0.0.1", "status_code": 401})

        assert brute_force._count_recent("10.0.0.1") == brute_force.FAILURE_THRESHOLD
        assert brute_force.should_preblock("/login", "10.0.0.1") is True


# ---------- Configurable status codes ----------

def test_configurable_status_codes_includes_429():
    """Status code 429 (rate limit) should count as a failure when configured."""
    import os
    os.environ["WEBSENTINEL_BRUTE_FORCE_STATUS_CODES"] = "401,403,429"
    try:
        app = _make_app()
        _reset_db(app)
        with app.app_context():
            for i in range(brute_force.FAILURE_THRESHOLD):
                result = brute_force.detect({"url": "/login", "ip": "10.0.0.2", "status_code": 429})
            assert result is not None
            assert result["attack_type"] == "Brute Force"
    finally:
        os.environ.pop("WEBSENTINEL_BRUTE_FORCE_STATUS_CODES", None)


def test_configurable_status_codes_excludes_401():
    """When 401 is removed from config, it should not count as a failure."""
    import os
    os.environ["WEBSENTINEL_BRUTE_FORCE_STATUS_CODES"] = "403"
    try:
        app = _make_app()
        _reset_db(app)
        with app.app_context():
            for i in range(brute_force.FAILURE_THRESHOLD):
                result = brute_force.detect({"url": "/login", "ip": "10.0.0.3", "status_code": 401})
            assert result is None  # 401 not in configured codes
    finally:
        os.environ.pop("WEBSENTINEL_BRUTE_FORCE_STATUS_CODES", None)


# ---------- Configurable login paths ----------

def test_configurable_login_paths_custom():
    """Custom login paths should be recognized."""
    import os
    os.environ["WEBSENTINEL_BRUTE_FORCE_LOGIN_PATHS"] = "check-creds,verify-user"
    try:
        assert brute_force._is_login_endpoint("/check-creds") is True
        assert brute_force._is_login_endpoint("/verify-user") is True
        assert brute_force._is_login_endpoint("/login") is False  # removed from defaults
    finally:
        os.environ.pop("WEBSENTINEL_BRUTE_FORCE_LOGIN_PATHS", None)


def test_default_login_paths():
    """Default paths should work when env var is not set."""
    import os
    os.environ.pop("WEBSENTINEL_BRUTE_FORCE_LOGIN_PATHS", None)
    assert brute_force._is_login_endpoint("/login") is True
    assert brute_force._is_login_endpoint("/signin") is True
    assert brute_force._is_login_endpoint("/auth") is True
    assert brute_force._is_login_endpoint("/admin") is True
    assert brute_force._is_login_endpoint("/about") is False
