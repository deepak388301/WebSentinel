from datetime import datetime, timezone
from database.models import db, Request, Incident
from proxy_app import create_app


def _make_app():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def test_request_model_create_and_read():
    app = _make_app()
    with app.app_context():
        req = Request(
            ip="192.168.1.1", method="POST", url="/login",
            headers='{"Content-Type": "application/x-www-form-urlencoded"}',
            payload="username=admin&password=wrong",
            user_agent="Mozilla/5.0", status_code=401,
        )
        db.session.add(req)
        db.session.commit()
        assert req.id is not None
        loaded = db.session.get(Request, req.id)
        assert loaded.ip == "192.168.1.1"
        assert loaded.method == "POST"
        assert loaded.url == "/login"
        assert loaded.status_code == 401


def test_request_timestamp_is_timezone_aware():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/", headers="{}",
                       payload="", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        assert req.timestamp is not None
        assert isinstance(req.timestamp, datetime)


def test_incident_model_create_and_read():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/search",
                       headers="{}", payload="test", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}", request_id=req.id,
            attack_type="XSS", severity="High", confidence="Medium",
            risk_score=75, evidence="script tag", recommendation="Use CSP",
            mitre_technique="T1059.007", status="Open",
        )
        db.session.add(inc)
        db.session.commit()
        loaded = db.session.get(Incident, inc.id)
        assert loaded.incident_code == "INC-00001"
        assert loaded.attack_type == "XSS"
        assert loaded.severity == "High"
        assert loaded.status == "Open"


def test_incident_timestamp_is_timezone_aware():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/", headers="{}",
                       payload="", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}", request_id=req.id,
            attack_type="Test", severity="Low", confidence="Low",
            risk_score=10, evidence="test", recommendation="test",
            mitre_technique="T0000", status="Open",
        )
        db.session.add(inc)
        db.session.commit()
        assert inc.created_at is not None
        assert isinstance(inc.created_at, datetime)


def test_request_incident_relationship():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/test",
                       headers="{}", payload="test", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}", request_id=req.id,
            attack_type="Test", severity="Low", confidence="Low",
            risk_score=10, evidence="test", recommendation="test",
            mitre_technique="T0000", status="Open",
        )
        db.session.add(inc)
        db.session.commit()
        assert inc in req.incidents
        assert inc.request is req


def test_request_to_dict_method():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/test",
                       headers="{}", payload="", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        d = req.to_dict()
        assert d["ip"] == "10.0.0.1"
        assert d["method"] == "GET"
        assert "timestamp" in d


def test_incident_to_dict_method():
    app = _make_app()
    with app.app_context():
        req = Request(ip="10.0.0.1", method="GET", url="/test",
                       headers="{}", payload="", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}", request_id=req.id,
            attack_type="SQL Injection", severity="Critical", confidence="High",
            risk_score=95, evidence="tautology", recommendation="Use parameterized queries",
            mitre_technique="T1190", status="Blocked",
        )
        db.session.add(inc)
        db.session.commit()
        d = inc.to_dict()
        assert d["incident_code"] == "INC-00001"
        assert d["attack_type"] == "SQL Injection"
        assert d["status"] == "Blocked"
        assert "created_at" in d
