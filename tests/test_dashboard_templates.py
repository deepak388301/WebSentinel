import os
from unittest.mock import patch, MagicMock
from database.models import db, Request, Incident
from proxy_app import create_app

# ---------- existing dashboard tests ----------
def test_dashboard_routes_render_templates():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    with app.app_context():
        sample_request = Request(
            ip="192.0.2.1",
            method="GET",
            url="/login",
            headers='{"User-Agent": "pytest"}',
            payload="username=admin",
            user_agent="pytest",
            status_code=200,
        )
        db.session.add(sample_request)
        db.session.commit()

        sample_incident = Incident(
            incident_code=f"INC-{sample_request.id:05d}",
            request_id=sample_request.id,
            attack_type="XSS",
            severity="High",
            confidence="Medium",
            risk_score=75,
            evidence="<script> found in query string",
            recommendation="Sanitize output and use CSP.",
            mitre_technique="T1059",
            status="Open",
        )
        db.session.add(sample_incident)
        db.session.commit()

    client = app.test_client()
    client.post("/websentinel/login", data={"username": "testadmin", "password": "testpass123"})

    home_resp = client.get('/websentinel/')
    assert home_resp.status_code == 200
    assert b'Overview' in home_resp.data
    assert b'Protecting:' in home_resp.data

    live_resp = client.get('/websentinel/live-monitor')
    assert live_resp.status_code == 200
    assert b'Live Monitor' in live_resp.data
    assert b'/login' in live_resp.data

    incidents_resp = client.get('/websentinel/incidents')
    assert incidents_resp.status_code == 200
    assert b'Incidents' in incidents_resp.data
    assert b'XSS' in incidents_resp.data

    analytics_resp = client.get('/websentinel/analytics')
    assert analytics_resp.status_code == 200
    assert b'Attack Distribution' in analytics_resp.data

    api_resp = client.get('/websentinel/api/attack-distribution')
    assert api_resp.status_code == 200
    assert api_resp.is_json
    payload = api_resp.get_json()
    assert payload["labels"] == ["XSS"]
    assert payload["counts"] == [1]

# ---------- new test: brute‑force blocking ----------
def test_brute_force_blocking():
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://dummy")
    with app.app_context():
        db.create_all()
    client = app.test_client()

    with patch('requests.request') as mock_request:
        # Mock response for a failed login (401)
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.content = b"Unauthorized"
        mock_response.headers = {}
        mock_request.return_value = mock_response

        # First 5 attempts → upstream returns 401 → counted as failures
        for _ in range(5):
            resp = client.post("/login", data={"username": "user", "password": "wrong"},
                               environ_base={"REMOTE_ADDR": "127.0.0.1"})
            # The proxy forwards and returns the upstream's status (401)
            assert resp.status_code == 401

        # 6th attempt → should be blocked (403) before any forward
        resp = client.post("/login", data={"username": "user", "password": "wrong"},
                           environ_base={"REMOTE_ADDR": "127.0.0.1"})
        assert resp.status_code == 403
        assert b"blocked" in resp.data.lower() or b"brute" in resp.data.lower()