import os
from base64 import urlsafe_b64decode
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from unittest.mock import patch, MagicMock

import pytest

from database.models import db, Request, Incident, AlertedIP
from proxy_app import create_app
from utils.alerting import (
    should_alert, maybe_alert, GMAIL_SCOPES, alerting_issue, authorize,
)
import utils.alerting as alerting_mod


def _make_app():
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "true"
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = "alerts@example.com"
    os.environ["WEBSENTINEL_ALERT_COOLDOWN_MINUTES"] = "60"
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    return app


def _mock_gmail_service():
    """Patch target: a service whose users().messages().send(...).execute()
    succeeds. Returns (service, context_manager) for `with patch(...)`."""
    service = MagicMock()
    send = service.users.return_value.messages.return_value.send
    send.return_value.execute.return_value = {"id": "msg123"}
    return service


def _capture_sent_message(service):
    """Return (subject, body) of the last message the mock service received."""
    send = service.users.return_value.messages.return_value.send
    raw = send.call_args.kwargs["body"]["raw"]
    parsed = message_from_bytes(urlsafe_b64decode(raw.encode()))
    subject = "".join(
        part.decode() if isinstance(part, bytes) else part
        for part, _ in decode_header(parsed["Subject"])
    )
    return subject, parsed.get_payload()


# ---- Gmail OAuth credential handling ----

def test_first_run_runs_oauth_flow_and_saves_token(tmp_path, monkeypatch):
    cred_file = tmp_path / "credentials.json"
    cred_file.write_text('{"installed": {}}')
    token_file = tmp_path / "token.json"
    monkeypatch.setattr(alerting_mod, "CREDENTIALS_FILE", str(cred_file))
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", str(token_file))

    fake_creds = MagicMock()
    fake_creds.to_json.return_value = '{"token": "first-run"}'
    # token.json missing (needs OAuth), credentials.json present (can start it)
    with patch("os.path.exists", side_effect=lambda p: p == str(cred_file)), \
            patch.object(alerting_mod, "InstalledAppFlow") as mock_flow:
        mock_flow.from_client_secrets_file.return_value.run_local_server.return_value = fake_creds
        creds = alerting_mod._gmail_credentials()

    assert creds is fake_creds
    mock_flow.from_client_secrets_file.assert_called_once_with(str(cred_file), GMAIL_SCOPES)
    assert token_file.read_text() == '{"token": "first-run"}'


def test_expired_token_is_refreshed_and_saved(tmp_path, monkeypatch):
    token_file = tmp_path / "token.json"
    token_file.write_text("{}")
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", str(token_file))

    creds = MagicMock()
    creds.valid = False
    creds.expired = True
    creds.refresh_token = "refresh-token"
    creds.to_json.return_value = '{"token": "refreshed"}'
    with patch("os.path.exists", return_value=True), \
            patch.object(alerting_mod, "Credentials") as mock_creds_cls, \
            patch.object(alerting_mod, "Request"):
        mock_creds_cls.from_authorized_user_file.return_value = creds
        result = alerting_mod._gmail_credentials()

    assert result is creds
    creds.refresh.assert_called_once()
    assert token_file.read_text() == '{"token": "refreshed"}'


# ---- Clear errors when OAuth cannot start ----

def test_missing_credentials_file_raises_clear_error(monkeypatch):
    """Without credentials.json the error must explain what to do, not a raw
    FileNotFoundError that gets silently swallowed."""
    monkeypatch.setattr(alerting_mod, "CREDENTIALS_FILE", "/nonexistent/credentials.json")
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", "/nonexistent/token.json")
    with patch("os.path.exists", return_value=False):
        with pytest.raises(RuntimeError) as exc:
            alerting_mod._gmail_credentials()
    message = str(exc.value)
    assert "credentials.json" in message
    assert "authorize" in message


def test_authorize_command_prints_token_path(tmp_path, monkeypatch, capsys):
    (tmp_path / "credentials.json").write_text("{}")
    monkeypatch.setattr(alerting_mod, "CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", str(tmp_path / "token.json"))
    with patch.object(alerting_mod, "_gmail_credentials", return_value=MagicMock()):
        authorize()
    out = capsys.readouterr().out
    assert "Authorized" in out
    assert str(tmp_path / "token.json") in out


# ---- Dashboard guidance (alerting_issue) ----

def test_alerting_issue_when_disabled_returns_empty(monkeypatch):
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "false"
    assert alerting_issue() == ""


def test_alerting_issue_when_no_email_configured(monkeypatch):
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "true"
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = ""
    assert "no email address" in alerting_issue()


def test_alerting_issue_when_credentials_missing(tmp_path, monkeypatch):
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "true"
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = "test@gmail.com"
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", str(tmp_path / "token.json"))
    monkeypatch.setattr(alerting_mod, "CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    assert "credentials.json not found" in alerting_issue()


def test_alerting_issue_when_unauthorized(tmp_path, monkeypatch):
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "true"
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = "test@gmail.com"
    (tmp_path / "credentials.json").write_text("{}")
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", str(tmp_path / "token.json"))
    monkeypatch.setattr(alerting_mod, "CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    assert "authorize" in alerting_issue()


def test_alerting_issue_when_ready(tmp_path, monkeypatch):
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "true"
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = "test@gmail.com"
    (tmp_path / "token.json").write_text("{}")
    monkeypatch.setattr(alerting_mod, "TOKEN_FILE", str(tmp_path / "token.json"))
    monkeypatch.setattr(alerting_mod, "CREDENTIALS_FILE", str(tmp_path / "credentials.json"))
    assert alerting_issue() == ""


def _create_incident_id(app, ip="10.0.0.1", severity="Critical"):
    with app.app_context():
        req = Request(ip=ip, method="GET", url="/test",
                       headers="{}", payload="test", user_agent="test", status_code=200)
        db.session.add(req)
        db.session.commit()
        inc = Incident(
            incident_code=f"INC-{req.id:05d}", request_id=req.id,
            attack_type="SQL Injection", severity=severity, confidence="High",
            risk_score=95, evidence="payload", recommendation="fix it",
            mitre_technique="T1190", status="Blocked",
        )
        db.session.add(inc)
        db.session.commit()
        return inc.id


# ---- Scenario 1: first Critical from new IP -> email sent ----

def test_first_critical_email_sent():
    app = _make_app()
    inc_id = _create_incident_id(app)
    service = _mock_gmail_service()
    with app.app_context():
        inc = Incident.query.get(inc_id)
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            service.users.return_value.messages.return_value.send.assert_called_once()
            assert AlertedIP.query.filter_by(ip="10.0.0.1").count() == 1


# ---- Scenario 2: second Critical from same IP within cooldown -> no email ----

def test_second_critical_within_cooldown_no_email():
    app = _make_app()
    inc1_id = _create_incident_id(app, severity="Critical")
    with app.app_context():
        inc1 = Incident.query.get(inc1_id)
        with patch("utils.alerting._gmail_service", return_value=_mock_gmail_service()):
            maybe_alert(inc1)

    inc2_id = _create_incident_id(app, severity="Critical")
    with app.app_context():
        inc2 = Incident.query.get(inc2_id)
        service = _mock_gmail_service()
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc2)
            service.users.return_value.messages.return_value.send.assert_not_called()


# ---- Scenario 3: same IP after cooldown expires -> email sent again ----

def test_incident_after_cooldown_sends_email():
    app = _make_app()
    inc1_id = _create_incident_id(app, severity="Critical")
    with app.app_context():
        inc1 = Incident.query.get(inc1_id)
        with patch("utils.alerting._gmail_service", return_value=_mock_gmail_service()):
            maybe_alert(inc1)

    with app.app_context():
        record = AlertedIP.query.filter_by(ip="10.0.0.1").first()
        record.first_alerted_at = datetime.now(timezone.utc) - timedelta(minutes=61)
        db.session.commit()

    inc2_id = _create_incident_id(app, severity="Critical")
    with app.app_context():
        inc2 = Incident.query.get(inc2_id)
        service = _mock_gmail_service()
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc2)
            service.users.return_value.messages.return_value.send.assert_called_once()


# ---- Scenario 4: Medium/Low severity -> never trigger ----

def test_medium_severity_no_alert():
    app = _make_app()
    inc_id = _create_incident_id(app, severity="Medium")
    with app.app_context():
        inc = Incident.query.get(inc_id)
        service = _mock_gmail_service()
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            service.users.return_value.messages.return_value.send.assert_not_called()
            assert AlertedIP.query.count() == 0


def test_low_severity_no_alert():
    app = _make_app()
    inc_id = _create_incident_id(app, severity="Low")
    with app.app_context():
        inc = Incident.query.get(inc_id)
        service = _mock_gmail_service()
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            service.users.return_value.messages.return_value.send.assert_not_called()
            assert AlertedIP.query.count() == 0


# ---- Scenario 5: WEBSENTINEL_ALERT_ENABLED=false -> no-op ----

def test_alerting_disabled_no_op():
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "false"
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    inc_id = _create_incident_id(app, severity="Critical")
    with app.app_context():
        inc = Incident.query.get(inc_id)
        service = _mock_gmail_service()
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            service.users.return_value.messages.return_value.send.assert_not_called()
            assert AlertedIP.query.count() == 0
    os.environ["WEBSENTINEL_ALERT_ENABLED"] = "true"


# ---- Scenario 6: no alert email configured -> silent no-op ----

def test_no_alert_email_configured_is_silent():
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = ""
    app = create_app(database_uri="sqlite:///:memory:", target_url="http://127.0.0.1:9000")
    with app.app_context():
        db.create_all()
    inc_id = _create_incident_id(app, severity="Critical")
    with app.app_context():
        inc = Incident.query.get(inc_id)
        service = _mock_gmail_service()
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            service.users.return_value.messages.return_value.send.assert_not_called()
            assert AlertedIP.query.count() == 0
    os.environ["WEBSENTINEL_ALERT_EMAIL"] = "alerts@example.com"


# ---- Scenario 7: Gmail API failure -> doesn't crash, incident persists ----

def test_gmail_failure_does_not_crash():
    app = _make_app()
    inc_id = _create_incident_id(app, severity="Critical")
    service = _mock_gmail_service()
    service.users.return_value.messages.return_value.send.return_value.execute.side_effect = \
        ConnectionError("Gmail down")
    with app.app_context():
        inc = Incident.query.get(inc_id)
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            assert Incident.query.filter_by(id=inc.id).count() == 1
            assert AlertedIP.query.filter_by(ip="10.0.0.1").count() == 0


def test_gmail_failure_does_not_break_proxied_request():
    """An API error inside maybe_alert() must not fail the proxied request:
    it still returns 403, the incident is persisted, and the failure is logged."""
    app = _make_app()
    client = app.test_client()
    service = _mock_gmail_service()
    service.users.return_value.messages.return_value.send.return_value.execute.side_effect = \
        ConnectionError("Gmail down")
    with patch("utils.alerting._gmail_service", return_value=service), \
            patch.object(alerting_mod.logger, "exception") as mock_log_exc:
        resp = client.get("/?id=1'+UNION+SELECT+username,password+FROM+users--")
        assert resp.status_code == 403
        mock_log_exc.assert_called_once()
        assert "Failed to send alert email" in mock_log_exc.call_args[0][0]
    with app.app_context():
        assert Incident.query.count() == 1
        assert AlertedIP.query.count() == 0


# ---- should_alert unit tests ----

def test_should_alert_new_ip():
    app = _make_app()
    with app.app_context():
        assert should_alert("192.168.1.1") is True


def test_should_alert_within_cooldown():
    app = _make_app()
    with app.app_context():
        record = AlertedIP(ip="192.168.1.2", incident_id=1,
                            first_alerted_at=datetime.now(timezone.utc))
        db.session.add(record)
        db.session.commit()
        assert should_alert("192.168.1.2") is False


def test_should_alert_after_cooldown():
    app = _make_app()
    with app.app_context():
        record = AlertedIP(ip="192.168.1.3", incident_id=1,
                            first_alerted_at=datetime.now(timezone.utc) - timedelta(minutes=61))
        db.session.add(record)
        db.session.commit()
        assert should_alert("192.168.1.3") is True


# ---- Email content verification ----

def test_email_subject_and_body():
    app = _make_app()
    inc_id = _create_incident_id(app, ip="10.99.99.99", severity="Critical")
    service = _mock_gmail_service()
    with app.app_context():
        inc = Incident.query.get(inc_id)
        with patch("utils.alerting._gmail_service", return_value=service):
            maybe_alert(inc)
            send = service.users.return_value.messages.return_value.send
            send.assert_called_once()
            assert send.call_args.kwargs["userId"] == "me"
            subject, body = _capture_sent_message(service)
            assert "WebSentinel" in subject
            assert "Critical" in subject
            assert "10.99.99.99" in subject
            assert "SQL Injection" in body
            assert "T1190" in body
            assert "10.99.99.99" in body
