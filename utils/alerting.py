"""
utils/alerting.py

Alerting for Critical/High severity incidents via the Gmail API (OAuth).

No SMTP, no app passwords. Two simple pieces:
  1. credentials.json  — an OAuth client (type "Desktop app") downloaded
                         from Google Cloud Console.
  2. token.json        — created automatically on first use: the app opens
                         a browser, you sign in with the Gmail account that
                         should receive alerts, and the token is saved here
                         for reuse. Reuse the same token.json in Docker.

Configuration can be set via environment variables or from the dashboard
Settings page (stored in the Setting table). DB settings take precedence.

Design rule: only ONE notification per attacker IP per cooldown period.
A brute-force burst (dozens of Critical incidents from the same IP in
seconds) must never generate more than one alert for that IP.

Public API:
    maybe_alert(incident)   # decides whether to send, sends, records
"""

import base64
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from database.models import db, AlertedIP, Setting
from utils.reference_helpers import get_mitre_info, get_owasp_info

logger = logging.getLogger("websentinel.alerting")

# Only "send mail" is granted — the app can't read or modify the mailbox.
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Overridable via env so Docker can point at a mounted volume.
CREDENTIALS_FILE = os.environ.get("WEBSENTINEL_GOOGLE_CREDENTIALS", "credentials.json")
TOKEN_FILE = os.environ.get("WEBSENTINEL_GOOGLE_TOKEN", "token.json")


def _save_token(creds) -> None:
    with open(TOKEN_FILE, "w") as f:
        f.write(creds.to_json())


def _utcnow():
    return datetime.now(timezone.utc)


def _coerce_aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _setting_or_env(key: str, env_var: str, default: str = "") -> str:
    """Return the Setting table value if it exists and is non-empty,
    otherwise fall back to the environment variable."""
    try:
        setting = Setting.query.filter_by(key=key).first()
        if setting and setting.value:
            return setting.value
    except Exception:
        pass
    return os.environ.get(env_var, default)


def _is_enabled() -> bool:
    val = _setting_or_env("alert_enabled", "WEBSENTINEL_ALERT_ENABLED", "false")
    return val.lower() == "true"


def _cooldown_minutes() -> int:
    raw = _setting_or_env("alert_cooldown_minutes", "WEBSENTINEL_ALERT_COOLDOWN_MINUTES", "60")
    try:
        return max(1, int(raw))
    except (ValueError, TypeError):
        return 60


def _alert_email() -> str:
    return _setting_or_env("alert_email", "WEBSENTINEL_ALERT_EMAIL", "").strip()


def _dashboard_url() -> str:
    return os.environ.get("WEBSENTINEL_PUBLIC_URL", "http://localhost:8080").rstrip("/")


# ------------------------------------------------------------------
# Core helpers
# ------------------------------------------------------------------

def should_alert(ip: str) -> bool:
    record = AlertedIP.query.filter_by(ip=ip).first()
    if record is None:
        return True
    cooldown = timedelta(minutes=_cooldown_minutes())
    return _utcnow() - _coerce_aware(record.first_alerted_at) >= cooldown


def _record_alerted(incident) -> None:
    attacker_ip = incident.request.ip if incident.request else "unknown"
    existing = AlertedIP.query.filter_by(ip=attacker_ip).first()
    if existing:
        existing.first_alerted_at = _utcnow()
        existing.incident_id = incident.id
    else:
        db.session.add(AlertedIP(
            ip=attacker_ip,
            incident_id=incident.id,
            first_alerted_at=_utcnow(),
        ))
    db.session.commit()


# ------------------------------------------------------------------
# Gmail API
# ------------------------------------------------------------------

def _gmail_credentials():
    """Load token.json; refresh it if expired; otherwise run the
    first-time OAuth flow (opens a browser) and save the token.

    Raises a clear RuntimeError (not a raw FileNotFoundError) when the
    one-time login would be needed but credentials.json is missing, so a
    swallowed failure shows WHY nothing was sent.
    """
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, GMAIL_SCOPES)
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        _save_token(creds)
        return creds
    # First run: credentials.json must exist in the working directory.
    if not os.path.exists(CREDENTIALS_FILE):
        raise RuntimeError(
            f"Gmail alerting cannot start OAuth: {CREDENTIALS_FILE} not found. "
            "Create an OAuth client of type 'Desktop app' in Google Cloud Console "
            "(APIs & Services > Credentials), save it as "
            f"{os.path.abspath(CREDENTIALS_FILE)}, then run "
            "`python -m utils.alerting authorize`."
        )
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, GMAIL_SCOPES)
    creds = flow.run_local_server(port=0)
    _save_token(creds)
    return creds


def _gmail_service():
    return build("gmail", "v1", credentials=_gmail_credentials())


def _alert_body(incident) -> str:
    req = incident.request
    attacker_ip = req.ip if req else "unknown"
    mitre_info = get_mitre_info(incident.mitre_technique)
    owasp_info = get_owasp_info(incident.mitre_technique)
    return (
        f"Attacker IP: {attacker_ip}\n"
        f"First detected: {incident.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Attack Type: {incident.attack_type}\n"
        f"Severity: {incident.severity} | Confidence: {incident.confidence} | Risk Score: {incident.risk_score}\n"
        f"Path: {req.url if req else 'N/A'}\n"
        f"MITRE: {mitre_info}\n"
        f"OWASP: {owasp_info}\n"
        f"Evidence: {incident.evidence}\n"
        f"\n"
        f"This IP will not trigger another alert for {_cooldown_minutes()} minutes.\n"
        f"Full incident history: {_dashboard_url()}/websentinel/incidents?search={attacker_ip}\n"
    )


def _send_gmail_message(to_address: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = to_address
    msg["To"] = to_address
    msg.set_content(body)

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    service = _gmail_service()
    service.users().messages().send(userId="me", body={"raw": raw}).execute()


def send_alert_email(incident, to_address: str) -> None:
    req = incident.request
    attacker_ip = req.ip if req else "unknown"
    subject = f"[WebSentinel] {incident.severity} alert — {attacker_ip}"
    _send_gmail_message(to_address, subject, _alert_body(incident))


def maybe_alert(incident) -> None:
    if incident.severity not in ("Critical", "High"):
        return

    if not _is_enabled():
        return

    attacker_ip = incident.request.ip if incident.request else "unknown"
    if not should_alert(attacker_ip):
        return

    to_address = _alert_email()
    if not to_address:
        return

    try:
        send_alert_email(incident, to_address)
        logger.info("Alert email sent for %s (IP %s)",
                     incident.incident_code, attacker_ip)
        _record_alerted(incident)
    except Exception:
        logger.exception("Failed to send alert email for %s — incident was still logged",
                         incident.incident_code)


def alerting_issue() -> str:
    """Return a user-facing explanation of why alerts won't send, else ''.

    Shown on the dashboard Settings page so a silently-failed alert has
    visible feedback instead of only an error-level log line.
    """
    if not _is_enabled():
        return ""
    if not _alert_email():
        return ("Alerting is enabled but no email address is set — "
                "configure WEBSENTINEL_ALERT_EMAIL or save one on this page.")
    if not os.path.exists(TOKEN_FILE):
        if not os.path.exists(CREDENTIALS_FILE):
            return (
                f"Gmail OAuth cannot start: {CREDENTIALS_FILE} not found. "
                "Create an OAuth client of type 'Desktop app' in Google Cloud Console "
                "(APIs & Services > Credentials) and save it in the project directory."
            )
        return ("Gmail not authorized yet. Run `python -m utils.alerting authorize` "
                "from the project directory to complete the one-time Google login.")
    return ""


def authorize() -> None:
    """Run the one-time OAuth login and save token.json.

    Use this from the command line (outside a request thread): it opens the
    browser, waits for the login, and writes token.json for reuse.
    """
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"ERROR: {CREDENTIALS_FILE} not found in {os.getcwd()}", file=sys.stderr)
        print("Create an OAuth Desktop client in Google Cloud Console and save it here, "
              "then re-run this command.", file=sys.stderr)
        sys.exit(1)
    creds = _gmail_credentials()
    print(f"Authorized. Token saved to {os.path.abspath(TOKEN_FILE)}")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m utils.alerting",
        description="WebSentinel Gmail alerting tools.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("authorize", help="one-time OAuth login, writes token.json")
    send = sub.add_parser("send-test", help="send a test alert email")
    send.add_argument("--email", required=True, help="recipient Gmail address")
    args = parser.parse_args()

    if args.command == "authorize":
        authorize()
    elif args.command == "send-test":
        try:
            _send_gmail_message(
                args.email,
                "[WebSentinel] Test alert",
                "This is a test alert from WebSentinel.",
            )
            print(f"Test alert sent to {args.email}")
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
