import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("WEBSENTINEL_ADMIN_USER", "testadmin")
os.environ.setdefault("WEBSENTINEL_ADMIN_PASS", "testpass123")
os.environ.setdefault("WEBSENTINEL_SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("WTF_CSRF_ENABLED", "false")
# Keep the in-memory rate limiter out of the general suite (dedicated tests
# in test_hardening.py enable it explicitly).
os.environ.setdefault("WEBSENTINEL_RATE_LIMIT", "0")

# Snapshot whether the Postgres URI was EXPLICITLY exported before the app's
# load_dotenv() can source it from .env. If it only came from .env, remove it
# again so the optional Postgres verification tests (which write to that DB)
# only run when the operator genuinely opts in — never against an arbitrary
# .env database.
_HAD_DB_URI = "WEBSENTINEL_DB_URI" in os.environ

from database.models import db as _db
from proxy_app import create_app

if not _HAD_DB_URI:
    os.environ.pop("WEBSENTINEL_DB_URI", None)


def _make_app():
    """Create a test app with in-memory SQLite and tables created."""
    app = create_app(
        database_uri="sqlite:///:memory:",
        target_url="http://127.0.0.1:9000",
    )
    with app.app_context():
        _db.create_all()
    return app
