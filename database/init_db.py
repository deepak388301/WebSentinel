"""
database/init_db.py

Database initializer — uses Flask-Migrate (Alembic) to manage schema.

Usage:
    python database/init_db.py            # apply all migrations
    python database/init_db.py --reset    # downgrade to base, then re-apply
    python database/init_db.py --seed     # also insert sample demo data
"""

import os
import sys

# Allow running this script directly (python database/init_db.py) by adding
# the project root to the path, since models.py is imported as a package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from proxy_app import create_app
from database.models import db, Request, Incident


def seed_sample_data():
    """Inserts a handful of realistic sample rows so the dashboard isn't
    empty on first run — useful for screenshots/demos before real traffic
    has hit the app."""
    sample_request = Request(
        ip="203.0.113.42",
        method="GET",
        url="/search",
        headers='{"User-Agent": "Mozilla/5.0"}',
        payload="id=1' OR 1=1--",
        user_agent="Mozilla/5.0",
        status_code=404,
    )
    db.session.add(sample_request)
    db.session.commit()  # commit first so sample_request.id is populated

    sample_incident = Incident(
        incident_code=f"INC-{sample_request.id:05d}",
        request_id=sample_request.id,
        attack_type="SQL Injection",
        severity="Critical",
        confidence="High",
        risk_score=95,
        evidence="Boolean tautology (OR 1=1 style) detected",
        recommendation=(
            "Use parameterized queries / prepared statements instead of "
            "string-concatenated SQL. Apply least-privilege database accounts."
        ),
        mitre_technique="T1190",
        status="Open",
    )
    db.session.add(sample_incident)
    db.session.commit()
    print(f"Seeded 1 sample request + 1 sample incident ({sample_incident.incident_code}).")


def main():
    reset = "--reset" in sys.argv
    seed = "--seed" in sys.argv

    app = create_app()
    with app.app_context():
        if reset:
            print("Downgrading to base...")
            from flask_migrate import downgrade
            downgrade(revision="base")

        from flask_migrate import upgrade
        upgrade()
        print("Migrations applied.")

        if seed:
            seed_sample_data()

    print(f"Database ready at {app.config['SQLALCHEMY_DATABASE_URI']}")


if __name__ == "__main__":
    main()
