"""
database/models.py

Defines the two core tables WebSentinel writes to:
  - Request  : every HTTP request that hits the app (the raw evidence log)
  - Incident : created only when a detector flags a request as malicious

Kept in one file for a 20-day project scope — split into request.py / incident.py
later if the schema grows.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# db is created here and imported by app.py — this avoids circular imports
# between app.py and the detector/route modules that also need db access.
db = SQLAlchemy()


class Request(db.Model):
    """One row per HTTP request received by the monitored application."""
    __tablename__ = "requests"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    ip = db.Column(db.String(45), nullable=False)          # IPv4/IPv6-safe length
    method = db.Column(db.String(10), nullable=False)      # GET, POST, etc.
    url = db.Column(db.String(500), nullable=False)
    headers = db.Column(db.Text)                            # stored as JSON string
    payload = db.Column(db.Text)                             # query string + body combined
    user_agent = db.Column(db.String(300))
    status_code = db.Column(db.Integer)

    # One request can trigger multiple incidents (rare, but possible if a
    # payload matches more than one detector) — backref lets an Incident
    # look up its parent Request easily.
    incidents = db.relationship("Incident", backref="request", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.ip,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
        }


class Incident(db.Model):
    """One row per detected attack. Created by the Incident Generator."""
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)
    incident_code = db.Column(db.String(20), unique=True, nullable=False)  # e.g. INC-00125
    request_id = db.Column(db.Integer, db.ForeignKey("requests.id"), nullable=False)

    attack_type = db.Column(db.String(50), nullable=False)   # SQL Injection, XSS, etc.
    severity = db.Column(db.String(20), nullable=False)      # Critical/High/Medium/Low
    confidence = db.Column(db.String(20))                    # High/Medium/Low
    risk_score = db.Column(db.Integer)                       # 0-100
    evidence = db.Column(db.Text)                             # what specifically matched
    recommendation = db.Column(db.Text)
    mitre_technique = db.Column(db.String(20))                # e.g. T1190
    status = db.Column(db.String(20), default="Open")         # Open/Reviewed/Closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "incident_code": self.incident_code,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "mitre_technique": self.mitre_technique,
            "status": self.status,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
