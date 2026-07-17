"""
utils/risk_engine.py

Converts a raw detector finding into a 0-100 risk score and a severity
label. Kept as a simple weighted lookup for v1 — this is the piece to
extend later with attempt-count history and endpoint sensitivity from
Section 8 of the project doc.
"""

# Base score per attack type — reflects typical real-world impact.
BASE_SCORES = {
    "SQL Injection": 85,
    "Cross-Site Scripting (XSS)": 65,
    "Path Traversal": 75,
    "Brute Force": 70,
    "Directory Enumeration": 40,
}

CONFIDENCE_MODIFIER = {
    "High": 10,
    "Medium": 0,
    "Low": -15,
}


def calculate_risk(finding: dict) -> dict:
    """
    finding: one dict returned by a detector (attack_type, confidence, ...)
    Returns the same dict with 'risk_score' and 'severity' added.
    """
    base = BASE_SCORES.get(finding["attack_type"], 50)
    modifier = CONFIDENCE_MODIFIER.get(finding.get("confidence", "Medium"), 0)

    score = max(0, min(100, base + modifier))

    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    finding["risk_score"] = score
    finding["severity"] = severity
    return finding
