"""
detectors/sql.py

Rule-based SQL Injection detector.

Design note: every detector in this project follows the SAME contract —
    detect(data: dict) -> dict | None
so the Detection Engine (detectors/__init__.py) can loop over all of them
identically without special-casing any one attack type. This is the pattern
to follow when you add new detectors later (e.g., SSRF, LFI).
"""

import re

# Each tuple is (compiled regex, human-readable evidence string, confidence).
# Confidence is per-pattern — not all SQL Injection signals are equally strong.
SQLI_PATTERNS = [
    (re.compile(r"(\bunion\b.{0,20}\bselect\b)", re.IGNORECASE), "UNION SELECT keyword sequence detected", "Very High"),
    (re.compile(r"(\bor\b\s+\d+\s*=\s*\d+)", re.IGNORECASE), "Boolean tautology (OR 1=1 style) detected", "High"),
    (re.compile(r"(--|#|/\*)"), "SQL comment sequence detected", "Medium"),
    (re.compile(r"(\binformation_schema\b)", re.IGNORECASE), "information_schema enumeration attempt detected", "High"),
    (re.compile(r"(\bdrop\b\s+\btable\b)", re.IGNORECASE), "DROP TABLE keyword detected", "High"),
    (re.compile(r"('.*(\bor\b|\band\b).*')", re.IGNORECASE), "Quoted boolean injection pattern detected", "High"),
]


def detect(data: dict):
    """
    data must contain 'payload' (query string + body, already URL-decoded).
    Returns an incident dict if matched, otherwise None.
    """
    from utils.normalize import normalize

    payload = normalize(data.get("payload", "") or "")

    for pattern, evidence, confidence in SQLI_PATTERNS:
        if pattern.search(payload):
            return {
                "attack_type": "SQL Injection",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1190",  # Exploit Public-Facing Application
                "recommendation": (
                    "Use parameterized queries / prepared statements instead of "
                    "string-concatenated SQL. Apply least-privilege database accounts "
                    "and validate/allow-list input types."
                ),
            }
    return None
