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

# Each tuple is (compiled regex, human-readable evidence string).
# Patterns are intentionally broad for a rule-based v1 — expect some false
# positives; that's a documented limitation (Section 15 of the project doc),
# not a bug to over-engineer away in a 20-day scope.
SQLI_PATTERNS = [
    (re.compile(r"(\bunion\b.{0,20}\bselect\b)", re.IGNORECASE), "UNION SELECT keyword sequence detected"),
    (re.compile(r"(\bor\b\s+\d+\s*=\s*\d+)", re.IGNORECASE), "Boolean tautology (OR 1=1 style) detected"),
    (re.compile(r"(--|#|/\*)"), "SQL comment sequence detected"),
    (re.compile(r"(\binformation_schema\b)", re.IGNORECASE), "information_schema enumeration attempt detected"),
    (re.compile(r"(\bdrop\b\s+\btable\b)", re.IGNORECASE), "DROP TABLE keyword detected"),
    (re.compile(r"('.*(\bor\b|\band\b).*')", re.IGNORECASE), "Quoted boolean injection pattern detected"),
]


def detect(data: dict):
    """
    data must contain 'payload' (query string + body, already URL-decoded).
    Returns an incident dict if matched, otherwise None.
    """
    payload = data.get("payload", "") or ""

    for pattern, evidence in SQLI_PATTERNS:
        if pattern.search(payload):
            return {
                "attack_type": "SQL Injection",
                "confidence": "High",
                "evidence": evidence,
                "mitre_technique": "T1190",  # Exploit Public-Facing Application
                "recommendation": (
                    "Use parameterized queries / prepared statements instead of "
                    "string-concatenated SQL. Apply least-privilege database accounts "
                    "and validate/allow-list input types."
                ),
            }
    return None
