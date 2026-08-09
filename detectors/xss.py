"""
detectors/xss.py

Rule-based Cross-Site Scripting (XSS) detector.
Same detect(data) -> dict|None contract as detectors/sql.py.
"""

import re

# Each tuple is (compiled regex, evidence, confidence).
XSS_PATTERNS = [
    (re.compile(r"<script.*?>", re.IGNORECASE), "Inline <script> tag detected", "Very High"),
    (re.compile(r"on\w+\s*=\s*['\"]", re.IGNORECASE), "Inline JS event handler (onerror=, onload=, etc.) detected", "High"),
    (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript: URI scheme detected", "High"),
    (re.compile(r"<img[^>]+onerror", re.IGNORECASE), "Image tag with onerror payload detected", "High"),
    (re.compile(r"%3Cscript", re.IGNORECASE), "URL-encoded <script> tag detected", "High"),
    (re.compile(r"document\.cookie", re.IGNORECASE), "Cookie-stealing payload pattern detected", "Very High"),
]


def detect(data: dict):
    from utils.normalize import normalize

    payload = normalize(data.get("payload", "") or "")

    for pattern, evidence, confidence in XSS_PATTERNS:
        if pattern.search(payload):
            return {
                "attack_type": "Cross-Site Scripting (XSS)",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1059.007",  # JavaScript execution
                "recommendation": (
                    "Encode all output rendered into HTML (contextual output encoding), "
                    "apply a strict Content-Security-Policy, and validate input server-side "
                    "rather than relying on client-side filtering alone."
                ),
            }
    return None
