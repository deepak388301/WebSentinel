"""
detectors/traversal.py

Rule-based Path/Directory Traversal detector.
Same detect(data) -> dict|None contract as the other detectors.
"""

import re

TRAVERSAL_PATTERNS = [
    (re.compile(r"\.\./"), "Relative traversal sequence (../) detected"),
    (re.compile(r"\.\.\\"), "Windows-style traversal sequence (..\\) detected"),
    (re.compile(r"%2e%2e%2f", re.IGNORECASE), "URL-encoded traversal sequence detected"),
    (re.compile(r"etc/passwd", re.IGNORECASE), "Sensitive Linux file path (/etc/passwd) referenced"),
    (re.compile(r"boot\.ini", re.IGNORECASE), "Sensitive Windows file path (boot.ini) referenced"),
    (re.compile(r"\.\./\.\./\.\./"), "Deep directory traversal chain detected"),
]


def detect(data: dict):
    payload = data.get("payload", "") or ""
    url = data.get("url", "") or ""
    combined = f"{url} {payload}"

    for pattern, evidence in TRAVERSAL_PATTERNS:
        if pattern.search(combined):
            return {
                "attack_type": "Path Traversal",
                "confidence": "High",
                "evidence": evidence,
                "mitre_technique": "T1083",  # File and Directory Discovery
                "recommendation": (
                    "Canonicalize and validate file paths server-side before use, "
                    "restrict file access to a fixed allow-listed directory, and "
                    "never build file paths directly from user input."
                ),
            }
    return None
