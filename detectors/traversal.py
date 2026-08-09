"""
detectors/traversal.py

Rule-based Path/Directory Traversal detector.
Same detect(data) -> dict|None contract as the other detectors.
"""

import re

# Each tuple is (compiled regex, evidence, confidence).
TRAVERSAL_PATTERNS = [
    (re.compile(r"\.\./\.\./\.\./"), "Deep directory traversal chain detected", "Very High"),
    (re.compile(r"\.\./"), "Relative traversal sequence (../) detected", "High"),
    (re.compile(r"\.\.\\"), "Windows-style traversal sequence (..\\) detected", "High"),
    (re.compile(r"%2e%2e%2f", re.IGNORECASE), "URL-encoded traversal sequence detected", "High"),
    (re.compile(r"etc/passwd", re.IGNORECASE), "Sensitive Linux file path (/etc/passwd) referenced", "Very High"),
    (re.compile(r"boot\.ini", re.IGNORECASE), "Sensitive Windows file path (boot.ini) referenced", "Very High"),
]


def detect(data: dict):
    from utils.normalize import normalize

    payload = normalize(data.get("payload", "") or "")
    url = normalize(data.get("url", "") or "")
    combined = f"{url} {payload}"

    for pattern, evidence, confidence in TRAVERSAL_PATTERNS:
        if pattern.search(combined):
            return {
                "attack_type": "Path Traversal",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1083",  # File and Directory Discovery
                "recommendation": (
                    "Canonicalize and validate file paths server-side before use, "
                    "restrict file access to a fixed allow-listed directory, and "
                    "never build file paths directly from user input."
                ),
            }
    return None
