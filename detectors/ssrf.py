"""
detectors/ssrf.py

Rule-based Server-Side Request Forgery (SSRF) detector.
Detects dangerous URI schemes, cloud metadata IPs, and internal
host references in request parameters.
"""

import re

# Each tuple is (compiled regex, evidence, confidence).
SSRF_PATTERNS = [
    (re.compile(r"file://", re.IGNORECASE), "File URI scheme (file://) detected", "Very High"),
    (re.compile(r"gopher://", re.IGNORECASE), "Gopher URI scheme (gopher://) detected", "Very High"),
    (re.compile(r"dict://", re.IGNORECASE), "Dict URI scheme (dict://) detected", "Very High"),
    (re.compile(r"169\.254\.169\.254"), "AWS/GCP cloud metadata IP detected", "Very High"),
    (re.compile(r"metadata\.google\.internal", re.IGNORECASE), "GCP metadata endpoint detected", "Very High"),
    (re.compile(r"(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?:[:/]|$)", re.IGNORECASE), "Internal host reference detected", "High"),
]


def detect(data: dict):
    from utils.normalize import normalize

    payload = normalize(data.get("payload", "") or "")
    url = normalize(data.get("url", "") or "")
    combined = f"{url} {payload}"

    for pattern, evidence, confidence in SSRF_PATTERNS:
        if pattern.search(combined):
            return {
                "attack_type": "SSRF",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1190",
                "recommendation": (
                    "Validate and sanitize all URLs before making server-side "
                    "requests. Use an allow-list of permitted domains/IPs, "
                    "block internal/private IP ranges, and disable unnecessary "
                    "URI schemes (file://, gopher://, dict://)."
                ),
            }
    return None
