"""
detectors/nosql_injection.py

Rule-based NoSQL Injection detector (MongoDB-style operators in
query params or JSON bodies).
"""

import re

# Each tuple is (compiled regex, evidence, confidence).
NOSQLI_PATTERNS = [
    (re.compile(r"\$where", re.IGNORECASE), "MongoDB $where operator detected", "Very High"),
    (re.compile(r"\$ne\b", re.IGNORECASE), "MongoDB $ne operator detected", "High"),
    (re.compile(r"\$gt\b", re.IGNORECASE), "MongoDB $gt operator detected", "High"),
    (re.compile(r"\$regex", re.IGNORECASE), "MongoDB $regex operator detected", "High"),
    (re.compile(r'"\$or"\s*:', re.IGNORECASE), 'MongoDB "$or" query operator detected', "High"),
    (re.compile(r'"\$and"\s*:', re.IGNORECASE), 'MongoDB "$and" query operator detected', "High"),
    (re.compile(r'"\$exists"\s*:', re.IGNORECASE), 'MongoDB "$exists" query operator detected', "High"),
    (re.compile(r'"\$in"\s*:', re.IGNORECASE), 'MongoDB "$in" query operator detected', "High"),
]


def detect(data: dict):
    from utils.normalize import normalize

    payload = normalize(data.get("payload", "") or "")

    for pattern, evidence, confidence in NOSQLI_PATTERNS:
        if pattern.search(payload):
            return {
                "attack_type": "NoSQL Injection",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1190",
                "recommendation": (
                    "Validate and sanitize input types server-side. "
                    "Reject requests containing MongoDB operators in "
                    "user-controlled parameters, and use typed queries "
                    "instead of raw operator expressions."
                ),
            }
    return None
