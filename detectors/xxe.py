"""
detectors/xxe.py

Rule-based XML External Entity (XXE) detector.
Only inspects request bodies when Content-Type suggests XML.
"""

import re

# Each tuple is (compiled regex, evidence, confidence).
XXE_PATTERNS = [
    (re.compile(r'SYSTEM\s+["\']file:', re.IGNORECASE), "SYSTEM file: entity reference detected", "Very High"),
    (re.compile(r"<!DOCTYPE", re.IGNORECASE), "DOCTYPE declaration detected", "High"),
    (re.compile(r"<!ENTITY", re.IGNORECASE), "ENTITY declaration detected", "High"),
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/xslt+xml",
    "application/mathml+xml",
]

# Prefixes that indicate XML content even without exact match above.
_XML_TYPE_PREFIXES = ["application/xml", "text/xml"]


def _is_xml_content_type(headers: str) -> bool:
    if not headers:
        return False
    lower = headers.lower()
    if any(ct in lower for ct in XML_CONTENT_TYPES):
        return True
    # Match vendor XML types like application/vnd.api+json+xml
    # but NOT non-XML vendor types like application/vnd.ms-excel.
    if any(lower.lstrip().startswith(p) or f" {p}" in lower for p in _XML_TYPE_PREFIXES):
        return True
    return False


def detect(data: dict):
    from utils.normalize import normalize

    headers = data.get("headers", "") or ""
    if not _is_xml_content_type(headers):
        return None

    payload = normalize(data.get("payload", "") or "")

    for pattern, evidence, confidence in XXE_PATTERNS:
        if pattern.search(payload):
            return {
                "attack_type": "XXE",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1190",
                "recommendation": (
                    "Disable external entity processing in XML parsers. "
                    "Use JSON instead of XML where possible, and validate "
                    "XML input against a strict schema before parsing."
                ),
            }
    return None
