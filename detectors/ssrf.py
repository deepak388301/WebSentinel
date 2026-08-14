"""
detectors/ssrf.py

Rule-based Server-Side Request Forgery (SSRF) detector.
Detects dangerous URI schemes, cloud metadata IPs, and internal
host references in request parameters.

Also exposes two pure helper functions — ``_parse_encoded_ip`` and
``_is_dangerous_ip`` — shared with the dashboard's manual Target
Management feature. They classify whether a host is an IP literal in
the SSRF-sensitive range (loopback/private/link-local/...); the target
management UI uses them only for an *informational* notice, never to
block. Keeping them here (instead of a second IP-classification module)
means the two consumers can never drift out of sync.
"""

import ipaddress
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


def _decode_numeric_part(part: str):
    """Decode a single dot-separated component of an encoded IP literal.

    Tries Python's base-0 parsing first (handles decimal and 0x/0o
    prefixed forms). Python 3 rejects a leading-zero literal such as
    ``0177`` with base 0, so fall back to an explicit base-8 decode for
    octal-looking components.
    """
    part = part.strip()
    if not part:
        return None
    try:
        return int(part, 0)
    except ValueError:
        pass
    if re.fullmatch(r"0[0-7]+", part):
        try:
            return int(part, 8)
        except ValueError:
            return None
    return None


def _parse_encoded_ip(host: str):
    """Decode a host string into a canonical ``ipaddress`` object.

    Accepts plain IPv4/IPv6 literals and the numeric encodings attackers
    use to smuggle an address past naive filters: decimal
    (2130706433 == 127.0.0.1), octal (017700000001), hex (0x7f000001)
    and mixed-radix short forms (127.1 == 127.0.0.1, 0x7f.1).

    Returns None when the host is a hostname rather than an IP literal.
    """
    host = (host or "").strip().lower()
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    parts = host.split(".")
    if not parts or not parts[0]:
        return None

    decoded = []
    for part in parts:
        value = _decode_numeric_part(part)
        if value is None:
            return None
        decoded.append(value)

    try:
        if len(decoded) == 1 and decoded[0] <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(decoded[0])
        if len(decoded) == 2 and decoded[0] <= 0xFF and decoded[1] <= 0xFFFFFF:
            return ipaddress.IPv4Address((decoded[0] << 24) | decoded[1])
        if len(decoded) == 3 and decoded[0] <= 0xFF and decoded[1] <= 0xFF and decoded[2] <= 0xFFFF:
            return ipaddress.IPv4Address((decoded[0] << 24) | (decoded[1] << 16) | decoded[2])
        if len(decoded) == 4 and all(v <= 0xFF for v in decoded):
            return ipaddress.IPv4Address(tuple(decoded))
    except ValueError:
        return None
    return None


def _is_dangerous_ip(host: str) -> bool:
    """True when the host names an address in the SSRF-sensitive range:
    loopback, private, link-local, reserved, multicast, or unspecified —
    or is the literal ``localhost``.

    This is an informational classification helper. It never blocks or
    rejects anything on its own; consumers decide what to do with it.
    """
    host = (host or "").strip().lower()
    if not host:
        return False
    if host == "localhost":
        return True
    parsed = _parse_encoded_ip(host)
    if parsed is None:
        return False
    return (
        parsed.is_loopback or parsed.is_private or parsed.is_link_local
        or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified
    )
