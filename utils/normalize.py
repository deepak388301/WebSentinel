"""
utils/normalize.py

Input normalization for the detection engine.
Decodes and flattens request values before pattern matching so that
double-URL-encoded or obfuscated payloads are caught.
"""

import re
from urllib.parse import unquote_plus


def normalize(raw: str) -> str:
    """Decode and flatten a request value before pattern matching.

    Must be idempotent (safe to call once) even on already-decoded input.
    Returns the normalized string; never raises on malformed encoding —
    falls back to the original string if decoding fails.
    """
    if not raw:
        return ""

    # 1. URL-decode repeatedly until stable (cap at 3 iterations)
    decoded = raw
    for _ in range(3):
        try:
            new = unquote_plus(decoded, errors="replace")
        except Exception:
            break
        if new == decoded:
            break
        decoded = new

    # 2. Lowercase a copy for keyword matching
    lowered = decoded.lower()

    # 3. Strip inline SQL comments /* ... */ and collapse whitespace
    stripped = re.sub(r"/\*.*?\*/", " ", lowered)
    stripped = re.sub(r"\s+", " ", stripped).strip()

    return stripped
