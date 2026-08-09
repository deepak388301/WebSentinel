import json
import logging
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

logger = logging.getLogger("websentinel.references")


def _load(filename, default):
    """Load a JSON lookup file, degrading gracefully if it is missing.

    The files in data/ are runtime assets, not generated code — if they are
    absent (e.g. an incomplete checkout) the WAF must still start; only the
    human-readable reference names degrade to 'Unknown'.
    """
    try:
        with open(_DATA_DIR / filename) as f:
            return json.load(f)
    except (OSError, ValueError):
        logger.warning("data/%s not found — reference names unavailable.", filename)
        return default


_MITRE_NAMES = _load("mitre_names.json", {})
_OWASP_MAPPINGS = _load("owasp_mappings.json", {})


def get_mitre_info(mitre_id: str | None) -> str:
    if not mitre_id:
        return "N/A"
    name = _MITRE_NAMES.get(mitre_id, "Unknown")
    return f"{mitre_id} – {name}"


def get_owasp_info(mitre_id: str | None) -> str:
    if not mitre_id:
        return "\u2014"
    mapping = _OWASP_MAPPINGS.get(mitre_id)
    if not mapping:
        return "\u2014"
    return f"{mapping['code']} \u2013 {mapping['name']}"
