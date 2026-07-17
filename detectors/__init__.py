"""
detectors/__init__.py

The Detection Engine. This is the single point app.py calls — it doesn't
need to know about sql.py, xss.py, etc. individually. To add a new attack
type later, write a new module with a detect(data) -> dict|None function
and add it to DETECTOR_MODULES below. Nothing else in the app needs to change.
"""

from . import sql, xss, traversal, brute_force, enumeration

DETECTOR_MODULES = [sql, xss, traversal, brute_force, enumeration]


def run_all_detectors(data: dict):
    """
    Runs every registered detector against one request's data.
    Returns a LIST of findings (usually 0 or 1, but a payload could
    theoretically trip more than one detector — e.g. an XSS payload that
    also contains traversal-like characters).
    """
    findings = []
    for module in DETECTOR_MODULES:
        result = module.detect(data)
        if result:
            findings.append(result)
    return findings
