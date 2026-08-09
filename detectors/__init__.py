"""
detectors/__init__.py

The Detection Engine. This is the single point app.py calls — it doesn't
need to know about sql.py, xss.py, etc. individually. To add a new attack
type later, write a new module with a detect(data) -> dict|None function
and add it to DETECTOR_MODULES below. Nothing else in the app needs to change.
"""

from . import sql, xss, traversal, brute_force, enumeration, command_injection, nosql_injection, ssrf, xxe

DETECTOR_MODULES = [sql, xss, traversal, brute_force, enumeration, command_injection, nosql_injection, ssrf, xxe]
PRE_FORWARD_DETECTORS = [sql, xss, traversal, enumeration, command_injection, nosql_injection, ssrf, xxe]  # All except brute_force


def run_pre_forward_detectors(data: dict):
    """
    Runs detectors that inspect the REQUEST (not the response).
    These run before forwarding the request upstream, so blocking can happen early.
    Brute force detection requires the response status_code and runs separately.
    Returns a LIST of findings.
    """
    findings = []
    for module in PRE_FORWARD_DETECTORS:
        result = module.detect(data)
        if result:
            findings.append(result)
    return findings


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
