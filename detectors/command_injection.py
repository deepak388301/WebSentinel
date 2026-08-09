"""
detectors/command_injection.py

Rule-based Command Injection detector.
Detects shell metacharacters combined with common commands.
"""

import re

# Each tuple is (compiled regex, evidence, confidence).
COMMAND_INJECTION_PATTERNS = [
    (re.compile(r";\s*rm\b", re.IGNORECASE), "Semicolon-separated rm command detected", "Very High"),
    (re.compile(r"\|\s*nc\b", re.IGNORECASE), "Pipe to netcat detected", "Very High"),
    (re.compile(r"\|\s*bash\b", re.IGNORECASE), "Pipe to bash detected", "Very High"),
    (re.compile(r"`[^`]*`", re.IGNORECASE), "Backtick command substitution detected", "High"),
    (re.compile(r"\$\([^)]*\)", re.IGNORECASE), "Dollar-paren command substitution detected", "High"),
    (re.compile(r"&&\s*curl\b", re.IGNORECASE), "AND-chained curl command detected", "High"),
    (re.compile(r"&&\s*wget\b", re.IGNORECASE), "AND-chained wget command detected", "High"),
    (re.compile(r";\s*cat\b", re.IGNORECASE), "Semicolon-separated cat command detected", "High"),
    (re.compile(r"\|\s*sh\b", re.IGNORECASE), "Pipe to shell detected", "High"),
    (re.compile(r">\s*/etc/", re.IGNORECASE), "Shell redirect to /etc/ detected", "High"),
]


def detect(data: dict):
    from utils.normalize import normalize

    payload = normalize(data.get("payload", "") or "")
    url = normalize(data.get("url", "") or "")
    combined = f"{url} {payload}"

    for pattern, evidence, confidence in COMMAND_INJECTION_PATTERNS:
        if pattern.search(combined):
            return {
                "attack_type": "Command Injection",
                "confidence": confidence,
                "evidence": evidence,
                "mitre_technique": "T1059",
                "recommendation": (
                    "Never pass user input directly to shell commands. "
                    "Use language-native APIs instead of shell execution, "
                    "and validate/sanitize input against an allow-list."
                ),
            }
    return None
