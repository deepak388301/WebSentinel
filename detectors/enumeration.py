"""
detectors/enumeration.py

Directory/Scanner enumeration detector — flags requests to paths commonly
probed by automated scanners (dirbuster, gobuster, nikto wordlists, etc.)
that shouldn't exist on a normal application.
"""

COMMON_SCANNER_PATHS = [
    "/.env", "/.git/config", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/admin.php", "/config.php", "/backup.sql", "/.htaccess", "/server-status",
    "/actuator/health", "/.aws/credentials", "/id_rsa",
]


def detect(data: dict):
    from utils.normalize import normalize

    url = normalize(data.get("url", "") or "")

    for path in COMMON_SCANNER_PATHS:
        if path in url:
            return {
                "attack_type": "Directory Enumeration",
                "confidence": "Medium",
                "evidence": f"Request to known scanner-targeted path: {path}",
                "mitre_technique": "T1595.003",  # Active Scanning: Wordlist Scanning
                "recommendation": (
                    "Ensure sensitive files (.env, .git, backups) are never served "
                    "from the web root. Return a generic 404 for unmapped routes and "
                    "monitor repeated 404s from the same IP as a scanning signal."
                ),
            }
    return None
