import re
import yaml
from pathlib import Path

DEFAULT_RULES = {
    "ssh_bruteforce": {"threshold": 5, "time_window": 60, "severity": "high", "action": "block_ip"},
    "ftp_bruteforce": {"threshold": 5, "time_window": 60, "severity": "medium", "action": "block_ip"},
    "sql_injection": {
        "patterns": [r"'.*OR.*'='", r"UNION.*SELECT", r"DROP.*TABLE", r"INSERT.*INTO"],
        "severity": "critical",
        "action": "block_and_alert",
    },
    "directory_traversal": {
        "patterns": [r"\.\./|\.\.\\", r"%2e%2e/", r"\.\.%2f"],
        "severity": "high",
        "action": "block_request",
    },
    "port_scan": {"threshold": 10, "time_window": 30, "severity": "medium", "action": "block_ip"},
    "malware_upload": {
        "extensions": [".exe", ".sh", ".bat", ".vbs", ".ps1", ".dll"],
        "severity": "critical",
        "action": "quarantine_and_block",
    },
}

def load_rules(rules_path: str):
    p = Path(rules_path)
    if not p.exists():
        return DEFAULT_RULES

    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # basic validation
    merged = dict(DEFAULT_RULES)
    for k, v in data.items():
        if isinstance(v, dict):
            merged[k] = {**merged.get(k, {}), **v}
        else:
            merged[k] = v
    return merged


def match_any(patterns, text: str) -> bool:
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False
