from typing import Tuple

# Centralized keyword -> severity mapping
KEYWORD_SEVERITY = {
    'VULNERABILITY:': 'High',
    'Potential sensitive data': 'High',
    'DOM-based XSS detected': 'High',
    'OUTDATED': 'Medium',
    'Missing Header:': 'Medium',
    'insecure HTTP URL': 'Medium',
    'Broken Link Found:': 'Low',
    'Unreachable Link Found:': 'Low',
    'Error:': 'Low'
}

def classify_line(line: str) -> Tuple[str, str]:
    """
    Return (severity, matched_keyword) for a line if any keyword is found.
    Severity can be 'High', 'Medium', 'Low', or ''.
    """
    for kw, sev in KEYWORD_SEVERITY.items():
        if kw in line:
            return sev, kw
    return '', ''
