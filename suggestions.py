"""
Centralized suggestion/remediation mapping for security findings.
Each finding keyword maps to helpful guidance.
"""

SUGGESTIONS = {
    "Missing Header: Strict-Transport-Security": [
        "Add HSTS header to force HTTPS connections.",
        "Example: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    ],
    "Missing Header: Content-Security-Policy": [
        "Implement CSP to prevent XSS and injection attacks.",
        "Start with a restrictive policy and gradually relax as needed.",
        "Example: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'"
    ],
    "Missing Header: X-Frame-Options": [
        "Set X-Frame-Options to prevent clickjacking attacks.",
        "Recommended value: X-Frame-Options: DENY or SAMEORIGIN"
    ],
    "Missing Header: X-Content-Type-Options": [
        "Add X-Content-Type-Options: nosniff to prevent MIME type sniffing.",
        "This forces browsers to respect the Content-Type header."
    ],
    "Missing Header: Referrer-Policy": [
        "Set Referrer-Policy to control how much referrer info is shared.",
        "Recommended: Referrer-Policy: strict-origin-when-cross-origin"
    ],
    "VULNERABILITY: Site may be vulnerable to Clickjacking": [
        "Add X-Frame-Options header or Content-Security-Policy with frame-ancestors directive.",
        "This prevents your site from being embedded in iframes on other domains."
    ],
    "VULNERABILITY: Reflected XSS found": [
        "Sanitize and validate all user input before rendering to HTML.",
        "Use context-aware output encoding (HTML, JavaScript, URL encoding).",
        "Consider using a template engine with auto-escaping enabled."
    ],
    "VULNERABILITY: DOM-based XSS detected": [
        "Avoid using innerHTML with untrusted data; use textContent instead.",
        "Sanitize DOM queries (document.getElementById, etc.) with trusted input only.",
        "Use a library like DOMPurify for HTML sanitization."
    ],
    "OUTDATED": [
        "Update the library to the latest stable version.",
        "Check the library's changelog for security fixes and breaking changes.",
        "Test thoroughly after updating dependencies."
    ],
    "Broken Link Found": [
        "Fix or remove broken internal links.",
        "Update or redirect outdated URLs.",
        "Use a link checker tool periodically to catch new broken links."
    ],
    "robots.txt contains disallowed paths that may expose sensitive endpoints": [
        "Review robots.txt to ensure sensitive paths are not disclosed.",
        "Consider removing sensitive path hints (e.g., /admin, /backup).",
        "Use authentication and proper access controls instead of obscurity."
    ],
    "Potential sensitive data found": [
        "Remove hardcoded API keys, secrets, and credentials from code.",
        "Use environment variables or secure secret management services.",
        "Scan code repositories regularly with tools like git-secrets or truffleHog."
    ]
}

def get_suggestions(finding_text):
    """
    Return a list of suggestions for a given finding.
    Searches for matching keywords in the finding text.
    """
    for keyword, suggestions_list in SUGGESTIONS.items():
        if keyword in finding_text:
            return suggestions_list
    return []

def print_suggestions(finding_text):
    """
    Print suggestions for a finding in a formatted way.
    """
    suggestions = get_suggestions(finding_text)
    if suggestions:
        print("  📋 SUGGESTIONS:")
        for i, suggestion in enumerate(suggestions, 1):
            print(f"    {i}. {suggestion}")
