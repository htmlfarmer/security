"""
Detailed descriptions of each security test for report generation.
Each description provides 2-5 sentences explaining what the test does.
"""

TEST_DESCRIPTIONS = {
    "tech_fingerprinter.py": "Identifies the web stack and technologies used by a website by analyzing HTTP response headers, cookies, meta tags, and HTML/JavaScript patterns. It detects CMS platforms like WordPress and Drupal, web frameworks like Next.js and Rails, UI libraries like React and Vue, and server software like Nginx and Apache. Additionally, it checks for outdated library versions that may contain known vulnerabilities. This passive reconnaissance helps identify potential weaknesses specific to detected technologies.",
    
    "header_checker.py": "Verifies the presence of critical security headers that protect against common web vulnerabilities. The test checks for headers like Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, and Referrer-Policy. Missing security headers can leave a website vulnerable to clickjacking, XSS, MIME sniffing, and other attacks. Each missing header represents a missed opportunity to strengthen the site's security posture.",
    
    "robots_txt.py": "Fetches and analyzes the robots.txt file to identify endpoints that the site owner has explicitly marked as off-limits to crawlers. While robots.txt is not a security mechanism, sensitive paths disclosed in Disallow entries (like /admin, /backup, .git) can hint at the site's internal structure. This test also identifies Sitemap entries and User-Agent rules. Sensitive information in robots.txt can be leveraged by attackers to discover hidden or administrative endpoints.",
    
    "dns_whois_nslookup_checker.py": "Performs DNS lookups and WHOIS queries to gather domain registration and DNS configuration information. It retrieves DNS records (A, AAAA, MX, TXT, NS) that reveal mail servers, name servers, and other infrastructure details. WHOIS data may include registrant contact information, creation/expiration dates, and registrar details. This reconnaissance data helps build an understanding of the target's infrastructure and organizational information.",
    
    "cookie_checker.py": "Inspects all cookies set by the website for security attributes like HttpOnly, Secure, and SameSite flags. The HttpOnly flag prevents JavaScript from accessing cookies, protecting against XSS attacks. The Secure flag ensures cookies are only transmitted over HTTPS. The SameSite attribute protects against Cross-Site Request Forgery (CSRF) attacks. Missing these attributes leaves session cookies and authentication tokens vulnerable to theft or misuse.",
    
    "spf_dmarc_checker.py": "Checks DNS records for SPF (Sender Policy Framework) and DMARC (Domain-based Message Authentication, Reporting and Conformance) configurations. SPF records specify which mail servers are authorized to send emails on behalf of the domain, preventing email spoofing. DMARC builds on SPF and DKIM to provide a policy for handling authentication failures. Missing or misconfigured SPF/DMARC records allow attackers to send phishing emails impersonating the organization.",
    
    "waf_detector.py": "Analyzes HTTP response headers and cookies to detect the presence of a Web Application Firewall (WAF). Common WAFs like Cloudflare, AWS WAF, ModSecurity, Akamai, and F5 BIG-IP leave distinctive signatures in headers and cookies. Identifying a WAF helps understand what protections are in place and may inform attack strategy. This information is valuable for understanding the target's defensive posture.",
    
    "link_checker.py": "Crawls the website's homepage and checks all internal and external links for accessibility and valid HTTP status codes. The test identifies broken links that return 4xx or 5xx errors, which can indicate missing pages or misconfigured redirects. Broken links harm user experience and may reveal recently removed or improperly migrated content. Excessive broken links suggest poor website maintenance.",
    
    "sensitive_data_scanner.py": "Scans the page HTML and linked JavaScript files for patterns matching common sensitive data like API keys, AWS credentials, private keys, email addresses, and JWT tokens. Hardcoded secrets in client-side code are immediately accessible to attackers and can grant unauthorized access to backend services. This test fetches a limited number of JavaScript files to avoid excessive bandwidth usage. Discovery of exposed secrets requires immediate remediation and secret rotation.",
    
    "sitemap_parser.py": "Fetches and parses the sitemap.xml file to extract all URLs that the site owner has explicitly listed for indexing. The sitemap provides a complete map of publicly intended endpoints and content structure. This information helps identify all pages and resources that should be tested. The URL list can also reveal the site's organization, functionality, and potential sensitive sections.",
    
    "subdomain_enum.py": "Attempts to discover subdomains of the target domain by testing a wordlist of common subdomain names against the domain's DNS. Subdomains like 'admin', 'api', 'staging', 'mail', and 'dev' often host additional services or administrative interfaces. Finding these subdomains expands the attack surface and may reveal less-protected development or internal systems. This active enumeration helps identify all internet-facing assets owned by the organization.",
    
    "dirbust_scanner.py": "Brute-forces common directory names on the web server to discover hidden or unlinked folders and files. Directories like /admin, /backup, /config, /uploads, and /staging are frequently discovered through directory brute-forcing. These hidden directories often contain sensitive files, configuration data, or unprotected functionality. Even if not directly accessible, discovering these directories provides valuable information about the site's structure.",
    
    "admin_finder.py": "Searches for common admin panel paths and login pages by attempting to access well-known administrative URLs. Admin panels like /admin, /wp-admin, /administrator, /cpanel, and /phpmyadmin are frequently targeted by attackers. Finding these panels identifies potential entry points for unauthorized access. The presence of publicly accessible admin panels represents a significant security risk.",
    
    "cors_checker.py": "Tests the site's Cross-Origin Resource Sharing (CORS) configuration by sending requests with a foreign origin and analyzing the response headers. Overly permissive CORS policies (allowing all origins with Access-Control-Allow-Origin: *) can enable attackers to access sensitive data from user browsers. Misconfigured CORS may allow unauthorized access to protected resources. This test identifies potential cross-origin vulnerabilities.",
    
    "http_methods_checker.py": "Tests which HTTP methods (GET, POST, PUT, DELETE, PATCH, TRACE, OPTIONS, CONNECT) are allowed on the server. Dangerous methods like PUT and DELETE can allow unauthorized modification or deletion of server content if not properly restricted. The TRACE method can expose sensitive headers and data. Unrestricted HTTP methods represent a significant security vulnerability.",
    
    "screenshot_taker.py": "Captures a screenshot of the website's homepage using a headless browser at 1920x1080 resolution. The screenshot provides a visual record of the site's appearance and may reveal UI-level security issues or misconfigured elements. Screenshots are useful for documenting the state of the site at the time of the audit. The screenshot is saved in both PNG and base64-encoded JSON formats for easy embedding in reports.",
    
    "insecure_form_checker.py": "Crawls the website to identify HTML forms that submit data over insecure HTTP instead of encrypted HTTPS. Forms transmitting data over HTTP expose sensitive information like credentials, personal data, and payment information to network eavesdroppers. This is a critical vulnerability as it violates fundamental web security practices. All forms containing sensitive data must use HTTPS POST to protect user information.",
    
    "dom_xss_scanner.py": "Uses a headless browser to test for DOM-based XSS vulnerabilities by injecting payloads into URL fragments and monitoring for script execution. DOM XSS occurs when JavaScript code dynamically processes untrusted input without proper sanitization. This type of XSS can be difficult to detect as the attack happens entirely in the browser. Finding DOM XSS indicates unsafe handling of user-controlled data in client-side JavaScript.",
    
    "xss_scanner.py": "Tests web forms for reflected Cross-Site Scripting (XSS) vulnerabilities by injecting JavaScript payloads and checking if they appear unsanitized in the response. Reflected XSS allows attackers to inject malicious scripts that execute in users' browsers, potentially stealing cookies, credentials, or session tokens. This is one of the most common web vulnerabilities. Successful XSS attacks can lead to account takeover or data theft.",
    
    "sqli_scanner.py": "Tests web forms for SQL Injection (SQLi) vulnerabilities by submitting SQL metacharacters and boolean-based payloads to identify improper input sanitization. SQL injection allows attackers to execute arbitrary database queries, potentially reading or modifying sensitive data. This vulnerability often leads to complete database compromise. Successful SQLi exploitation can bypass authentication and expose all confidential information.",
    
    "open_redirect_checker.py": "Tests URL parameters for open redirect vulnerabilities by attempting to redirect to external domains and analyzing the response. Open redirects can be exploited to trick users into visiting malicious sites by disguising the redirect behind a trusted domain. Attackers use open redirects for phishing attacks and malware distribution. This vulnerability breaks user trust and enables social engineering attacks.",
    
    "directory_traversal_checker.py": "Tests URL parameters for directory traversal vulnerabilities by attempting to access files outside the web root using path traversal sequences. Directory traversal allows attackers to read sensitive files like configuration files, source code, or /etc/passwd on Unix systems. This vulnerability can expose database credentials, API keys, and other sensitive information. Successful exploitation often leads to complete system compromise.",
    
    "dependency_scanner.py": "Scans the page's script and link tags to detect frontend library versions and compares them against known latest versions. Outdated libraries often contain publicly disclosed vulnerabilities that attackers can easily exploit. Libraries like jQuery, Bootstrap, React, and Angular frequently have security updates. Using vulnerable library versions is a common security oversight that can be easily remediated.",
}

def get_description(script_name):
    """Retrieve the description for a given script."""
    return TEST_DESCRIPTIONS.get(script_name, "No description available for this test.")
