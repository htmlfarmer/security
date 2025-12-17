# Automated Security Audit Script Ideas

This list is divided into three audit levels. Each level builds upon the last, increasing in depth and potential intrusiveness.

*   **Basic Audit:** Fast, passive, non-intrusive checks focused on configuration and public information.
*   **Advanced Audit:** Active enumeration and deeper inspection that sends more traffic to the target.
*   **Extreme Audit:** Intrusive testing that involves submitting payloads, heavy crawling, and attempting to trigger vulnerabilities.

---

### I. Basic Audit (Fast & Non-Intrusive)

1.  **Technology Fingerprinter:** Identifies the web stack by inspecting HTTP headers (`Server`, `X-Powered-By`), meta tags (`generator`), JavaScript variables (`React`, `Drupal.settings`), and unique HTML source code patterns to detect CMS (WordPress, Joomla), frameworks (Next.js, Ruby on Rails), UI libraries (React, Vue), and server technologies (Nginx, Apache).
2.  **Security Headers Checker:** Verifies the presence of headers like CSP, HSTS, etc.
3.  **Clickjacking Tester:** Checks for missing `X-Frame-Options` or `frame-ancestors`.
4.  **Cookie Attribute Scanner:** Inspects cookies for `HttpOnly`, `Secure`, and `SameSite` attributes.
5.  **Robots.txt & Sitemap Parser:** Finds disallowed or interesting endpoints from `robots.txt` and `sitemap.xml`.
6.  **WHOIS & DNS Record Inspector:** Gathers domain registration and basic DNS records.
7.  **Email Spoofing (SPF/DMARC) Checker:** Checks DNS for correct anti-spoofing configurations.
8.  **WAF Detector:** Identifies if a Web Application Firewall is in place.
9.  **Broken Link Checker:** Crawls the initial page to find broken links.

---

### II. Advanced Audit (Active Enumeration & Deeper Inspection)

10. **Subdomain Enumerator:** Discovers subdomains using a common wordlist.
11. **Directory & File Brute-Forcer:** Searches for common hidden directories and files.
12. **Admin Panel Finder:** Tries to locate admin login pages.
13. **Sensitive File Finder:** Scans for publicly exposed files like `.git`, `.env`.
14. **Port Scanner:** Checks for common open web-related ports on the server.
15. **SSL/TLS Scanner:** Checks for weak ciphers and expired certificates.
16. **HTTP Methods Tester:** Checks which HTTP methods are allowed on the web root.
17. **CORS Misconfiguration Checker:** Tests for overly permissive CORS headers.
18. **Username Enumeration Detector:** Checks login/reset pages for information disclosure.
19. **CSRF Token Checker:** Crawls and verifies that sensitive forms contain anti-CSRF tokens.
20. **Dependency Vulnerability Scanner:** Checks for outdated and vulnerable frontend JS libraries.
21. **API Endpoint Discovery:** Scans JS files to discover unlinked API endpoints.

---

### III. Extreme Audit (Intrusive Payload & Logic Testing)

22. **Reflected XSS Scanner:** Injects basic XSS payloads into URL parameters and forms.
23. **SQL Injection (SQLi) Scanner:** Tests inputs with basic boolean and time-based payloads.
24. **Command Injection Scanner:** Tries to inject OS commands into input fields.
25. **Open Redirect Tester:** Checks parameters for redirection to arbitrary websites.
26. **Directory Traversal Finder:** Tries to access files outside the web root.
27. **Verbose Error Message Detector:** Submits invalid data to trigger and detect detailed errors.
28. **Login Rate-Limiting Tester:** Attempts a small brute-force on a login form.
29. **File Upload Vulnerability Checker:** Attempts to upload files with dangerous extensions.
30. **Website Crawler & Link/Form Extractor:** Navigates the entire website to map it out.
31. **DOM-based XSS Scanner:** Uses a headless browser to inject payloads into URL fragments.
32. **Insecure Form Action Checker:** Crawls the site to find forms submitting over HTTP.
33. **User Workflow IDOR Tester:** (Requires configuration) Logs in as different users to test access controls.
34. **API Authorization Tester:** Tries to access authenticated API endpoints with invalid tokens.
35. **API Rate Limiting Tester:** Sends a high volume of requests to an API endpoint.
