import requests
import argparse
from urllib.parse import urlparse

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_headers(url):
    """
    Checks for the presence of recommended security headers.
    """
    print(f"[*] Checking security headers for: {url}")
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        missing_headers = []

        print("\n[+] Found Headers:")
        for header in SECURITY_HEADERS:
            if header in headers:
                print(f"  - {header}: {headers[header]}")
            else:
                missing_headers.append(header)
                
    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")
        return

    if missing_headers:
        print("\n[-] Missing Recommended Security Headers:")
        for header in missing_headers:
            print(f"  - Missing Header: {header}")

def main():
    parser = argparse.ArgumentParser(description="Check for recommended security headers.")
    parser.add_argument("url", help="The target URL to analyze (e.g., https://example.com or example.com)")
    args = parser.parse_args()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    check_headers(target_url)

if __name__ == "__main__":
    main()
