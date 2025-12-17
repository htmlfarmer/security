import requests
import argparse
from urllib.parse import urlparse

def check_clickjacking(url):
    """
    Checks for headers that prevent clickjacking attacks.
    """
    print(f"[*] Checking for Clickjacking vulnerability on: {url}")
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers

        xfo = headers.get('X-Frame-Options', '').lower()
        csp = headers.get('Content-Security-Policy', '')

        if xfo in ['deny', 'sameorigin']:
            print(f"[+] Site is protected with X-Frame-Options: {xfo}")
            return
        
        if 'frame-ancestors' in csp:
            print(f"[+] Site is protected with Content-Security-Policy: frame-ancestors directive found.")
            return

        print("[-] VULNERABILITY: Site may be vulnerable to Clickjacking.")
        print("    Reason: Missing 'X-Frame-Options' or 'Content-Security-Policy' with 'frame-ancestors'.")
        
    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check for Clickjacking vulnerability.")
    parser.add_argument("url", help="The target URL or domain to analyze (e.g., example.com).")
    args = parser.parse_args()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    check_clickjacking(target_url)

if __name__ == "__main__":
    main()
