import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

def check_cookies(url):
    """Inspect cookies for security attributes."""
    print(f"[*] Checking cookie attributes on {url}")
    try:
        response = requests.get(url, timeout=10, verify=False)
        cookies = response.cookies
        
        if not cookies:
            print("[-] No cookies found on the page.")
            return
        
        print(f"[+] Found {len(cookies)} cookie(s):")
        for cookie in cookies:
            print(f"\n  - {cookie.name}:")
            print(f"    Value: {cookie.value[:50]}..." if len(cookie.value) > 50 else f"    Value: {cookie.value}")
            
            issues = []
            if not cookie.secure:
                issues.append("Missing 'Secure' flag (cookie sent over HTTP)")
            if not cookie.has_nonscript_attr and cookie.name not in ['__Host-', '__Secure-']:
                issues.append("Missing 'HttpOnly' flag (accessible via JavaScript)")
            if not cookie.samesite:
                issues.append("Missing 'SameSite' attribute (vulnerable to CSRF)")
            
            if issues:
                for issue in issues:
                    finding = f"Cookie '{cookie.name}': {issue}"
                    print(f"    [!] {finding}")
                    print_suggestions(finding)
            else:
                print(f"    [+] All security attributes present")
    
    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check cookie security attributes.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    check_cookies(target)

if __name__ == "__main__":
    main()
