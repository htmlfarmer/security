import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

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
            
            # Robust attribute detection using cookie._rest / cookie.rest
            rest = {}
            if hasattr(cookie, 'rest') and isinstance(cookie.rest, dict):
                rest = cookie.rest
            elif hasattr(cookie, '_rest') and isinstance(cookie._rest, dict):
                rest = cookie._rest
            rest_l = {k.lower(): v for k, v in rest.items()}
            
            issues = []
            # Secure flag
            if not getattr(cookie, 'secure', False):
                issues.append("Missing 'Secure' flag (cookie sent over HTTP)")
            # HttpOnly: check presence in rest keys (case-insensitive)
            has_httponly = any(k for k in rest_l.keys() if k == 'httponly')
            if not has_httponly and not (cookie.name.startswith('__Host-') or cookie.name.startswith('__Secure-')):
                issues.append("Missing 'HttpOnly' flag (accessible via JavaScript)")
            # SameSite
            samesite = rest_l.get('samesite') or rest_l.get('same_site') or None
            if not samesite:
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
