import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

def check_http_methods(url):
    """Check allowed HTTP methods."""
    print(f"[*] Checking HTTP methods on {url}")
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'CONNECT']
    allowed = []
    
    try:
        for method in methods:
            try:
                r = requests.request(method, url, timeout=3)
                if r.status_code != 405:  # 405 Method Not Allowed
                    allowed.append(method)
                    print(f"[+] {method}: Allowed (Status: {r.status_code})")
            except Exception:
                pass
        
        if 'PUT' in allowed or 'DELETE' in allowed or 'TRACE' in allowed:
            finding = "VULNERABILITY: Dangerous HTTP methods allowed"
            print(f"[-] {finding}")
            print_suggestions(finding)
    
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check allowed HTTP methods.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    check_http_methods(target)

if __name__ == "__main__":
    main()
