import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

ADMIN_PATHS = [
    '/admin', '/administrator', '/admin.php', '/admin.html',
    '/wp-admin', '/wp-login.php', '/user/login', '/login',
    '/backend', '/manage', '/dashboard', '/control-panel',
    '/phpmyadmin', '/cpanel', '/administrator.php'
]

def find_admin(url):
    """Search for admin panels."""
    print(f"[*] Searching for admin panels on {url}")
    found = []
    
    for path in ADMIN_PATHS:
        test_url = urljoin(url, path)
        try:
            r = requests.get(test_url, timeout=3, allow_redirects=False)
            if r.status_code < 400:
                print(f"[+] Found: {test_url} (Status: {r.status_code})")
                found.append(test_url)
        except Exception:
            pass
    
    if not found:
        print("[-] No admin panels found.")

def main():
    parser = argparse.ArgumentParser(description="Find admin panels.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    find_admin(target)

if __name__ == "__main__":
    main()
