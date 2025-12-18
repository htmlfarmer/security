import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

COMMON_DIRS = [
    'admin', 'backup', 'config', 'uploads', 'files', 'download',
    'includes', 'lib', 'src', 'api', 'v1', 'v2', 'test', 'staging',
    'private', 'secret', 'hidden', '.git', '.env', 'web.config'
]

def dirbust(url):
    """Brute-force common directories."""
    print(f"[*] Scanning for common directories on {url}")
    found = []
    
    for directory in COMMON_DIRS:
        test_url = urljoin(url, f"/{directory}")
        try:
            r = requests.head(test_url, timeout=3, allow_redirects=False)
            if r.status_code < 400:
                print(f"[+] Found: {test_url} (Status: {r.status_code})")
                found.append(test_url)
        except Exception:
            pass
    
    if not found:
        print("[-] No common directories found.")

def main():
    parser = argparse.ArgumentParser(description="Brute-force common directories.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    dirbust(target)

if __name__ == "__main__":
    main()
