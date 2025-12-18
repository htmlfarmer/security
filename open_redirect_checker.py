import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urljoin
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

def check_open_redirect(url):
    """Test for open redirect."""
    print(f"[*] Testing for open redirect on {url}")
    
    redirect_params = ['redirect', 'return', 'url', 'target', 'next', 'continue', 'go', 'back']
    redirect_url = 'https://attacker.com'
    
    try:
        for param in redirect_params:
            test_url = f"{url}?{param}={redirect_url}" if '?' not in url else f"{url}&{param}={redirect_url}"
            try:
                r = requests.get(test_url, allow_redirects=False, timeout=5, verify=False)
                if r.status_code in [301, 302, 303, 307, 308]:
                    location = r.headers.get('Location', '')
                    if 'attacker.com' in location:
                        finding = f"VULNERABILITY: Open redirect via {param} parameter"
                        print(f"[+] {finding}")
                        print_suggestions(finding)
            except Exception:
                pass
    
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Test for open redirect.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    check_open_redirect(target)

if __name__ == "__main__":
    main()
