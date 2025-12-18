import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

def scan_xss(url):
    """
    Scans a URL for forms and tests for basic reflected XSS vulnerabilities.
    """
    print(f"[*] Scanning for reflected XSS on {url}")
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'lxml')
        forms = soup.find_all('form')
        print(f"[*] Found {len(forms)} forms on the page.")

        xss_payload = "<script>alert('xss')</script>"
        vulnerable = False

        for form in forms:
            action = form.get('action')
            post_url = urljoin(url, action)
            method = form.get('method', 'get').lower()
            
            inputs = form.find_all(['input', 'textarea'])
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                if name:
                    if input_type == 'text':
                        data[name] = xss_payload
                    else:
                        data[name] = "test" # default value for other fields
            
            print(f"[*] Testing form with action: {post_url}")
            try:
                if method == 'post':
                    res = requests.post(post_url, data=data, timeout=10)
                else:
                    res = requests.get(post_url, params=data, timeout=10)
                
                if xss_payload in res.text:
                    finding = f"VULNERABILITY: Reflected XSS found in form at {post_url}"
                    print(f"[+] {finding}")
                    print_suggestions(finding)
                    vulnerable = True
            except requests.RequestException as e:
                print(f"[-] Failed to submit form to {post_url}: {e}")

        if not vulnerable and forms:
            print("[-] No simple reflected XSS vulnerabilities found in forms.")
        elif not forms:
            print("[-] No forms found to test.")

    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")

def main():
    parser = argparse.ArgumentParser(description="Basic Reflected XSS scanner for forms.")
    parser.add_argument("url", help="The target URL or domain to scan (e.g., example.com).")
    args = parser.parse_args()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url
        
    scan_xss(target_url)

if __name__ == "__main__":
    main()
