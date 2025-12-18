import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cf-request-id', 'cloudflare'],
    'AWS WAF': ['x-amzn-waf-action', 'x-amzn-requestid'],
    'ModSecurity': ['modsecurity'],
    'Akamai': ['akamai-origin-hop'],
    'F5 BIG-IP': ['bigipserver'],
    'Imperva': ['x-iinfo', '_Incap_Session'],
}

def detect_waf(url):
    """Detect presence of WAF."""
    print(f"[*] Checking for WAF on {url}")
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        cookies = response.cookies.get_dict()
        
        detected_waf = set()
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                sig_lower = sig.lower()
                for header_val in [h.lower() for h in headers.values()]:
                    if sig_lower in header_val:
                        detected_waf.add(waf_name)
                for cookie_val in [c.lower() for c in cookies.values()]:
                    if sig_lower in cookie_val:
                        detected_waf.add(waf_name)
        
        if detected_waf:
            print(f"[+] Detected WAF(s): {', '.join(detected_waf)}")
        else:
            print("[-] No common WAF signatures detected")
    
    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")

def main():
    parser = argparse.ArgumentParser(description="Detect WAF presence.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    detect_waf(target)

if __name__ == "__main__":
    main()
