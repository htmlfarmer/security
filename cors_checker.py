import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

def check_cors(url):
    """Check for CORS misconfigurations."""
    print(f"[*] Checking CORS headers on {url}")
    try:
        headers = {'Origin': 'https://attacker.com'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao:
            if acao == '*':
                finding = "VULNERABILITY: CORS allows all origins (*)"
                print(f"[-] {finding}")
                print_suggestions(finding)
            elif 'attacker.com' in acao:
                finding = "VULNERABILITY: CORS misconfigured (echoes origin)"
                print(f"[-] {finding}")
                print_suggestions(finding)
            else:
                print(f"[+] CORS configured: {acao}")
        else:
            print("[+] CORS not configured (restrictive by default)")
    
    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check CORS configuration.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    check_cors(target)

if __name__ == "__main__":
    main()
