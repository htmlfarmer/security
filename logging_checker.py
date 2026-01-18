#!/usr/bin/env python3
"""logging_checker.py
External checks for error disclosures or lack of basic monitoring indicators.
"""
import requests
import argparse
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

ERROR_PATTERNS = ['Traceback', 'Stack trace', 'Exception', 'Fatal error', 'Warning:', 'at line']

def main():
    p = argparse.ArgumentParser(description='Check pages for error disclosures and security.txt presence')
    p.add_argument('url')
    args = p.parse_args()
    base = args.url if '://' in args.url else 'http://' + args.url
    try:
        r = requests.get(base, timeout=8, verify=False)
        r.raise_for_status()
    except Exception as e:
        print(f"Error fetching page: {e}")
        return
    findings = []
    for pat in ERROR_PATTERNS:
        if pat in r.text:
            findings.append(f"Error disclosure pattern found: {pat}")
    # check security.txt
    try:
        s = requests.get(base.rstrip('/') + '/.well-known/security.txt', timeout=5, verify=False)
        if s.status_code == 200:
            findings.append('security.txt present')
    except Exception:
        pass

    if findings:
        print('Logging/monitoring findings:')
        for f in findings:
            print(' -', f)
    else:
        print('No obvious error disclosures or security.txt found.')

if __name__ == '__main__':
    main()
