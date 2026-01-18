#!/usr/bin/env python3
"""integrity_checker.py
Checks HTML assets for Subresource Integrity (SRI) attributes on <script> and <link> tags.
"""
import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

def main():
    p = argparse.ArgumentParser(description='Check for Subresource Integrity attributes on page assets')
    p.add_argument('url')
    args = p.parse_args()
    url = args.url if '://' in args.url else 'http://' + args.url
    try:
        r = requests.get(url, timeout=10, verify=False)
        r.raise_for_status()
    except Exception as e:
        print(f"Error fetching page: {e}")
        return
    soup = BeautifulSoup(r.text, 'lxml')
    findings = []
    for tag in soup.find_all(['script','link']):
        src = tag.get('src') or tag.get('href')
        if not src: continue
        if src.startswith('http'):
            integrity = tag.get('integrity')
            if not integrity:
                findings.append(f"Missing SRI for asset: {src}")
    if findings:
        print("Potential integrity issues:")
        for f in findings:
            print(' -', f)
    else:
        print('No missing SRI attributes detected (only checks external assets).')

if __name__ == '__main__':
    main()
