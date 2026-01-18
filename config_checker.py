#!/usr/bin/env python3
"""config_checker.py
Quick checks for common misconfiguration exposures: /.git/HEAD, /.env, /phpinfo.php, /config.php
"""
import requests
import argparse
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

PATHS = ['/.git/HEAD', '/.env', '/phpinfo.php', '/config.php', '/.git/config']

def main():
    p = argparse.ArgumentParser(description='Check for exposed config files')
    p.add_argument('url')
    args = p.parse_args()
    base = args.url if '://' in args.url else 'http://' + args.url
    findings = []
    for path in PATHS:
        try:
            r = requests.get(urljoin(base, path), timeout=8, verify=False)
            if r.status_code == 200 and r.text.strip():
                findings.append(f"Accessible: {path} (HTTP 200)")
        except Exception:
            pass
    try:
        r = requests.get(urljoin(base, '/robots.txt'), timeout=5, verify=False)
        if r.status_code == 200 and 'Disallow' in r.text:
            findings.append('robots.txt present (may expose sensitive paths)')
    except Exception:
        pass

    if findings:
        print('Misconfiguration findings:')
        for f in findings:
            print(' -', f)
    else:
        print('No obvious exposed config files detected (HTTP checks only).')

if __name__ == '__main__':
    main()
