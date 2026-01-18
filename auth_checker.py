#!/usr/bin/env python3
"""auth_checker.py
Checks for obvious authentication issues: insecure cookie flags and presence of common login/admin endpoints.
"""
import requests
import argparse
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

COMMON_LOGIN_PATHS = ['/login', '/admin', '/wp-login.php', '/phpmyadmin', '/admin/login']

def check_cookies(url):
    try:
        r = requests.get(url, timeout=8, verify=False)
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []
    findings = []
    sc = r.headers.get('Set-Cookie')
    if sc:
        # multiple cookies may be set; check presence of Secure and HttpOnly
        parts = sc.split(',')
        for p in parts:
            if 'secure' not in p.lower():
                findings.append('Cookie without Secure flag: ' + p.split('=')[0].strip())
            if 'httponly' not in p.lower():
                findings.append('Cookie without HttpOnly flag: ' + p.split('=')[0].strip())
    return findings

def check_login_paths(base):
    found = []
    for p in COMMON_LOGIN_PATHS:
        try:
            r = requests.get(urljoin(base, p), timeout=6, verify=False, allow_redirects=True)
            if r.status_code == 200:
                found.append(f"Login/Admin page found: {p} (HTTP 200)")
        except Exception:
            pass
    return found

def main():
    p = argparse.ArgumentParser(description='Basic authentication checks')
    p.add_argument('url')
    args = p.parse_args()
    base = args.url if '://' in args.url else 'http://' + args.url
    findings = []
    findings += check_cookies(base)
    findings += check_login_paths(base)
    if findings:
        print('Authentication findings:')
        for f in findings:
            print(' -', f)
    else:
        print('No obvious authentication issues detected via basic checks.')

if __name__ == '__main__':
    main()
