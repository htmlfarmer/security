import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import argparse
import requests
from urllib.parse import urlparse
from suggestions import print_suggestions

requests.packages.urllib3.disable_warnings()

SUSPICIOUS_KEYWORDS = ['admin', 'wp-', '.git', '.env', 'backup', 'config', 'db', 'login', 'private', 'staging', 'test']

def analyze_robots(url):
    parsed = urlparse(url if '://' in url else 'http://' + url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        r = requests.get(robots_url, timeout=8)
        if r.status_code != 200 or not r.text.strip():
            print(f"[-] robots.txt not found at {robots_url}")
            return

        print(f"[*] Found robots.txt at {robots_url}")
        lines = [line.strip() for line in r.text.splitlines() if line.strip() and not line.strip().startswith('#')]

        disallows = []
        allows = []
        sitemaps = []
        for line in lines:
            lower = line.lower()
            if lower.startswith('disallow:'):
                path = line.split(':',1)[1].strip()
                disallows.append(path)
            elif lower.startswith('allow:'):
                path = line.split(':',1)[1].strip()
                allows.append(path)
            elif lower.startswith('sitemap:'):
                sm = line.split(':',1)[1].strip()
                sitemaps.append(sm)

        if sitemaps:
            print("[+] robots.txt Sitemap entries:")
            for s in sitemaps:
                print(f"  - {s}")

        if disallows:
            print(f"[+] robots.txt Disallow entries ({len(disallows)}):")
            for p in disallows:
                print(f"  - {p}")
            suspicious = [p for p in disallows if any(k in p.lower() for k in SUSPICIOUS_KEYWORDS)]
            if suspicious:
                finding = "robots.txt contains disallowed paths that may expose sensitive endpoints"
                print(f"[!] {finding}:")
                for s in suspicious:
                    print(f"    - {s}")
                print_suggestions(finding)
        else:
            print("[+] robots.txt present but no Disallow entries found.")

        if allows:
            print(f"[+] robots.txt Allow entries ({len(allows)}):")
            for p in allows:
                print(f"  - {p}")

    except requests.RequestException as e:
        print(f"[-] Could not fetch robots.txt ({robots_url}): {e}")

def main():
    import sys
    parser = argparse.ArgumentParser(description="Fetch and analyze robots.txt for a target domain or URL.")
    parser.add_argument("target", help="Target URL or domain (e.g., example.com or https://example.com)")
    args = parser.parse_args()
    analyze_robots(args.target)

if __name__ == "__main__":
    main()
