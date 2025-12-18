import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

# Small list of libraries and minimum safe version heuristics (very conservative)
LIB_SIGNATURES = {
    'jquery': {
        'regex': re.compile(r'jquery[-\.]?(\d+\.\d+\.\d+)'),
        'min_version': (3, 5, 0)
    },
    'bootstrap': {
        'regex': re.compile(r'bootstrap[-\.]?(\d+\.\d+\.\d+)'),
        'min_version': (4, 5, 0)
    },
    'react': {
        'regex': re.compile(r'react[-\.]?(\d+\.\d+\.\d+)'),
        'min_version': (16, 8, 0)
    },
    'vue': {
        'regex': re.compile(r'vue(?:\.runtime)?[-\.]?(\d+\.\d+\.\d+)'),
        'min_version': (2, 6, 0)
    },
    'angular': {
        'regex': re.compile(r'angular(?:\.js)?[-\.]?(\d+\.\d+\.\d+)'),
        'min_version': (1, 7, 0)
    }
}

def parse_version_tuple(vstr):
    parts = re.findall(r'\d+', vstr)
    return tuple(int(p) for p in parts[:3]) if parts else ()

def is_older(found, minimum):
    if not found or not minimum:
        return False
    f = parse_version_tuple(found)
    return f < minimum

def find_assets(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return []

    soup = BeautifulSoup(r.text, 'lxml')
    assets = []
    for tag in soup.find_all(['script', 'link']):
        src = tag.get('src') or tag.get('href')
        if src:
            full = urljoin(url, src)
            assets.append(full)
    return list(dict.fromkeys(assets))  # preserve order, dedupe

def scan_assets_for_libs(assets):
    findings = []
    for a in assets:
        for lib, meta in LIB_SIGNATURES.items():
            m = meta['regex'].search(a)
            if m:
                ver = m.group(1)
                older = is_older(ver, meta['min_version'])
                findings.append({
                    'library': lib,
                    'version': ver,
                    'asset': a,
                    'older': older
                })
    return findings

def main():
    parser = argparse.ArgumentParser(description="Scan a page's assets to detect frontend libraries and versions.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()

    target = args.url if '://' in args.url else 'http://' + args.url
    print(f"[*] Scanning assets on {target} ...")
    assets = find_assets(target)
    if not assets:
        print("[-] No assets found or page could not be fetched.")
        return

    findings = scan_assets_for_libs(assets)
    if findings:
        print("[+] Detected frontend libraries:")
        for f in findings:
            status = "OUTDATED" if f['older'] else "OK"
            note = "  -- Potentially vulnerable (old version)" if f['older'] else ""
            print(f"  - {f['library']} {f['version']} (source: {f['asset']}) [{status}]{note}")
    else:
        print("[-] No known libraries/versions detected from asset URLs.")

if __name__ == "__main__":
    main()
