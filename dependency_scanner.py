import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

requests.packages.urllib3.disable_warnings()

# ANSI color codes (simple, no extra deps)
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"

def color(text: str, col: str) -> str:
    return f"{col}{text}{RESET}"

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
        print(color(f"Error fetching {url}: {e}", RED))
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
    print(color(f"[*] Scanning assets on {target} ...", CYAN))
    assets = find_assets(target)
    if not assets:
        print(color("[-] No assets found or page could not be fetched.", YELLOW))
        return

    findings = scan_assets_for_libs(assets)
    if findings:
        print(color("[+] Detected frontend libraries:", GREEN))
        for f in findings:
            status = "OUTDATED" if f['older'] else "OK"
            if f['older']:
                status_colored = color(status, RED + BOLD)
                note = color("  -- Potentially vulnerable (old version)", YELLOW)
                finding = f"OUTDATED: {f['library']} {f['version']}"
                print(f"  - {color(f['library'], MAGENTA)} {color(f['version'], CYAN)} (source: {f['asset']}) [{status_colored}]{note}")
            else:
                status_colored = color(status, GREEN)
                print(f"  - {color(f['library'], MAGENTA)} {color(f['version'], CYAN)} (source: {f['asset']}) [{status_colored}]")
    else:
        print(color("[-] No known libraries/versions detected from asset URLs.", YELLOW))

if __name__ == "__main__":
    main()
