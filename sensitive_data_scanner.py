import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re

PATTERNS = {
    'AWS Access Key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'Google API Key': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'JWT token-like': re.compile(r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    'Private Key Block': re.compile(r'-----BEGIN (?:RSA|PRIVATE) KEY-----'),
    'Email': re.compile(r'[a-zA-Z0-9.\-_]+@[a-zA-Z0-9\-_]+\.[a-zA-Z]{2,}'),
    'Possible Secret var': re.compile(r'(?:api[_-]?key|secret|password|token)[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9\-\._=+/]{8,})', re.IGNORECASE)
}

MAX_JS_FILES = 10
SNIPPET_LEN = 120

def fetch_text(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.text
    except Exception:
        return ''

def collect_js_urls(base_url, html):
    soup = BeautifulSoup(html, 'lxml')
    urls = []
    for s in soup.find_all('script', src=True):
        urls.append(urljoin(base_url, s['src']))
        if len(urls) >= MAX_JS_FILES:
            break
    return urls

def scan_text_for_patterns(text):
    results = []
    for name, pat in PATTERNS.items():
        for m in pat.finditer(text):
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            snippet = text[start:end].replace('\n', ' ')
            results.append({'type': name, 'match': m.group(0), 'snippet': snippet[:SNIPPET_LEN]})
    return results

def main():
    parser = argparse.ArgumentParser(description="Scan page and linked JS for exposed secrets and sensitive data.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()

    target = args.url if '://' in args.url else 'http://' + args.url
    print(f"[*] Scanning {target} for sensitive data (this is read-only)...")
    page_text = fetch_text(target)
    if not page_text:
        print("[-] Could not fetch target page.")
        return

    findings = scan_text_for_patterns(page_text)
    js_urls = collect_js_urls(target, page_text)
    for js in js_urls:
        js_text = fetch_text(js)
        if js_text:
            findings += scan_text_for_patterns(js_text)

    if findings:
        print("[+] Potential sensitive data found:")
        for f in findings:
            print(f"  - {f['type']}: {f['match']}")
            print(f"      Snippet: {f['snippet']}")
    else:
        print("[-] No obvious sensitive patterns were found (this is not exhaustive).")

if __name__ == "__main__":
    main()
