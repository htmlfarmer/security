import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse, urljoin
import sys
import xml.etree.ElementTree as ET
import os
import re
import tempfile
from collections import deque
import xml.dom.minidom as minidom

requests.packages.urllib3.disable_warnings()

def parse_sitemap(url):
    """Fetch and parse sitemap.xml."""
    parsed = urlparse(url if '://' in url else 'http://' + url)
    sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
    try:
        r = requests.get(sitemap_url, timeout=8)
        if r.status_code != 200:
            print(f"[-] sitemap.xml not found at {sitemap_url}")
            # attempt to generate a sitemap by crawling the site
            generated = generate_sitemap(parsed.scheme + '://' + parsed.netloc)
            return generated

        print(f"[+] Found sitemap.xml at {sitemap_url}")
        root = ET.fromstring(r.content)
        urls = []
        # stream each found URL as we parse
        for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
            u = url_elem.text
            urls.append(u)
            print(f"  - {u}")
            sys.stdout.flush()
        return urls
    except Exception as e:
        print(f"[-] Could not parse sitemap.xml: {e}")
        # fallback: try to generate
        try:
            generated = generate_sitemap(parsed.scheme + '://' + parsed.netloc)
            return generated
        except Exception as ex:
            print(f"[-] Sitemap generation failed: {ex}")
            return []


def generate_sitemap(base_url, max_urls=200):
    """Simple site crawler to generate a sitemap.xml file for the given base URL.

    This is a best-effort generator that follows internal links and writes
    a sitemap XML file to ./generated_sitemaps/<host>.xml. It does not
    execute javascript and is intended as a helpful fallback when no
    sitemap.xml is present.
    """
    parsed = urlparse(base_url if '://' in base_url else 'http://' + base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    seen = set()
    urls = []
    q = deque([base])
    link_re = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

    # print XML header and opening tag for streaming output
    print('<?xml version="1.0" ?>')
    print('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    sys.stdout.flush()

    while q and len(urls) < max_urls:
        cur = q.popleft()
        if cur in seen: continue
        seen.add(cur)
        try:
            r = requests.get(cur, timeout=6, allow_redirects=True)
            if r.status_code != 200:
                continue
            # record canonical URL
            urls.append(cur)
            # stream discovered URL as plain list item
            print(f"  - {cur}")
            # also stream XML element for this URL
            print(f"  <url>\n    <loc>{cur}</loc>\n  </url>")
            sys.stdout.flush()
            # avoid requests' slow charset detection on large pages
            try:
                html = r.content.decode('utf-8', errors='replace')
            except Exception:
                html = r.text
            for m in link_re.findall(html):
                href = m.strip()
                if href.startswith('#') or href.lower().startswith('mailto:') or href.lower().startswith('javascript:'):
                    continue
                if href.startswith('//'):
                    candidate = parsed.scheme + ':' + href
                elif href.startswith('http://') or href.startswith('https://'):
                    candidate = href
                else:
                    candidate = urljoin(cur, href)
                try:
                    cand_parsed = urlparse(candidate)
                    if cand_parsed.netloc != parsed.netloc:
                        continue
                    # normalize (strip fragments)
                    candidate = candidate.split('#')[0]
                    if candidate not in seen and candidate not in q and len(urls) + len(q) < max_urls:
                        q.append(candidate)
                except Exception:
                    continue
        except Exception:
            continue

    # close the urlset tag
    print('</urlset>')
    print(f"[+] Generated sitemap with {len(urls)} URL(s)")
    sys.stdout.flush()
    return urls
    return urls

def main():
    parser = argparse.ArgumentParser(description="Parse robots.txt and sitemap.xml for endpoints.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    target = args.url if '://' in args.url else 'http://' + args.url
    
    urls = parse_sitemap(target)
    if urls:
        print(f"[+] Found {len(urls)} URL(s) in sitemap.xml:")
        for u in urls[:20]:  # Show first 20
            print(f"  - {u}")
        if len(urls) > 20:
            print(f"  ... and {len(urls)-20} more")

if __name__ == "__main__":
    main()
