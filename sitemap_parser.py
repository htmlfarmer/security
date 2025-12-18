import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

requests.packages.urllib3.disable_warnings()

def parse_sitemap(url):
    """Fetch and parse sitemap.xml."""
    parsed = urlparse(url if '://' in url else 'http://' + url)
    sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
    try:
        r = requests.get(sitemap_url, timeout=8)
        if r.status_code != 200:
            print(f"[-] sitemap.xml not found at {sitemap_url}")
            return []
        
        print(f"[+] Found sitemap.xml at {sitemap_url}")
        root = ET.fromstring(r.content)
        urls = []
        for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}loc'):
            urls.append(url_elem.text)
        return urls
    except Exception as e:
        print(f"[-] Could not parse sitemap.xml: {e}")
        return []

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
