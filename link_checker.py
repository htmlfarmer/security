import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse

def check_links(url):
    """
    Finds and checks all links on a given page for their status.
    """
    print(f"[*] Checking for broken links on: {url}")
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'lxml')
        base_domain = urlparse(url).netloc

        for link in soup.find_all('a', href=True):
            href = link['href']
            # Resolve relative URLs
            full_url = urljoin(url, href)
            
            # Optional: only check internal links to avoid crawling the web
            if urlparse(full_url).netloc != base_domain:
                continue

            try:
                # Use a HEAD request to be more efficient
                link_res = requests.head(full_url, timeout=5, allow_redirects=True)
                if 400 <= link_res.status_code < 600:
                    print(f"[-] Broken Link Found: {full_url} (Status: {link_res.status_code})")
            except requests.RequestException:
                print(f"[-] Unreachable Link Found: {full_url}")
    
    except requests.RequestException as e:
        print(f"Error: Could not connect to {url}. Details: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check for broken links on a webpage.")
    parser.add_argument("url", help="The target URL or domain to check (e.g., example.com).")
    args = parser.parse_args()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    check_links(target_url)

if __name__ == "__main__":
    main()
