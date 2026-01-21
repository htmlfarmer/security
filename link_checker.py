import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse

requests.packages.urllib3.disable_warnings()

def check_links(url):
    """
    Finds and checks all links on a given page for their status.
    Prints a concise summary and lists any broken or unreachable links.
    """
    print(f"[*] Checking for broken links on: {url}")
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'lxml')
        base_domain = urlparse(url).netloc

        # Collect unique internal links and external links, skipping fragments and non-HTTP schemes
        internal_links = []
        external_links = []
        seen_internal = set()
        base_root = base_domain.lower()
        if base_root.startswith('www.'):
            base_root = base_root[4:]

        for link in soup.find_all('a', href=True):
            href = link['href']
            # Skip fragment-only and unsupported schemes
            if href.startswith('#'):
                continue
            href_l = href.lower()
            if href_l.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
                continue

            full_url = urljoin(url, href)
            parsed = urlparse(full_url)
            netloc = parsed.netloc.lower().split(':')[0]

            # Treat as internal if host equals base root or is a subdomain of it
            if netloc == base_root or netloc.endswith('.' + base_root):
                if full_url not in seen_internal:
                    internal_links.append(full_url)
                    seen_internal.add(full_url)
            else:
                if full_url not in external_links:
                    external_links.append(full_url)

        if not internal_links:
            print("[-] No internal links found on the page.")
            if external_links:
                print(f"[i] Found {len(external_links)} external links (not checked):")
                for l in external_links[:10]:
                    print(f" - {l}")
            return

        if not internal_links:
            print("[-] No internal links found on the page.")
            return

        checked = 0
        broken = []
        unreachable = []

        checked_links = []
        for full_url in internal_links:
            checked += 1
            status_text = 'Unknown'
            try:
                # Use a HEAD request to be more efficient; fall back to GET if not allowed
                link_res = requests.head(full_url, timeout=5, allow_redirects=True)
                status = link_res.status_code
                if 400 <= status < 600:
                    broken.append((full_url, status))
                    status_text = f'Broken ({status})'
                else:
                    status_text = f'OK ({status})'
            except requests.RequestException:
                # Try GET as a fallback
                try:
                    link_res = requests.get(full_url, timeout=8, allow_redirects=True)
                    status = link_res.status_code
                    if 400 <= status < 600:
                        broken.append((full_url, status))
                        status_text = f'Broken ({status})'
                    else:
                        status_text = f'OK ({status})'
                except requests.RequestException:
                    unreachable.append(full_url)
                    status_text = 'Unreachable'
            checked_links.append((full_url, status_text))

        # Summary
        print(f"[*] Checked {checked} internal links:")
        for link, st in checked_links:
            print(f" - {link} => {st}")

        # Counts
        ok_count = sum(1 for _, st in checked_links if st.startswith('OK'))
        broken_count = len(broken)
        unreachable_count = len(unreachable)

        print(f"\n[*] Final counts: {checked} checked, {ok_count} OK, {broken_count} broken, {unreachable_count} unreachable")

        # Machine-readable summary for downstream processing or LLM parsing
        print(f"LINKS_SUMMARY: checked={checked} ok={ok_count} broken={broken_count} unreachable={unreachable_count}")

        if broken:
            print('\n[-] Broken links:')
            for b, code in broken:
                print(f" - {b} (Status: {code})")
        if unreachable:
            print('\n[-] Unreachable links:')
            for u in unreachable:
                print(f" - {u}")
        if not broken and not unreachable:
            print('\n[+] No broken or unreachable links were found.')

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
