import requests
import argparse
from urllib.parse import urlparse

def enumerate_subdomains(domain):
    """
    Finds valid subdomains for a given domain from a predefined list.
    """
    print(f"[*] Starting subdomain enumeration for: {domain}")
    found_subdomains = []
    
    # A small list of common subdomains. This could be read from a large file.
    subdomain_list = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "admin", "test", "dev", "blog", "shop", "api", "vpn", "m", "portal", "cpanel"
    ]

    for sub in subdomain_list:
        sub_url = f"http://{sub}.{domain}"
        try:
            requests.get(sub_url, timeout=3, allow_redirects=False)
            print(f"[+] Found: {sub_url}")
            found_subdomains.append(sub_url)
        except requests.ConnectionError:
            pass
        except Exception as e:
            print(f"[-] An error occurred trying {sub_url}: {e}")
            
    return found_subdomains

def main():
    parser = argparse.ArgumentParser(description="Enumerate subdomains for a given URL.")
    parser.add_argument("url", help="The target URL (e.g., https://example.com)")
    args = parser.parse_args()

    try:
        domain = urlparse(args.url).netloc
        # Handle URLs with ports e.g. localhost:8000
        if ':' in domain:
            domain = domain.split(':')[0]
    except Exception as e:
        print(f"Error: Invalid URL provided. {e}")
        return

    found = enumerate_subdomains(domain)
    if not found:
        print("\n[-] No common subdomains found.")

if __name__ == "__main__":
    main()
