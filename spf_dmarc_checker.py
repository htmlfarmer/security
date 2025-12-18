import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import dns.resolver
import argparse
from urllib.parse import urlparse
from suggestions import print_suggestions

def check_spf_dmarc(domain):
    """Check for SPF and DMARC DNS records."""
    print(f"[*] Checking SPF/DMARC records for {domain}")
    
    try:
        # Check SPF
        print("[*] Checking SPF record...")
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            for rdata in spf_records:
                txt = rdata.to_text()
                if 'v=spf1' in txt:
                    print(f"[+] SPF record found: {txt}")
                    spf_found = True
            if not spf_found:
                finding = "Missing SPF record (domain vulnerable to email spoofing)"
                print(f"[-] {finding}")
                print_suggestions(finding)
        except dns.resolver.NXDOMAIN:
            print(f"[-] Domain {domain} does not exist")
            return
        except Exception:
            finding = "Missing SPF record (domain vulnerable to email spoofing)"
            print(f"[-] {finding}")
            print_suggestions(finding)
        
        # Check DMARC
        print("[*] Checking DMARC record...")
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_records:
                txt = rdata.to_text()
                if 'v=DMARC1' in txt:
                    print(f"[+] DMARC record found: {txt}")
        except Exception:
            finding = "Missing DMARC record (domain vulnerable to email spoofing)"
            print(f"[-] {finding}")
            print_suggestions(finding)
    
    except Exception as e:
        print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Check SPF and DMARC DNS records.")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    args = parser.parse_args()
    
    raw = args.url
    if '://' not in raw:
        raw = '//' + raw
    domain = urlparse(raw).netloc
    if ':' in domain:
        domain = domain.split(':')[0]
    
    check_spf_dmarc(domain)

if __name__ == "__main__":
    main()
