import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import whois
import dns.resolver
import argparse
from urllib.parse import urlparse

def get_dns_records(domain):
    """
    Retrieves common DNS records for a given domain, similar to nslookup.
    """
    print(f"\n[*] Performing DNS Lookup (NSLOOKUP) for {domain}...")
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    for r_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            
            header = f"  --- {r_type} Records ---"
            if r_type == 'A':
                header = "  --- IP Address (A Record) ---"
            elif r_type == 'AAAA':
                header = "  --- IPv6 Address (AAAA Record) ---"
            
            print(header)
            for rdata in answers:
                print(f"    {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            # Only show output for records that are found to keep it clean.
            pass
        except dns.resolver.NXDOMAIN:
            print(f"  Error: The domain '{domain}' does not exist.")
            return
        except Exception as e:
            print(f"  Could not retrieve {r_type} records: {e}")

def get_whois_info(domain):
    """
    Retrieves WHOIS information for a given domain.
    """
    print(f"[*] Querying WHOIS information for {domain}...")
    try:
        w = whois.whois(domain)
        
        # Check if the query returned a valid object with a domain name
        if not w or not w.domain_name:
            print("  - WHOIS lookup failed. The domain may not exist or the WHOIS server is unavailable.")
            return

        # Check for signs of privacy protection or parsing failure
        if not w.registrar:
            print("  - Could not parse WHOIS details automatically. The domain likely has privacy protection enabled.")
            return

        # An expanded list of attributes to find detailed contact information.
        attributes_to_print = [
            'registrar', 'whois_server', 'creation_date', 'expiration_date', 
            'updated_date', 'name_servers', 'status', 'dnssec',
            # Registrant contact info
            'name', 'org', 'address', 'city', 'state', 'zipcode', 'country',
            'phone', 'emails'
        ]

        print("  --- Detailed WHOIS Information ---")
        found_info = False
        for attr in attributes_to_print:
            value = getattr(w, attr, None)
            if value:
                found_info = True
                # Format list values for cleaner output
                if isinstance(value, list):
                    value = ', '.join(map(str, value))
                print(f"  - {attr.replace('_', ' ').title()}: {value}")
        
        if not found_info:
            print("  - No detailed WHOIS fields could be extracted, but a basic record was found.")

    except Exception as e:
        print(f"  - Error retrieving WHOIS info: {e}")
        print("  - This can happen if the TLD is not supported, due to network issues, or if the 'whois' command-line tool is not installed on your system.")

def main():
    parser = argparse.ArgumentParser(description="Perform DNS, WHOIS, and NSLOOKUP lookups for a domain.")
    parser.add_argument("url", help="The target URL or domain (e.g., https://example.com or example.com)")
    args = parser.parse_args()

    raw_input = args.url
    
    # Prepend '//' if the scheme is missing to help urlparse correctly identify the domain part
    if '://' not in raw_input:
        raw_input = '//' + raw_input
        
    domain = urlparse(raw_input).netloc

    if not domain:
        print(f"Error: Could not parse a valid domain from '{args.url}'")
        return

    # Clean up the domain
    if ':' in domain:
        domain = domain.split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]

    get_whois_info(domain)
    get_dns_records(domain)

if __name__ == "__main__":
    main()
