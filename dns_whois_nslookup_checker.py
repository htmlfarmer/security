import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import sys
try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:
    DNS_AVAILABLE = False
import argparse
from urllib.parse import urlparse

def get_dns_records(domain):
    """
    Retrieves common DNS records for a given domain, similar to nslookup.
    """
    print(f"\n[*] Performing DNS Lookup (NSLOOKUP) for {domain}...", flush=True)
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
    for r_type in record_types:
        if not DNS_AVAILABLE:
            print("  - DNS library not available (dnspython). Skipping DNS lookups.", flush=True)
            return
        try:
            answers = dns.resolver.resolve(domain, r_type)
            
            header = f"  --- {r_type} Records ---"
            if r_type == 'A':
                header = "  --- IP Address (A Record) ---"
            elif r_type == 'AAAA':
                header = "  --- IPv6 Address (AAAA Record) ---"
            
            print(header)
            for rdata in answers:
                print(f"    {rdata.to_text()}", flush=True)
        except dns.resolver.NoAnswer:
            # Only show output for records that are found to keep it clean.
            pass
        except dns.resolver.NXDOMAIN:
            print(f"  Error: The domain '{domain}' does not exist.")
            return
        except Exception as e:
            print(f"  Could not retrieve {r_type} records: {e}", flush=True)

def get_whois_info(domain):
    """
    Retrieves WHOIS information for a given domain.
    """
    print(f"[*] Querying WHOIS information for {domain}...", flush=True)
    try:
        if not WHOIS_AVAILABLE:
            print("  - WHOIS library not available. Falling back to system 'whois' command.", flush=True)
            # try system whois
            try:
                import subprocess
                proc = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if proc.stdout:
                    for line in proc.stdout:
                        print("    " + line.rstrip(), flush=True)
                proc.wait(timeout=30)
                return
            except Exception as ex:
                print(f"  - System whois failed: {ex}", flush=True)
                return
        # try multiple possible APIs offered by different whois packages
        try:
            if hasattr(whois, 'whois'):
                w = whois.whois(domain)
            elif hasattr(whois, 'query'):
                w = whois.query(domain)
            elif hasattr(whois, 'Whois'):
                w = whois.Whois(domain)
            else:
                # unknown whois module shape; fallback to system 'whois'
                import subprocess
                proc = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if proc.stdout:
                    for line in proc.stdout:
                        print("    " + line.rstrip(), flush=True)
                proc.wait(timeout=30)
                return
        except Exception as ex:
            # if python whois wrapper failed, fallback to system whois
            try:
                import subprocess
                proc = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if proc.stdout:
                    for line in proc.stdout:
                        print("    " + line.rstrip(), flush=True)
                proc.wait(timeout=30)
                return
            except Exception as ex2:
                print(f"  - WHOIS lookups failed: {ex} / {ex2}", flush=True)
                return
        
        # Normalize and print WHOIS info whether `w` is an object or dict
        def get_field(obj, name):
            if obj is None: return None
            # dict-like
            if isinstance(obj, dict):
                return obj.get(name)
            # object-like
            return getattr(obj, name, None)

        domain_name = get_field(w, 'domain_name')
        if not w or not domain_name:
            print("  - WHOIS lookup returned no structured data; printing raw representation:", flush=True)
            # try to extract any useful textual representation
            try:
                if hasattr(w, 'text') and w.text:
                    print(w.text, flush=True)
                elif hasattr(w, 'raw') and w.raw:
                    print(w.raw, flush=True)
                else:
                    # try to dump __dict__ if present
                    if hasattr(w, '__dict__') and w.__dict__:
                        for k, v in w.__dict__.items():
                            print(f"  - {k}: {v}", flush=True)
                    else:
                        print(str(w), flush=True)
            except Exception:
                try:
                    print(repr(w), flush=True)
                except Exception:
                    print(str(w), flush=True)
            return

        # Fields to attempt to print
        attributes_to_print = [
            'registrar', 'whois_server', 'creation_date', 'expiration_date',
            'updated_date', 'name_servers', 'status', 'dnssec',
            'name', 'org', 'address', 'city', 'state', 'zipcode', 'country',
            'phone', 'emails'
        ]

        print("  --- Detailed WHOIS Information ---", flush=True)
        found_info = False
        for attr in attributes_to_print:
            value = get_field(w, attr)
            if value:
                found_info = True
                if isinstance(value, list):
                    value = ', '.join(map(str, value))
                print(f"  - {attr.replace('_', ' ').title()}: {value}", flush=True)

        if not found_info:
            print("  - No detailed WHOIS fields could be extracted, but a basic record was found.", flush=True)

    except Exception as e:
        print(f"  - Error retrieving WHOIS info: {e}", flush=True)
        print("  - This can happen if the TLD is not supported, due to network issues, or if the 'whois' package is not installed on your system.", flush=True)

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

    try:
        get_whois_info(domain)
    except Exception as e:
        print(f"[!] WHOIS step failed: {e}", flush=True)
    try:
        get_dns_records(domain)
    except Exception as e:
        print(f"[!] DNS lookup step failed: {e}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('\n[!] Interrupted by user', flush=True)
    except Exception as e:
        print(f"[!] Unexpected error: {e}", flush=True)
        sys.exit(1)
