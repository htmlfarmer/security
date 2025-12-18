import warnings
import sys

# Suppress all warnings early, before importing requests
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

# Extra suppression for requests/urllib3
requests.packages.urllib3.disable_warnings()

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

def color(text: str, col: str) -> str:
    return f"{col}{text}{RESET}"

# Define technology signatures
# This can be expanded significantly.
TECHNOLOGY_SIGNATURES = {
    # CMS & Frameworks
    'WordPress': {
        'html': ['/wp-content/', '/wp-includes/', '<meta name="generator" content="WordPress'],
        'headers': {},
        'cookies': ['wp-settings-', 'wordpress_logged_in'],
        'robots': ['/wp-admin/']
    },
    'Joomla': {
        'html': ['<meta name="generator" content="Joomla!'],
        'headers': {},
        'cookies': [],
        'robots': ['/administrator/']
    },
    'Drupal': {
        'html': ['/sites/default/files/', 'Drupal.settings'],
        'headers': {'X-Generator': 'Drupal'},
        'cookies': ['has_js'],
        'robots': []
    },
    'Shopify': {
        'html': ['cdn.shopify.com'],
        'headers': {'X-Shopify-Stage': ''},
        'cookies': [],
        'robots': []
    },
    'Next.js': {
        'html': ['/_next/static/'],
        'headers': {'X-Powered-By': 'Next.js'},
        'cookies': [],
        'robots': []
    },
    'React': {
        'html': ['data-reactroot', 'data-reactid', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
        'headers': {},
        'cookies': [],
        'robots': []
    },
    'Vue.js': {
        'html': ['data-v-', '<!--vue-ssr-outlet-->', '<div id="app">', '__VUE_DEVTOOLS_GLOBAL_HOOK__'],
        'headers': {},
        'cookies': [],
        'robots': []
    },
    'Ruby on Rails': {
        'html': ['<meta name="csrf-param" content="authenticity_token"'],
        'headers': {'X-Runtime': ''},
        'cookies': ['_rails_session_id'],
        'robots': []
    },
    # Web Servers
    'Nginx': {
        'html': [],
        'headers': {'Server': 'nginx'},
        'cookies': [],
        'robots': []
    },
    'Apache': {
        'html': [],
        'headers': {'Server': 'Apache'},
        'cookies': [],
        'robots': []
    },
    'Cloudflare': {
        'html': [],
        'headers': {'Server': 'cloudflare'},
        'cookies': ['__cfduid', '__cf_bm'],
        'robots': []
    },
    # Languages
    'PHP': {
        'html': ['.php'],
        'headers': {'X-Powered-By': 'PHP', 'Set-Cookie': 'PHPSESSID'},
        'cookies': ['PHPSESSID'],
        'robots': []
    },
    'ASP.NET': {
        'html': ['.aspx', '__VIEWSTATE'],
        'headers': {'X-Powered-By': 'ASP.NET', 'X-AspNet-Version': ''},
        'cookies': ['ASP.NET_SessionId'],
        'robots': []
    }
}

# Known latest versions (update periodically)
KNOWN_LATEST_VERSIONS = {
    'jquery': '3.7.1',
    'bootstrap': '5.3.2',
    'react': '18.2.0',
    'vue': '3.3.4',
    'angular': '17.0.0',
}

def parse_version_tuple(vstr):
    """Convert version string to tuple for comparison."""
    parts = re.findall(r'\d+', vstr)
    return tuple(int(p) for p in parts[:3]) if parts else ()

def is_outdated(found_version, latest_version):
    """Compare two version strings."""
    if not found_version or not latest_version:
        return False
    return parse_version_tuple(found_version) < parse_version_tuple(latest_version)

def extract_versions_from_html(html_content):
    """Extract library versions from HTML script/link tags."""
    versions = {}
    soup = BeautifulSoup(html_content, 'lxml')
    
    # Check for version patterns in script and link tags
    for tag in soup.find_all(['script', 'link']):
        src = tag.get('src') or tag.get('href') or ''
        
        # jQuery
        if 'jquery' in src.lower():
            m = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', src, re.IGNORECASE)
            if m:
                versions['jquery'] = m.group(1)
        
        # Bootstrap
        if 'bootstrap' in src.lower():
            m = re.search(r'bootstrap[.-]?(\d+\.\d+\.\d+)', src, re.IGNORECASE)
            if m:
                versions['bootstrap'] = m.group(1)
        
        # React
        if 'react' in src.lower():
            m = re.search(r'react[.-]?(\d+\.\d+\.\d+)', src, re.IGNORECASE)
            if m:
                versions['react'] = m.group(1)
        
        # Vue
        if 'vue' in src.lower():
            m = re.search(r'vue[.-]?(\d+\.\d+\.\d+)', src, re.IGNORECASE)
            if m:
                versions['vue'] = m.group(1)
        
        # Angular
        if 'angular' in src.lower():
            m = re.search(r'angular[.-]?(\d+\.\d+\.\d+)', src, re.IGNORECASE)
            if m:
                versions['angular'] = m.group(1)
    
    return versions

def check_technology_versions(url):
    """Detect technologies and check their versions against known latest."""
    print(color(f"[*] Checking technology versions on {url}", CYAN))
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        html_content = response.text
        
        versions = extract_versions_from_html(html_content)
        
        if versions:
            print(color("[+] Detected library versions:", GREEN))
            for lib, version in versions.items():
                latest = KNOWN_LATEST_VERSIONS.get(lib, "unknown")
                if latest != "unknown" and is_outdated(version, latest):
                    status = color(f"OUTDATED (latest: {latest})", RED + BOLD)
                    print(f"  - {color(lib, CYAN)}: {color(version, YELLOW)} [{status}]")
                elif latest != "unknown":
                    status = color("UP-TO-DATE", GREEN)
                    print(f"  - {color(lib, CYAN)}: {color(version, GREEN)} [{status}]")
                else:
                    print(f"  - {color(lib, CYAN)}: {color(version, CYAN)} [version unknown]")
        else:
            print(color("[-] No versioned libraries detected in asset URLs.", YELLOW))
    
    except requests.RequestException as e:
        print(color(f"Error: Could not connect to {url}. Details: {e}", RED))

def check_technologies(url):
    """
    Analyzes a URL to identify its technology stack.
    """
    detected_tech = set()
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Get content, headers, and cookies
        html_content = response.text
        response_headers = response.headers
        response_cookies = response.cookies.get_dict()
        
        # --- Start Checking ---
        for tech, signatures in TECHNOLOGY_SIGNATURES.items():
            # 1. Check Headers
            for header, value in signatures.get('headers', {}).items():
                if header in response_headers:
                    if not value or value.lower() in response_headers[header].lower():
                        detected_tech.add(tech)

            # 2. Check HTML content
            for snippet in signatures.get('html', []):
                if snippet.lower() in html_content.lower():
                    detected_tech.add(tech)
            
            # 3. Check Cookies
            for cookie_name in signatures.get('cookies', []):
                for key in response_cookies.keys():
                    if cookie_name.lower() in key.lower():
                        detected_tech.add(tech)

        # 4. Check robots.txt (if it exists)
        robots_url = urljoin(url, '/robots.txt')
        try:
            robots_response = requests.get(robots_url, headers=headers, timeout=5, verify=False)
            if robots_response.status_code == 200:
                robots_content = robots_response.text
                for tech, signatures in TECHNOLOGY_SIGNATURES.items():
                    for path in signatures.get('robots', []):
                        if path.lower() in robots_content.lower():
                            detected_tech.add(tech)
        except requests.RequestException:
            pass # Ignore if robots.txt is not found or fails to load

    except requests.RequestException as e:
        print(color(f"Error: Could not connect to {url}. Details: {e}", RED))
        return []

    return list(detected_tech)

def main():
    parser = argparse.ArgumentParser(description="Identify web technologies for a given URL.")
    parser.add_argument("url", help="The target URL to analyze (e.g., https://example.com)")
    args = parser.parse_args()
    
    # Ensure URL has a scheme
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme:
        target_url = "http://" + args.url
    else:
        target_url = args.url

    print(color(f"[*] Analyzing {target_url}...", CYAN))
    
    # Suppress InsecureRequestWarning for self-signed certs
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    # Check technologies
    technologies = check_technologies(target_url)
    
    if technologies:
        print(color("\n[+] Detected Technologies:", GREEN))
        for tech in sorted(technologies):
            print(f"  - {tech}")
    else:
        print(color("\n[-] Could not identify any specific technologies.", YELLOW))
    
    # Check specific library versions
    print()
    check_technology_versions(target_url)

if __name__ == "__main__":
    main()
