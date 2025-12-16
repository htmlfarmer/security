import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

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
        'html': ['data-reactroot', 'data-reactid'],
        'headers': {},
        'cookies': [],
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
        print(f"Error: Could not connect to {url}. Details: {e}")
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

    print(f"[*] Analyzing {target_url}...")
    
    # Suppress InsecureRequestWarning for self-signed certs
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    
    technologies = check_technologies(target_url)
    
    if technologies:
        print("\n[+] Detected Technologies:")
        for tech in sorted(technologies):
            print(f"  - {tech}")
    else:
        print("\n[-] Could not identify any specific technologies.")

if __name__ == "__main__":
    main()
