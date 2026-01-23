import argparse
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By

import os
import tempfile
import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def setup_driver():
    """Sets up the Selenium WebDriver.

    Uses a temporary cache location and configures the browser to accept
    insecure certificates so sites with TLS issues don't immediately fail.
    """
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    # Accept insecure certs (useful for scanning dev sites or sites with cert problems)
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--allow-insecure-localhost")
    options.set_capability('acceptInsecureCerts', True)
    
    # Use a temporary, writable directory for the user data cache and also set XDG cache
    user_data_dir = os.path.join(tempfile.gettempdir(), 'selenium_cache')
    os.makedirs(user_data_dir, exist_ok=True)
    os.environ['XDG_CACHE_HOME'] = tempfile.gettempdir()
    options.add_argument(f"--user-data-dir={user_data_dir}")

    # Selenium Manager will handle the driver automatically; provide helpful errors
    try:
        return webdriver.Chrome(options=options)
    except Exception as e:
        print("[-] Could not start Selenium Chrome driver:", e)
        print("    * Ensure Chrome and ChromeDriver are compatible and available on PATH.")
        print("    * Ensure the process has write access to the cache/user-data directories or set XDG_CACHE_HOME to a writable dir.")
        return None

def _fallback_check_insecure_forms(url):
    """Fallback implementation using requests + BeautifulSoup when Selenium fails."""
    print("[*] Falling back to non-JS HTML parsing (requests/BeautifulSoup)")
    try:
        r = requests.get(url, verify=False, timeout=12)
        soup = BeautifulSoup(r.text, 'lxml')
        forms = soup.find_all('form')
        if not forms:
            print("[-] No forms found on the page (fallback).")
            return
        for i, form in enumerate(forms):
            action = (form.get('action') or '').strip()
            if action.startswith('http://'):
                print(f"[+] VULNERABILITY: Form #{i+1} submits to an insecure HTTP URL: {action}")
            else:
                print(f"[*] Form #{i+1} appears to be secure (action: {action or 'none'}).")
    except Exception as e:
        print(f"[-] Fallback failed: {e}")


def check_insecure_forms(url, driver):
    """Checks for forms submitting data over HTTP.

    Starts a non-JS heuristic immediately in the background while attempting
    to use Selenium for a dynamic, JS-enabled check.
    """
    print(f"[*] Checking for insecure forms on {url}")

    # Start heuristic in the background
    try:
        h_thread = threading.Thread(target=_fallback_check_insecure_forms, args=(url,))
        h_thread.daemon = True
        h_thread.start()
    except Exception as e:
        print(f"[-] Could not start heuristic background scan: {e}")

    try:
        if not driver:
            print("[-] Selenium driver not available; relying on heuristic scan results.")
            h_thread.join(timeout=5)
            return
        driver.get(url)
        forms = driver.find_elements(By.TAG_NAME, "form")
        if not forms:
            print("[-] No forms found on the page.")
            return

        for i, form in enumerate(forms):
            action = form.get_attribute("action")
            if action and action.startswith("http://"):
                print(f"[+] VULNERABILITY: Form #{i+1} submits to an insecure HTTP URL: {action}")
            else:
                print(f"[*] Form #{i+1} appears to be secure (action: {action or 'none'}).")
                
    except Exception as e:
        msg = str(e)
        print(f"[-] An error occurred: {msg}")
        if 'SSL' in msg or 'ERR_SSL' in msg or 'certificate' in msg.lower() or 'permission' in msg.lower():
            print("    * Selenium navigation failed; heuristic static scan is running in background.")
        else:
            print("    * Selenium encountered an error; heuristic static scan is running in background.")
    finally:
        try:
            h_thread.join(timeout=10)
            if h_thread.is_alive():
                print("[*] Heuristic scan still running; results will be printed when ready.")
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Check for forms submitting data over insecure HTTP.")
    parser.add_argument("url", help="The target URL or domain to check (e.g., example.com).")
    args = parser.parse_args()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    driver = setup_driver()
    if driver:
        check_insecure_forms(target_url, driver)
        driver.quit()

if __name__ == "__main__":
    main()
