import argparse
from urllib.parse import urlparse
from selenium import webdriver
from selenium.common.exceptions import UnexpectedAlertPresentException
import os
import tempfile
import requests
from bs4 import BeautifulSoup
import urllib3
import threading
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
    user_data_dir = os.path.join(tempfile.gettempdir(), 'selenium_cache_xss')
    os.makedirs(user_data_dir, exist_ok=True)
    os.environ['XDG_CACHE_HOME'] = tempfile.gettempdir()
    options.add_argument(f"--user-data-dir={user_data_dir}")

    try:
        return webdriver.Chrome(options=options)
    except Exception as e:
        print("[-] Could not start Selenium Chrome driver:", e)
        print("    * Ensure Chrome and ChromeDriver are compatible and available on PATH.")
        print("    * Ensure the process has write access to the cache/user-data directories or set XDG_CACHE_HOME to a writable dir.")
        return None

def _heuristic_dom_scan(url):
    """Heuristic non-JS scan using static HTML analysis to detect DOM sink patterns."""
    print("[*] Performing heuristic DOM analysis via static HTML fetch")
    try:
        r = requests.get(url, verify=False, timeout=12)
        body = r.text
        sinks = ['innerHTML', 'document.write', 'eval(', 'location.hash', 'location.href', 'document.location', 'window.location', 'setAttribute(']
        found = [s for s in sinks if s in body]
        if found:
            print(f"[!] Heuristic: potential DOM sink patterns found: {', '.join(found)}")
            print("    Note: this is not a definitive DOM-XSS proof. Use a JS-enabled browser for dynamic verification.")
        else:
            print("[-] Heuristic: no obvious DOM sink patterns found in page HTML.")
    except Exception as e:
        print(f"[-] Heuristic fetch failed: {e}")


def check_dom_xss(url, driver):
    """Appends a payload to the URL and checks for an alert, indicating DOM XSS.

    Starts a heuristic static analysis in a separate thread immediately so we get
    quick indications while Selenium runs (if available).
    """
    # A simple payload that should trigger an alert if vulnerable.
    payload = "<img src=x onerror=alert('VULNERABLE_DOM_XSS')>"
    test_url = f"{url}#{payload}"
    
    print(f"[*] Testing for DOM-based XSS with URL: {test_url}")

    # Start heuristic scan in background (non-blocking)
    try:
        h_thread = threading.Thread(target=_heuristic_dom_scan, args=(url,))
        h_thread.daemon = True
        h_thread.start()
    except Exception as e:
        print(f"[-] Could not start heuristic background scan: {e}")

    try:
        if not driver:
            print("[-] Selenium driver not available; relying on heuristic scan results.")
            # Wait briefly for heuristic to complete or at least start producing output
            h_thread.join(timeout=5)
            return
        driver.get(test_url)
        # This line will raise an exception if an alert is present
        driver.title 
        print("[-] No alert was triggered. Site does not appear to be vulnerable to this payload.")

    except UnexpectedAlertPresentException:
        print("[+] VULNERABILITY: DOM-based XSS detected! An alert was triggered by the payload.")
        try:
            alert = driver.switch_to.alert
            alert.accept() # Close the alert to allow the script to finish
        except Exception:
            pass
    except Exception as e:
        msg = str(e)
        print(f"[-] An error occurred during the test: {msg}")
        # If it's an SSL or driver startup problem, note that heuristic is running
        if 'SSL' in msg or 'ERR_SSL' in msg or 'certificate' in msg.lower() or 'permission' in msg.lower():
            print("    * Selenium navigation failed; heuristic static scan is running in background.")
        else:
            print("    * Selenium encountered an error; heuristic static scan is running in background.")
    finally:
        # Give heuristic a short time to finish and return control
        try:
            h_thread.join(timeout=10)
            if h_thread.is_alive():
                print("[*] Heuristic scan still running; results will be printed when ready.")
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description="Basic scanner for DOM-based XSS.")
    parser.add_argument("url", help="The target URL or domain to check (e.g., example.com).")
    args = parser.parse_args()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    driver = setup_driver()
    if driver:
        check_dom_xss(target_url, driver)
        driver.quit()

if __name__ == "__main__":
    main()
