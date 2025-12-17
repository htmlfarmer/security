import argparse
from urllib.parse import urlparse
from selenium import webdriver
from selenium.common.exceptions import UnexpectedAlertPresentException

def setup_driver():
    """Sets up the Selenium WebDriver."""
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    # Selenium Manager will now handle the driver automatically
    return webdriver.Chrome(options=options)

def check_dom_xss(url, driver):
    """Appends a payload to the URL and checks for an alert, indicating DOM XSS."""
    # A simple payload that should trigger an alert if vulnerable.
    payload = "<img src=x onerror=alert('VULNERABLE_DOM_XSS')>"
    test_url = f"{url}#{payload}"
    
    print(f"[*] Testing for DOM-based XSS with URL: {test_url}")
    
    try:
        driver.get(test_url)
        # This line will raise an exception if an alert is present
        driver.title 
        print("[-] No alert was triggered. Site does not appear to be vulnerable to this payload.")

    except UnexpectedAlertPresentException:
        print("[+] VULNERABILITY: DOM-based XSS detected! An alert was triggered by the payload.")
        alert = driver.switch_to.alert
        alert.accept() # Close the alert to allow the script to finish
    except Exception as e:
        print(f"[-] An error occurred during the test: {e}")

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
