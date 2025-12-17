import argparse
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By

def setup_driver():
    """Sets up the Selenium WebDriver."""
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    # Selenium Manager will now handle the driver automatically
    return webdriver.Chrome(options=options)

def check_insecure_forms(url, driver):
    """Checks for forms submitting data over HTTP."""
    print(f"[*] Checking for insecure forms on {url}")
    try:
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
        print(f"[-] An error occurred: {e}")

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
