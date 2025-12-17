import argparse
import os
from urllib.parse import urlparse, urlunparse
from selenium import webdriver

def remove_old_screenshots():
    """Finds and removes all .png files in the current working directory."""
    print("[*] Removing old screenshots...")
    files_removed = 0
    # The script is run from the project root, so '.' is the correct directory.
    for filename in os.listdir('.'):
        if filename.endswith(".png"):
            try:
                os.remove(filename)
                files_removed += 1
            except OSError as e:
                print(f"[-] Could not remove {filename}: {e}")
    if files_removed > 0:
        print(f"[+] Removed {files_removed} old screenshot(s).")
    else:
        print("[-] No old screenshots found to remove.")

def setup_driver():
    """Sets up the Selenium WebDriver."""
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("window-size=1280x800")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    
    # Selenium Manager will now handle the driver automatically
    driver = webdriver.Chrome(options=options)
    return driver

def take_screenshot(url, driver):
    """Navigates to a URL and takes a screenshot."""
    print(f"[*] Taking screenshot of {url}")
    try:
        driver.get(url)
        # Generate a filename from the URL
        parsed_url = urlparse(url)
        filename = f"{parsed_url.netloc.replace(':', '_')}.png"
        driver.save_screenshot(filename)
        print(f"[+] Screenshot saved as {os.path.abspath(filename)}")
    except Exception as e:
        print(f"[-] An error occurred while taking screenshot: {e}")

def main():
    parser = argparse.ArgumentParser(description="Take a screenshot of a webpage using Selenium.")
    parser.add_argument("url", help="The target URL or domain to capture (e.g., example.com).")
    args = parser.parse_args()

    # Remove old screenshots before starting a new run.
    remove_old_screenshots()

    target_url = args.url
    if not urlparse(target_url).scheme:
        target_url = "http://" + target_url

    driver = setup_driver()
    if driver:
        take_screenshot(target_url, driver)
        driver.quit()

if __name__ == "__main__":
    main()
