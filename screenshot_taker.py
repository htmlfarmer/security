import argparse
import os
import json
import base64
import shutil
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from selenium import webdriver

OUTPUTS_DIR = Path("outputs")

def remove_old_screenshots():
    """Clean outputs/ but preserve per-domain screenshot files.
    Only remove the transient 'screenshot_latest.*' files to avoid leaving stale temporary files,
    while keeping screenshot_<domain>.png and screenshot_<domain>.json for each lookup.
    """
    print("[*] Cleaning outputs/ (removing only transient latest screenshot files)...")
    files_removed = 0
    OUTPUTS_DIR.mkdir(exist_ok=True)
    # Remove only the latest transient files, keep domain-named artifacts
    for filename in OUTPUTS_DIR.iterdir():
        if filename.name.startswith("screenshot_latest."):
            try:
                filename.unlink()
                files_removed += 1
            except OSError as e:
                print(f"[-] Could not remove {filename}: {e}")
    if files_removed > 0:
        print(f"[+] Removed {files_removed} transient latest screenshot file(s) from {OUTPUTS_DIR}.")
    else:
        print(f"[-] No transient latest screenshot files found in {OUTPUTS_DIR} to remove.")

def setup_driver():
    """Sets up the Selenium WebDriver."""
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    # Request a 1080p viewport
    options.add_argument("--window-size=1920,1080")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    
    driver = webdriver.Chrome(options=options)
    try:
        driver.set_window_size(1920, 1080)
    except Exception:
        pass
    return driver

def save_screenshot_data(png_path: Path, domain: str):
    """Read PNG bytes and save base64-encoded data + metadata to a JSON file in outputs/."""
    try:
        with open(png_path, "rb") as f:
            b = f.read()
        b64 = base64.b64encode(b).decode('ascii')
        metadata = {
            "filename": png_path.name,
            "size_bytes": len(b),
            "data_base64": b64
        }
        json_name = OUTPUTS_DIR / f"screenshot_{domain}.json"
        with open(json_name, "w", encoding="utf-8") as jf:
            json.dump(metadata, jf)
        print(f"[+] Screenshot data saved as {json_name.resolve()}")
    except Exception as e:
        print(f"[-] Could not save screenshot data: {e}")

def take_screenshot(url, driver):
    """Navigates to a URL and takes a screenshot (PNG + base64 JSON) into outputs/."""
    print(f"[*] Taking screenshot of {url}")
    try:
        driver.get(url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace(':', '_')
        OUTPUTS_DIR.mkdir(exist_ok=True)

        # Primary filename based on domain inside outputs/
        png_path = OUTPUTS_DIR / f"screenshot_{domain}.png"
        driver.save_screenshot(str(png_path))
        print(f"[+] Screenshot saved as {png_path.resolve()}")

        # Also update latest copy
        latest_png = OUTPUTS_DIR / "screenshot_latest.png"
        try:
            shutil.copy2(png_path, latest_png)
            print(f"[+] Latest screenshot updated: {latest_png.resolve()}")
        except Exception as e:
            print(f"[-] Could not update latest screenshot copy: {e}")

        # Save base64 metadata JSON (domain-based)
        save_screenshot_data(png_path, domain=domain)

    except Exception as e:
        print(f"[-] An error occurred while taking screenshot: {e}")

def main():
    parser = argparse.ArgumentParser(description="Take a screenshot of a webpage using Selenium.")
    parser.add_argument("url", help="The target URL or domain to capture (e.g., example.com).")
    args = parser.parse_args()

    # Remove old screenshots and associated data before starting a new run.
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
