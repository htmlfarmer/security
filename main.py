import argparse
import subprocess
import sys
import os
from typing import List

# A dictionary to map test names to their script files.
# This makes it easy to add new scripts later.
SCRIPTS = {
    "tech": "tech_fingerprinter.py",
    "headers": "header_checker.py",
    "clickjacking": "clickjacking_checker.py",
    "cookies": "cookie_checker.py",
    "robots": "robots_txt.py",
    "dns": "dns_whois_nslookup_checker.py",
    "spf-dmarc": "spf_dmarc_checker.py",
    "waf": "waf_detector.py",
    "links": "link_checker.py",
    "sensitive-data": "sensitive_data_scanner.py",
    "sitemap": "sitemap_parser.py",
    "subdomain": "subdomain_enum.py",
    "dirbust": "dirbust_scanner.py",
    "admin": "admin_finder.py",
    "cors": "cors_checker.py",
    "http-methods": "http_methods_checker.py",
    "screenshot": "screenshot_taker.py",
    "insecure-forms": "insecure_form_checker.py",
    "dom-xss": "dom_xss_scanner.py",
    "xss": "xss_scanner.py",
    "sqli": "sqli_scanner.py",
    "open-redirect": "open_redirect_checker.py",
    "traversal": "directory_traversal_checker.py",
}

# Define which scripts belong to each audit level.
AUDIT_LEVELS = {
    "basic": ["tech", "headers", "clickjacking", "cookies", "robots", "dns", "spf-dmarc", "waf", "links", "sensitive-data", "sitemap", "screenshot"],
    "advanced": ["subdomain", "dirbust", "admin", "cors", "http-methods", "insecure-forms"],
    "extreme": ["xss", "dom-xss", "sqli", "open-redirect", "traversal"]
}

# A list of keywords that indicate a potential vulnerability in a script's output.
VULNERABILITY_KEYWORDS = [
    "VULNERABILITY:",
    "Missing Header:",
    "Broken Link Found:",
    "Unreachable Link Found:",
]

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

def color(text: str, col: str) -> str:
    return f"{col}{text}{RESET}"

def run_script(script_name, target_url) -> List[str]:
    """
    Runs a specified security script and captures its output to find vulnerabilities.
    Returns a list of strings, where each string is a reported vulnerability.
    """
    script_path = os.path.join(os.path.dirname(__file__), SCRIPTS[script_name])
    findings = []

    if not os.path.exists(script_path):
        print(color(f"\n--- [ERROR: Script not found for '{script_name.upper()}'] ---", RED))
        print(color(f"File not found: {script_path}", YELLOW))
        return findings

    print(color(f"\n--- [RUNNING: {script_name.upper()}] ---", CYAN))
    try:
        # Use sys.executable to ensure the correct Python interpreter is used.
        command = [sys.executable, script_path, target_url]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True, # Raise an exception if the script returns a non-zero exit code
            timeout=60 # Add a timeout to prevent indefinite hanging
        )
        
        # Print raw script output (keep uncolored so parsers can read it if needed)
        if result.stdout:
            print(result.stdout)
        
        # Parse output for vulnerabilities
        for line in result.stdout.splitlines():
            for keyword in VULNERABILITY_KEYWORDS:
                if keyword in line:
                    # Add a descriptive header for the finding
                    findings.append(f"[{script_name.upper()}] {line.strip()}")
                    break # Move to the next line once a keyword is found

        if result.stderr:
            print(color("--- STDERR ---", YELLOW))
            print(result.stderr)

    except FileNotFoundError:
        print(color(f"Error: Python interpreter '{sys.executable}' not found.", RED))
    except subprocess.CalledProcessError as e:
        print(color(f"Error executing {script_name}: Script returned a non-zero exit code.", RED))
        print(f"--- STDOUT ---\n{e.stdout}")
        print(f"--- STDERR ---\n{e.stderr}")
    except subprocess.TimeoutExpired:
        print(color(f"Error: The script '{script_name}' timed out after 60 seconds.", RED))
    except Exception as e:
        print(color(f"An unexpected error occurred while running {script_name}: {e}", RED))
    
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="Main security audit script runner.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("url", help="The target URL for the security audit.")
    
    # Allow user to select a level or specify individual tests, but not both.
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-l", "--level",
        choices=AUDIT_LEVELS.keys(),
        default='basic',
        help="Specify the audit level:\n"
             "  basic: Fast, non-intrusive checks.\n"
             "  advanced: Includes 'basic' plus active enumeration.\n"
             "  extreme: Includes 'advanced' plus intrusive payload injection."
    )
    group.add_argument(
        "-t", "--tests",
        nargs='+',
        choices=list(SCRIPTS.keys()),
        help=f"Specify individual tests to run instead of an audit level."
    )
    args = parser.parse_args()

    target_url = args.url
    # Ensure URL has a scheme
    if '://' not in target_url:
        target_url = "http://" + target_url

    tests_to_run = []
    audit_level_msg = "custom"
    all_findings = []

    if args.tests:
        # User specified individual tests
        tests_to_run = args.tests
    else:
        # Determine tests based on the chosen level (cumulative)
        audit_level_msg = args.level
        if args.level == 'extreme':
            tests_to_run.extend(AUDIT_LEVELS.get('basic', []))
            tests_to_run.extend(AUDIT_LEVELS.get('advanced', []))
            tests_to_run.extend(AUDIT_LEVELS.get('extreme', []))
        elif args.level == 'advanced':
            tests_to_run.extend(AUDIT_LEVELS.get('basic', []))
            tests_to_run.extend(AUDIT_LEVELS.get('advanced', []))
        else:  # basic
            tests_to_run.extend(AUDIT_LEVELS.get('basic', []))
        
        # Remove duplicates while preserving order for logical flow
        tests_to_run = sorted(list(dict.fromkeys(tests_to_run)), key=lambda x: list(SCRIPTS.keys()).index(x))


    print(color(f"[*] Starting security audit for: {target_url}", CYAN))
    print(color(f"[*] Audit Level: {audit_level_msg}", CYAN))
    print(color(f"[*] Tests to run: {', '.join(tests_to_run)}\n", CYAN))
    
    for test in tests_to_run:
        if test in SCRIPTS:
            findings = run_script(test, target_url)
            if findings:
                all_findings.extend(findings)
        else:
            print(color(f"\n--- [WARNING: Test '{test}' is defined in a level but has no corresponding script] ---", YELLOW))

    print("\n\n" + color("-----------------------------------------", BOLD))
    print(color("--- IMPORTANT SECURITY FINDINGS SUMMARY ---", BOLD + CYAN))
    print(color("-----------------------------------------", BOLD))
    if all_findings:
        print(color("The following potential issues were identified:", YELLOW))
        for finding in all_findings:
            # Color findings by severity keyword
            if "VULNERABILITY" in finding or "VULNERABLE" in finding:
                print(color(f"  * {finding}", RED))
            elif "OUTDATED" in finding or "Missing Header" in finding:
                print(color(f"  * {finding}", YELLOW))
            else:
                print(color(f"  * {finding}", GREEN))
    else:
        print(color("No significant vulnerabilities were automatically detected based on the checks performed.", GREEN))


    print("\n" + color("--- [AUDIT COMPLETE] ---", BOLD + GREEN))


if __name__ == "__main__":
    main()
