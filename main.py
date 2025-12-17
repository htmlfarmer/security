import argparse
import subprocess
import sys
import os
from typing import List

# A dictionary to map test names to their script files.
# This makes it easy to add new scripts later.
SCRIPTS = {
    "tech": "tech_fingerprinter.py",
    "subdomain": "subdomain_enum.py",
    "headers": "header_checker.py",
    "xss": "xss_scanner.py",
    "links": "link_checker.py",
    "clickjacking": "clickjacking_checker.py",
    "dns": "dns_whois_nslookup_checker.py",
    "screenshot": "screenshot_taker.py",
    "insecure-forms": "insecure_form_checker.py",
    "dom-xss": "dom_xss_scanner.py",
}

# Define which scripts belong to each audit level.
AUDIT_LEVELS = {
    "basic": ["tech", "headers", "clickjacking", "links", "dns", "screenshot"],
    "advanced": ["subdomain", "insecure-forms"],
    "extreme": ["xss", "dom-xss"]
}

# A list of keywords that indicate a potential vulnerability in a script's output.
VULNERABILITY_KEYWORDS = [
    "VULNERABILITY:",
    "Missing Header:",
    "Broken Link Found:",
    "Unreachable Link Found:",
]

def run_script(script_name, target_url) -> List[str]:
    """
    Runs a specified security script and captures its output to find vulnerabilities.
    Returns a list of strings, where each string is a reported vulnerability.
    """
    script_path = os.path.join(os.path.dirname(__file__), SCRIPTS[script_name])
    findings = []

    if not os.path.exists(script_path):
        print(f"\n--- [ERROR: Script not found for '{script_name.upper()}'] ---")
        print(f"File not found: {script_path}")
        return findings

    print(f"\n--- [RUNNING: {script_name.upper()}] ---")
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
        
        print(result.stdout)
        
        # Parse output for vulnerabilities
        for line in result.stdout.splitlines():
            for keyword in VULNERABILITY_KEYWORDS:
                if keyword in line:
                    # Add a descriptive header for the finding
                    findings.append(f"[{script_name.upper()}] {line.strip()}")
                    break # Move to the next line once a keyword is found

        if result.stderr:
            print("--- STDERR ---")
            print(result.stderr)

    except FileNotFoundError:
        print(f"Error: Python interpreter '{sys.executable}' not found.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing {script_name}: Script returned a non-zero exit code.")
        print(f"--- STDOUT ---\n{e.stdout}")
        print(f"--- STDERR ---\n{e.stderr}")
    except subprocess.TimeoutExpired:
        print(f"Error: The script '{script_name}' timed out after 60 seconds.")
    except Exception as e:
        print(f"An unexpected error occurred while running {script_name}: {e}")
    
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
        tests_to_run = sorted(list(set(tests_to_run)), key=lambda x: list(SCRIPTS.keys()).index(x))


    print(f"[*] Starting security audit for: {target_url}")
    print(f"[*] Audit Level: {audit_level_msg}")
    print(f"[*] Tests to run: {', '.join(tests_to_run)}\n")
    
    for test in tests_to_run:
        if test in SCRIPTS:
            findings = run_script(test, target_url)
            if findings:
                all_findings.extend(findings)
        else:
            print(f"\n--- [WARNING: Test '{test}' is defined in a level but has no corresponding script] ---")

    print("\n\n-----------------------------------------")
    print("--- IMPORTANT SECURITY FINDINGS SUMMARY ---")
    print("-----------------------------------------")
    if all_findings:
        print("The following potential issues were identified:")
        for finding in all_findings:
            print(f"  * {finding}")
    else:
        print("No significant vulnerabilities were automatically detected based on the checks performed.")


    print("\n--- [AUDIT COMPLETE] ---")


if __name__ == "__main__":
    main()
