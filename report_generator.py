import argparse
import subprocess
import sys
import os
import datetime
import html
import glob
import json
from typing import List, Tuple, Dict

SCRIPTS_TO_RUN = [
    "tech_fingerprinter.py",
    "header_checker.py",
    "dns_whois_nslookup_checker.py",
    "dependency_scanner.py",
    "sensitive_data_scanner.py",
    "link_checker.py",
    "clickjacking_checker.py"
]

PROJECT_DIR = os.path.dirname(__file__)
OUTPUTS_DIR = os.path.join(PROJECT_DIR, "outputs")

# Simple keyword -> severity mapping for automatic classification
KEYWORD_SEVERITY = {
    'VULNERABILITY': 'High',
    'Potential sensitive data': 'High',
    'OUTDATED': 'Medium',
    'Missing Header': 'Medium',
    'Broken Link Found': 'Low',
    'Unreachable Link Found': 'Low',
    'Could not fetch': 'Low',
    'Error': 'Low'
}

def classify_line(line: str) -> Tuple[str, str]:
    for kw, sev in KEYWORD_SEVERITY.items():
        if kw in line:
            return kw, sev
    return '', ''

def run_script_and_capture(script: str, target: str) -> Tuple[str, List[dict]]:
    path = os.path.join(PROJECT_DIR, script)
    if not os.path.exists(path):
        return f"Script missing: {script}\n", []
    try:
        proc = subprocess.run([sys.executable, path, target],
                              capture_output=True, text=True, timeout=120)
        out = proc.stdout or ""
        err = proc.stderr or ""
        if err:
            out += "\n--- STDERR ---\n" + err

        findings = []
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            kw, sev = classify_line(line)
            if kw:
                findings.append({'line': line, 'keyword': kw, 'severity': sev, 'script': script})
        return out, findings
    except Exception as e:
        return f"Error running {script}: {e}\n", [{'line': str(e), 'keyword': 'Error', 'severity': 'Low', 'script': script}]

def find_screenshot_for_target(target: str) -> Tuple[str, str]:
    """
    Return (inline_base64, file_path) tuple.
    If a screenshot JSON exists, return its base64 content as inline_base64 and empty file_path.
    Otherwise return (None, file_path) pointing to a PNG in outputs/ if found.
    """
    domain = target.replace('http://','').replace('https://','').split('/')[0].replace(':','_')
    # Check JSON first
    json_path = os.path.join(OUTPUTS_DIR, f"screenshot_{domain}.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as jf:
                meta = json.load(jf)
                b64 = meta.get("data_base64")
                if b64:
                    return (b64, "")  # inline base64 present
        except Exception:
            pass
    # Check PNG domain file
    png_path = os.path.join(OUTPUTS_DIR, f"screenshot_{domain}.png")
    if os.path.exists(png_path):
        return ("", png_path)
    # Fallback to latest
    latest = os.path.join(OUTPUTS_DIR, "screenshot_latest.png")
    if os.path.exists(latest):
        return ("", latest)
    return ("", "")

def build_html_report(title: str, sections: List[dict], summary: dict, screenshot_inline_b64: str = None, screenshot_file: str = None, report_path: str = None) -> str:
    now = datetime.datetime.utcnow().isoformat()
    html_parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>",
        html.escape(title),
        "</title><style>",
        "body{font-family:Arial,Helvetica,sans-serif;padding:18px}",
        ".summary{display:flex;gap:20px;margin-bottom:18px}",
        ".card{border:1px solid #ddd;padding:12px;border-radius:6px;background:#fff;flex:1}",
        ".high{color:#b00020;font-weight:700}.medium{color:#d98200;font-weight:700}.low{color:#0b6d0b;font-weight:700}",
        "pre{background:#f6f6f6;padding:10px;border:1px solid #ddd;overflow:auto;max-height:360px}",
        "h2{border-bottom:1px solid #eee;padding-bottom:6px;margin-top:28px}",
        ".top-issue{margin:6px 0;padding:8px;border-left:3px solid #f00;background:#fff7f7}",
        "</style></head><body>"
    ]
    html_parts.append(f"<h1>{html.escape(title)}</h1><p>Generated: {now} UTC</p>")

    # Summary cards
    html_parts.append("<div class='summary'>")
    html_parts.append("<div class='card'><h3>Top Issues</h3>")
    if summary['findings']:
        for f in summary['findings'][:10]:
            sev_class = 'high' if f['severity']=='High' else ('medium' if f['severity']=='Medium' else 'low')
            html_parts.append(f"<div class='top-issue'><strong class='{sev_class}'>{html.escape(f['severity'])}</strong> &nbsp; <em>{html.escape(f['script'])}</em><br><small>{html.escape(f['line'])}</small></div>")
    else:
        html_parts.append("<p>No notable issues automatically detected.</p>")
    html_parts.append("</div>")

    html_parts.append("<div class='card'><h3>Counts by Severity</h3>")
    html_parts.append(f"<p><span class='high'>High: {summary['counts'].get('High',0)}</span><br>")
    html_parts.append(f"<span class='medium'>Medium: {summary['counts'].get('Medium',0)}</span><br>")
    html_parts.append(f"<span class='low'>Low: {summary['counts'].get('Low',0)}</span></p>")
    html_parts.append("</div>")

    html_parts.append("<div class='card'><h3>Screenshot</h3>")
    if screenshot_inline_b64:
        html_parts.append(f"<p><img src='data:image/png;base64,{screenshot_inline_b64}' alt='screenshot' style='max-width:100%;border:1px solid #ccc'></p>")
        html_parts.append("<p>Embedded screenshot from outputs/</p>")
    elif screenshot_file and os.path.exists(screenshot_file):
        # Compute path relative to report location if provided
        if report_path:
            rel_path = os.path.relpath(screenshot_file, start=os.path.dirname(os.path.abspath(report_path)))
        else:
            rel_path = os.path.relpath(screenshot_file, start=os.path.dirname(os.path.abspath(__file__)))
        html_parts.append(f"<p><img src='{html.escape(rel_path)}' alt='screenshot' style='max-width:100%;border:1px solid #ccc'></p>")
        html_parts.append(f"<p>Saved: {html.escape(rel_path)}</p>")
    else:
        html_parts.append("<p>No screenshot available.</p>")
    html_parts.append("</div>")
    html_parts.append("</div>")  # end summary

    # Full sections
    for sec in sections:
        html_parts.append(f"<h2>{html.escape(sec['name'])}</h2>")
        html_parts.append("<pre>")
        html_parts.append(html.escape(sec['output']))
        html_parts.append("</pre>")

    html_parts.append("</body></html>")
    return ''.join(html_parts)

def run_screenshot_for_target(target: str) -> None:
    """
    Invoke screenshot_taker.py to ensure a screenshot exists for the target.
    Prints its stdout/stderr to the console for visibility.
    """
    script = os.path.join(PROJECT_DIR, "screenshot_taker.py")
    if not os.path.exists(script):
        print(f"[-] Screenshot script not found: {script}")
        return
    try:
        print(f"[*] Taking screenshot for {target} ...")
        proc = subprocess.run([sys.executable, script, target], capture_output=True, text=True, timeout=180)
        if proc.stdout:
            print(proc.stdout)
        if proc.stderr:
            print("--- STDERR from screenshot_taker.py ---")
            print(proc.stderr)
    except Exception as e:
        print(f"[-] Error running screenshot_taker.py: {e}")

def main():
    parser = argparse.ArgumentParser(description="Run selected scanners and generate a single HTML report.")
    parser.add_argument("target", help="Target URL or domain (e.g., example.com)")
    parser.add_argument("-o", "--out", help="Output HTML filename (default: outputs/report_<target>.html)")
    args = parser.parse_args()

    target = args.target if '://' in args.target else 'http://' + args.target
    sections = []
    aggregated_findings = []

    # Ensure outputs dir exists and take a screenshot first
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    run_screenshot_for_target(target)

    for script in SCRIPTS_TO_RUN:
        print(f"[*] Running {script} ...")
        output, findings = run_script_and_capture(script, target)
        sections.append({'name': script, 'output': output})
        aggregated_findings.extend(findings)

    # Build summary
    counts = {'High':0,'Medium':0,'Low':0}
    for f in aggregated_findings:
        sev = f.get('severity','Low')
        counts[sev] = counts.get(sev,0) + 1

    sorted_findings = sorted(aggregated_findings, key=lambda x: (0 if x['severity']=='High' else (1 if x['severity']=='Medium' else 2), x.get('script','')))

    summary = {
        'counts': counts,
        'findings': sorted_findings
    }

    inline_b64, screenshot_file = find_screenshot_for_target(target)

    # Default report location inside outputs/
    safe_name = args.out or os.path.join(OUTPUTS_DIR, f"report_{target.replace('://','_').replace('/','_')}.html")
    report_html = build_html_report(f"Security Scan Report for {target}", sections, summary, screenshot_inline_b64=inline_b64 if inline_b64 else None, screenshot_file=screenshot_file if screenshot_file else None, report_path=safe_name)

    try:
        with open(safe_name, 'w', encoding='utf-8') as f:
            f.write(report_html)
        print(f"[+] Report written to {os.path.abspath(safe_name)}")
    except Exception as e:
        print(f"[-] Could not write report file: {e}")

if __name__ == "__main__":
    main()
