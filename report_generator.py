import argparse
import subprocess
import sys
import os
import datetime
import html
import glob
import json
from typing import List, Tuple, Dict
from test_descriptions import get_description

SCRIPTS_TO_RUN = [
    "tech_fingerprinter.py",
    "header_checker.py",
    "robots_txt.py",
    "dns_whois_nslookup_checker.py",
    "cookie_checker.py",
    "spf_dmarc_checker.py",
    "waf_detector.py",
    "dependency_scanner.py",
    "sensitive_data_scanner.py",
    "sitemap_parser.py",
    "link_checker.py",
    "clickjacking_checker.py",
    "dirbust_scanner.py",
    "admin_finder.py",
    "cors_checker.py",
    "http_methods_checker.py"
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
    """
    Return (matched_keyword, severity) for a line if any keyword is found.
    """
    for kw, sev in KEYWORD_SEVERITY.items():
        if kw in line:
            return kw, sev
    return '', ''

def run_script_and_capture(script: str, target: str) -> Tuple[str, List[dict], List[str]]:
    """
    Run a script and return raw output, parsed findings, and suggestions.
    Returns (output, findings_list, suggestions_list)
    """
    path = os.path.join(PROJECT_DIR, script)
    if not os.path.exists(path):
        return f"Script missing: {script}\n", [], []
    try:
        proc = subprocess.run([sys.executable, path, target],
                              capture_output=True, text=True, timeout=120)
        out = proc.stdout or ""
        err = proc.stderr or ""
        if err:
            out += "\n--- STDERR ---\n" + err

        findings = []
        suggestions = []
        current_in_suggestions = False
        
        for raw_line in out.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            
            # Check if we're entering suggestions section
            if "SUGGESTIONS:" in line or "📋" in line:
                current_in_suggestions = True
                continue
            
            # Capture suggestions
            if current_in_suggestions and (line.startswith('1.') or line.startswith('2.') or 
                                          line.startswith('3.') or line.startswith('4.') or
                                          line.startswith('5.') or line.startswith('-')):
                suggestions.append(line)
            elif current_in_suggestions and line.startswith('['):
                # End of suggestions section
                current_in_suggestions = False
            
            # Capture findings
            kw, sev = classify_line(line)
            if kw:
                findings.append({'line': line, 'keyword': kw, 'severity': sev, 'script': script})
        
        return out, findings, suggestions
    except Exception as e:
        return f"Error running {script}: {e}\n", [{'line': str(e), 'keyword': 'Error', 'severity': 'Low', 'script': script}], []

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
        "* { box-sizing: border-box; }",
        "body { font-family: Arial, Helvetica, sans-serif; padding: 20px; margin: 0; background: #f5f5f5; }",
        "h1 { color: #333; margin-bottom: 8px; }",
        ".header-info { color: #666; margin-bottom: 20px; font-size: 0.9em; }",
        ".summary { display: flex; flex-direction: column; gap: 20px; margin-bottom: 30px; }",
        ".card { border: 1px solid #ddd; padding: 16px; border-radius: 6px; background: #fff; }",
        ".card h3 { margin-top: 0; margin-bottom: 12px; color: #333; }",
        ".card p { margin: 6px 0; }",
        ".high { color: #b00020; font-weight: 700; }",
        ".medium { color: #d98200; font-weight: 700; }",
        ".low { color: #0b6d0b; font-weight: 700; }",
        "pre { background: #f6f6f6; padding: 12px; border: 1px solid #ddd; overflow-x: auto; max-height: 400px; border-radius: 4px; font-size: 0.85em; }",
        "h2 { border-bottom: 2px solid #2196F3; padding-bottom: 10px; margin-top: 40px; margin-bottom: 16px; color: #333; }",
        ".description { background: #e3f2fd; border-left: 4px solid #2196F3; padding: 14px; margin: 16px 0; font-size: 0.95em; line-height: 1.6; border-radius: 4px; }",
        ".suggestions-box { background: #fff3cd; border-left: 4px solid #ffc107; padding: 14px; margin: 16px 0; font-size: 0.95em; border-radius: 4px; }",
        ".suggestions-box h4 { margin-top: 0; color: #856404; }",
        ".suggestions-box ol { margin: 10px 0; padding-left: 20px; }",
        ".suggestions-box li { margin: 6px 0; color: #333; }",
        ".top-issue { margin: 8px 0; padding: 10px; border-left: 3px solid #f00; background: #fff7f7; border-radius: 2px; }",
        ".top-issue strong { display: inline-block; min-width: 70px; }",
        ".top-issue em { color: #666; font-size: 0.9em; }",
        ".top-issue small { display: block; margin-top: 4px; color: #555; }",
        ".screenshot-thumb { max-width: 100%; max-height: 400px; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; transition: transform 0.2s; }",
        ".screenshot-thumb:hover { transform: scale(1.02); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }",
        ".modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.7); }",
        ".modal.active { display: flex; align-items: center; justify-content: center; }",
        ".modal-content { background-color: #fefefe; max-width: 95vw; max-height: 95vh; overflow: auto; border-radius: 8px; position: relative; }",
        ".modal-content img { width: 100%; height: auto; }",
        ".close-btn { position: absolute; top: 10px; right: 20px; color: #fff; font-size: 28px; font-weight: bold; cursor: pointer; background: rgba(0,0,0,0.5); padding: 5px 15px; border-radius: 4px; }",
        ".close-btn:hover { background: rgba(0,0,0,0.8); }",
        "@media (max-width: 1200px) { body { padding: 10px; } .card { padding: 12px; } }",
        "</style></head><body>"
    ]
    html_parts.append(f"<h1>{html.escape(title)}</h1>")
    html_parts.append(f"<div class='header-info'>Generated: {now} UTC</div>")

    # Summary cards (vertical stack)
    html_parts.append("<div class='summary'>")
    
    # Top Issues Card
    html_parts.append("<div class='card'><h3>Top Issues</h3>")
    if summary['findings']:
        for f in summary['findings'][:10]:
            sev_class = 'high' if f['severity']=='High' else ('medium' if f['severity']=='Medium' else 'low')
            html_parts.append(f"<div class='top-issue'><strong class='{sev_class}'>{html.escape(f['severity'])}</strong> <em>{html.escape(f['script'])}</em><br><small>{html.escape(f['line'][:100])}</small></div>")
    else:
        html_parts.append("<p>No notable issues automatically detected.</p>")
    html_parts.append("</div>")

    # Severity Counts Card
    html_parts.append("<div class='card'><h3>Counts by Severity</h3>")
    html_parts.append(f"<p><span class='high'>● High: {summary['counts'].get('High',0)}</span></p>")
    html_parts.append(f"<p><span class='medium'>● Medium: {summary['counts'].get('Medium',0)}</span></p>")
    html_parts.append(f"<p><span class='low'>● Low: {summary['counts'].get('Low',0)}</span></p>")
    html_parts.append("</div>")

    # Screenshot Card with modal
    html_parts.append("<div class='card'><h3>Screenshot</h3>")
    if screenshot_inline_b64:
        html_parts.append(f"<img id='screenshotThumb' class='screenshot-thumb' src='data:image/png;base64,{screenshot_inline_b64}' alt='screenshot' onclick=\"openModal('data:image/png;base64,{screenshot_inline_b64}', true)\">")
        html_parts.append("<p style='font-size: 0.9em; color: #666;'>Click to view full size | Embedded screenshot from outputs/</p>")
    elif screenshot_file and os.path.exists(screenshot_file):
        if report_path:
            rel_path = os.path.relpath(screenshot_file, start=os.path.dirname(os.path.abspath(report_path)))
        else:
            rel_path = os.path.relpath(screenshot_file, start=os.path.dirname(os.path.abspath(__file__)))
        html_parts.append(f"<img id='screenshotThumb' class='screenshot-thumb' src='{html.escape(rel_path)}' alt='screenshot' onclick=\"openModal('{html.escape(rel_path)}', false)\">")
        html_parts.append(f"<p style='font-size: 0.9em; color: #666;'>Click to view full size | Saved: {html.escape(rel_path)}</p>")
    else:
        html_parts.append("<p style='color: #999;'>No screenshot available.</p>")
    html_parts.append("</div>")

    html_parts.append("</div>")  # end summary

    # Full sections with descriptions and suggestions
    for sec in sections:
        script_name = sec['name']
        description = get_description(script_name)
        suggestions = sec.get('suggestions', [])
        
        html_parts.append(f"<h2>{html.escape(script_name)}</h2>")
        html_parts.append(f"<div class='description'>{html.escape(description)}</div>")
        
        # Add suggestions box if any suggestions found
        if suggestions:
            html_parts.append("<div class='suggestions-box'>")
            html_parts.append("<h4>💡 Suggestions & Remediation</h4>")
            html_parts.append("<ol>")
            for suggestion in suggestions:
                # Clean up suggestion text (remove numbering if present)
                clean_suggestion = suggestion.lstrip('0123456789.- ')
                html_parts.append(f"<li>{html.escape(clean_suggestion)}</li>")
            html_parts.append("</ol>")
            html_parts.append("</div>")
        
        html_parts.append("<h4>Test Output:</h4>")
        html_parts.append("<pre>")
        html_parts.append(html.escape(sec['output'][:2000]))
        html_parts.append("</pre>")

    # Modal for full-size screenshot
    html_parts.append("<div id='screenshotModal' class='modal'>")
    html_parts.append("<div class='modal-content'>")
    html_parts.append("<span class='close-btn' onclick='closeModal()'>&times;</span>")
    html_parts.append("<img id='modalImage' src='' alt='Full size screenshot'>")
    html_parts.append("</div>")
    html_parts.append("</div>")

    # JavaScript for modal functionality
    html_parts.append("<script>")
    html_parts.append("""
function openModal(src, isBase64) {
    const modal = document.getElementById('screenshotModal');
    const img = document.getElementById('modalImage');
    img.src = src;
    modal.classList.add('active');
}

function closeModal() {
    const modal = document.getElementById('screenshotModal');
    modal.classList.remove('active');
}

document.getElementById('screenshotModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeModal();
    }
});

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});
""")
    html_parts.append("</script>")

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
        output, findings, suggestions = run_script_and_capture(script, target)
        sections.append({'name': script, 'output': output, 'suggestions': suggestions})
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
