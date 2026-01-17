from flask import Flask, request, jsonify, send_from_directory, render_template_string
import os
import sys
import subprocess
import json

import main as core

APP = Flask(__name__, static_folder='static', template_folder='static')


def run_script_capture(script_key, target_url, timeout=60):
    script_path = os.path.join(os.path.dirname(__file__), core.SCRIPTS.get(script_key, ''))
    result = {
        'script': script_key,
        'script_path': script_path,
        'stdout': '',
        'stderr': '',
        'findings': []
    }

    if not os.path.exists(script_path):
        result['stderr'] = f"Script not found: {script_path}"
        return result

    cmd = [sys.executable, script_path, target_url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result['stdout'] = proc.stdout
        result['stderr'] = proc.stderr

        # simple findings extraction using keywords from core
        for line in proc.stdout.splitlines():
            for kw in core.VULNERABILITY_KEYWORDS:
                if kw in line:
                    result['findings'].append(line.strip())
                    break

    except subprocess.TimeoutExpired:
        result['stderr'] = f"Script timed out after {timeout} seconds"
    except Exception as e:
        result['stderr'] = str(e)

    return result


@APP.route('/scripts')
def scripts():
    return jsonify({
        'scripts': list(core.SCRIPTS.keys()),
        'labels': core.SCRIPTS,
        'levels': core.AUDIT_LEVELS
    })


@APP.route('/run', methods=['POST'])
def run():
    data = request.get_json() or {}
    url = data.get('url')
    tests = data.get('tests')
    level = data.get('level')

    if not url:
        return jsonify({'error': 'Missing url parameter'}), 400

    # normalize URL
    if '://' not in url:
        url = 'http://' + url

    tests_to_run = []
    if tests:
        tests_to_run = [t for t in tests if t in core.SCRIPTS]
    elif level:
        # build cumulative level as in main.py
        if level == 'extreme':
            tests_to_run.extend(core.AUDIT_LEVELS.get('basic', []))
            tests_to_run.extend(core.AUDIT_LEVELS.get('advanced', []))
            tests_to_run.extend(core.AUDIT_LEVELS.get('extreme', []))
        elif level == 'advanced':
            tests_to_run.extend(core.AUDIT_LEVELS.get('basic', []))
            tests_to_run.extend(core.AUDIT_LEVELS.get('advanced', []))
        else:
            tests_to_run.extend(core.AUDIT_LEVELS.get('basic', []))

        # dedupe preserving order
        seen = set()
        tests_to_run = [x for x in tests_to_run if not (x in seen or seen.add(x))]
    else:
        # default to basic
        tests_to_run = core.AUDIT_LEVELS.get('basic', [])

    results = []
    for t in tests_to_run:
        results.append(run_script_capture(t, url))

    # summary
    summary_findings = []
    for r in results:
        for f in r.get('findings', []):
            summary_findings.append(f"[{r['script'].upper()}] {f}")

    return jsonify({'url': url, 'results': results, 'summary': summary_findings})


@APP.route('/security.html')
def ui():
    return send_from_directory('static', 'security.html')


if __name__ == '__main__':
    APP.run(host='0.0.0.0', port=8000, debug=True)
