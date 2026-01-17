<?php
// security.php - serves a simple UI and runs python security scripts on the server
header("Access-Control-Allow-Origin: *");

$method = $_SERVER['REQUEST_METHOD'];
$action = isset($_GET['action']) ? $_GET['action'] : '';

$SCRIPTS = array(
    "tech" => "tech_fingerprinter.py",
    "headers" => "header_checker.py",
    "clickjacking" => "clickjacking_checker.py",
    "cookies" => "cookie_checker.py",
    "robots" => "robots_txt.py",
    "dns" => "dns_whois_nslookup_checker.py",
    "spf-dmarc" => "spf_dmarc_checker.py",
    "waf" => "waf_detector.py",
    "links" => "link_checker.py",
    "sensitive-data" => "sensitive_data_scanner.py",
    "sitemap" => "sitemap_parser.py",
    "subdomain" => "subdomain_enum.py",
    "dirbust" => "dirbust_scanner.py",
    "admin" => "admin_finder.py",
    "cors" => "cors_checker.py",
    "http-methods" => "http_methods_checker.py",
    "screenshot" => "screenshot_taker.py",
    "insecure-forms" => "insecure_form_checker.py",
    "dom-xss" => "dom_xss_scanner.py",
    "xss" => "xss_scanner.py",
    "sqli" => "sqli_scanner.py",
    "open-redirect" => "open_redirect_checker.py",
    "traversal" => "directory_traversal_checker.py",
);

$AUDIT_LEVELS = array(
    "basic" => array("tech","headers","clickjacking","cookies","robots","dns","spf-dmarc","waf","links","sensitive-data","sitemap","screenshot"),
    "advanced" => array("subdomain","dirbust","admin","cors","http-methods","insecure-forms"),
    "extreme" => array("xss","dom-xss","sqli","open-redirect","traversal"),
);

$VULN_KEYWORDS = array(
    "VULNERABILITY:",
    "Missing Header:",
    "Broken Link Found:",
    "Unreachable Link Found:",
);

function respond_json($obj) {
    header('Content-Type: application/json');
    echo json_encode($obj);
    exit;
}

// Return scripts and level metadata
if ($method === 'GET' && $action === 'scripts') {
    respond_json(array('scripts' => array_keys($SCRIPTS), 'labels' => $SCRIPTS, 'levels' => $AUDIT_LEVELS));
}

// Handle run request
if ($method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    if (!$body) { respond_json(array('error' => 'Invalid JSON body')); }

    $url = isset($body['url']) ? $body['url'] : null;
    if (!$url) { respond_json(array('error' => 'Missing url parameter')); }
    if (strpos($url, '://') === false) { $url = 'http://' . $url; }

    $tests = isset($body['tests']) ? $body['tests'] : null;
    $level = isset($body['level']) ? $body['level'] : null;

    $tests_to_run = array();
    if ($tests && is_array($tests)) {
        foreach ($tests as $t) { if (isset($SCRIPTS[$t])) $tests_to_run[] = $t; }
    } elseif ($level) {
        if ($level === 'extreme') {
            $tests_to_run = array_merge($tests_to_run, $AUDIT_LEVELS['basic']);
            $tests_to_run = array_merge($tests_to_run, $AUDIT_LEVELS['advanced']);
            $tests_to_run = array_merge($tests_to_run, $AUDIT_LEVELS['extreme']);
        } elseif ($level === 'advanced') {
            $tests_to_run = array_merge($tests_to_run, $AUDIT_LEVELS['basic']);
            $tests_to_run = array_merge($tests_to_run, $AUDIT_LEVELS['advanced']);
        } else {
            $tests_to_run = $AUDIT_LEVELS['basic'];
        }
        // dedupe preserving order
        $seen = array(); $unique = array();
        foreach ($tests_to_run as $v) { if (!in_array($v, $seen)) { $seen[] = $v; $unique[] = $v; } }
        $tests_to_run = $unique;
    } else {
        $tests_to_run = $AUDIT_LEVELS['basic'];
    }

    $results = array();
    foreach ($tests_to_run as $t) {
        $entry = array('script' => $t, 'script_path' => '', 'stdout' => '', 'stderr' => '', 'findings' => array());
        if (!isset($SCRIPTS[$t])) { $entry['stderr'] = "Unknown script: $t"; $results[] = $entry; continue; }

        $script_path = __DIR__ . DIRECTORY_SEPARATOR . $SCRIPTS[$t];
        $entry['script_path'] = $script_path;
        if (!file_exists($script_path)) { $entry['stderr'] = "Script not found: $script_path"; $results[] = $entry; continue; }

        // Build command. Use `timeout` to prevent long-running scripts (Linux utility)
        $python = 'python3';
        $timeout = 'timeout 60s';
        $cmd = $timeout . ' ' . escapeshellcmd($python) . ' ' . escapeshellarg($script_path) . ' ' . escapeshellarg($url) . ' 2>&1';

        $output = array();
        $ret = 0;
        exec($cmd, $output, $ret);
        $stdout = implode("\n", $output);
        $entry['stdout'] = $stdout;
        if ($ret !== 0) { $entry['stderr'] = "Exit code: $ret"; }

        // find findings
        foreach (explode("\n", $stdout) as $line) {
            foreach ($VULN_KEYWORDS as $kw) {
                if (strpos($line, $kw) !== false) { $entry['findings'][] = trim($line); break; }
            }
        }

        $results[] = $entry;
    }

    // Build summary
    $summary = array();
    foreach ($results as $r) { foreach ($r['findings'] as $f) { $summary[] = "[" . strtoupper($r['script']) . "] " . $f; } }

    respond_json(array('url' => $url, 'results' => $results, 'summary' => $summary));
}

// If GET without action, serve a simple UI that posts back to this file.
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Audit (PHP)</title>
  <style>
    body{font-family:system-ui,Arial,sans-serif;margin:20px}
    label{display:block;margin:6px 0}
    #tests label{display:inline-block;margin-right:12px}
    pre{background:#111;color:#e6e6e6;padding:8px;white-space:pre-wrap}
    .stderr{background:#330000;color:#ffdddd}
    .findings{background:#fff8e1;padding:8px;margin-top:8px}
    section.script-result{border:1px solid #ddd;padding:8px;margin:8px 0;border-radius:4px}
  </style>
</head>
<body>
  <h1>Security Audit (PHP)</h1>
  <label>Target URL: <input id="url" placeholder="example.com"></label>
  <div id="tests"></div>
  <div class="controls">
    <label>Level:
      <select id="level"><option value="basic">basic</option><option value="advanced">advanced</option><option value="extreme">extreme</option></select>
    </label>
    <button id="run-selected">Run Selected</button>
    <button id="run-level">Run Level</button>
    <button id="run-all">Run All</button>
  </div>

  <h3>Summary</h3>
  <div id="summary"></div>
  <h3>Results</h3>
  <div id="results"></div>

  <script>
    async function loadScripts(){
      const r = await fetch('?action=scripts');
      const data = await r.json();
      const container = document.getElementById('tests'); container.innerHTML='';
      data.scripts.forEach(s=>{const id='chk_'+s; const label=document.createElement('label'); label.innerHTML=`<input type="checkbox" id="${id}" value="${s}"> ${s}`; container.appendChild(label);});
    }
    async function runPayload(payload){
      const resp = await fetch('', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
      return await resp.json();
    }
    async function runSelected(){const url=document.getElementById('url').value; const checks=Array.from(document.querySelectorAll('#tests input:checked')).map(i=>i.value); if(!url){alert('Enter a target URL'); return;} const d=await runPayload({url, tests:checks}); renderResults(d);}    
    async function runLevel(){const url=document.getElementById('url').value; const level=document.getElementById('level').value; if(!url){alert('Enter a target URL'); return;} const d=await runPayload({url, level}); renderResults(d);}    
    async function runAll(){const url=document.getElementById('url').value; if(!url){alert('Enter a target URL'); return;} const r=await fetch('?action=scripts'); const data=await r.json(); const d=await runPayload({url, tests: data.scripts}); renderResults(d);}    
    function renderResults(data){ const sum=document.getElementById('summary'); const res=document.getElementById('results'); res.innerHTML=''; sum.innerHTML=''; if(data.summary && data.summary.length){ const ul=document.createElement('ul'); data.summary.forEach(s=>{const li=document.createElement('li'); li.textContent=s; ul.appendChild(li)}); sum.appendChild(ul);} else sum.textContent='No findings'; data.results.forEach(r=>{const sec=document.createElement('section');sec.className='script-result'; const h=document.createElement('h4');h.textContent=r.script; sec.appendChild(h); const pre=document.createElement('pre'); pre.textContent=r.stdout || ''; sec.appendChild(pre); if(r.stderr){ const pree=document.createElement('pre'); pree.className='stderr'; pree.textContent=r.stderr; sec.appendChild(pree);} if(r.findings && r.findings.length){ const f=document.createElement('div'); f.className='findings'; f.innerHTML='<strong>Findings:</strong><ul>'+r.findings.map(x=>`<li>${x}</li>`).join('')+'</ul>'; sec.appendChild(f);} res.appendChild(sec); }); }
    document.getElementById('run-selected').addEventListener('click', runSelected);
    document.getElementById('run-level').addEventListener('click', runLevel);
    document.getElementById('run-all').addEventListener('click', runAll);
    loadScripts();
  </script>
</body>
</html>
