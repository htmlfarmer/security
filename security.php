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
    "nmap" => "connect-scan (unprivileged TCP connect)",
    "firewall" => "connect-scan (firewall probe - unprivileged)",
    "ping" => "ping.py",
    "traceroute" => "traceroute.py",
    "diagnose" => "website_debug.py",
      "tls" => "tls_checker.py",
      "integrity" => "integrity_checker.py",
      "config" => "config_checker.py",
      "logging" => "logging_checker.py",
      "auth" => "auth_checker.py",
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

// Default list of commonly vulnerable or interesting ports (override from UI)
$DEFAULT_VULN_PORTS = "20,21,22,23,25,53,67,68,69,80,110,119,123,137,138,139,143,161,162,389,443,445,465,514,636,993,995,1433,1521,3306";

// Icons for tools (emoji fallback)
$ICONS = array(
  "tech" => "🧭",
  "headers" => "📄",
  "clickjacking" => "🖼️",
  "cookies" => "🍪",
  "robots" => "🤖",
  "dns" => "🌐",
  "spf-dmarc" => "📧",
  "waf" => "🛡️",
  "links" => "🔗",
  "sensitive-data" => "🔐",
  "sitemap" => "🗺️",
  "subdomain" => "🏷️",
  "dirbust" => "📂",
  "admin" => "👤",
  "cors" => "🌍",
  "http-methods" => "⚙️",
  "screenshot" => "📸",
  "insecure-forms" => "✉️",
  "dom-xss" => "🧩",
  "xss" => "💥",
  "sqli" => "🧨",
  "open-redirect" => "➡️",
  "traversal" => "🕳️",
  "nmap" => "🔎",
  "firewall" => "🧱",
  "tls" => "🔐",
  "integrity" => "🧾",
  "config" => "⚙️",
  "logging" => "📣",
  "auth" => "🔑",
  "ping" => "📶",
  "traceroute" => "🛰️",
  "diagnose" => "🩺",
);

function respond_json($obj) {
    header('Content-Type: application/json');
    echo json_encode($obj);
    exit;
}

function stream_json_line($obj) {
  echo json_encode($obj) . "\n";
  if (ob_get_level()) { @ob_flush(); }
  @flush();
}

// Call the local LLM server to get a short analysis for a script's output.
function call_llm_php($script, $findings, $suggestions, $output, $reason = '', $mode = 'structured') {
  $llm_url = getenv('LLM_SERVER_URL') ?: 'http://ashy.tplinkdns.com:5005/ask';
  $prompt = "AI SECURITY ANALYSIS\nTest: $script\n";
  $prompt .= "Analyze the following raw scanner output and identify security implications.\n";

  if ($output) {
    // Increase excerpt size for better LLM context (up to 4000 chars)
    $excerpt = substr($output, 0, 4000);
    $prompt .= "\nRaw Output Excerpt:\n" . $excerpt;
  }

  $system = 'You are an expert security analyst. Analyze the provided scanner output and respond ONLY with a valid JSON object. Do not include any other text.
  Keys required:
  "summary": A concise overview of the results (2-3 sentences).
  "reason": Describe what you think the technical purpose or reason for running this specific test is, based on the output.
  "findings": A list or summary of specific vulnerabilities or security concerns you identified.
  "remediation": Actionable suggestions to mitigate the identified risks.';
  
  // If caller requested free-text mode, do not include a strict system prompt forcing JSON
  $payload_array = array('prompt' => $prompt);
  if ($mode === 'free-text') {
    // leave payload without system prompt so assistant may reply in free form
  } else {
    $payload_array['system_prompt'] = $system;
  }
  $payload = json_encode($payload_array);

  // Debug log to server error log for troubleshooting
  error_log("LLM request for $script to $llm_url; prompt length=" . strlen($prompt));

  // If streaming, send prompt to client for debug console and indicate LLM started
  if ((isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream'])) {
    stream_json_line(array('type' => 'llm_request', 'script' => $script, 'prompt' => $prompt));
    // indicate the LLM invocation has started (client can show pending/attempts)
    stream_json_line(array('type' => 'llm_status', 'script' => $script, 'status' => 'started'));
  }

  // Support configurable timeout (env LLM_TIMEOUT) and a simple retry mechanism
  $llm_timeout = intval(getenv('LLM_TIMEOUT') ?: 30);
  $max_attempts = intval(getenv('LLM_RETRIES') ?: 2);
  $resp = false; $err = ''; $code = 0;
  for ($attempt = 1; $attempt <= $max_attempts; $attempt++) {
    // announce the attempt when streaming
    if ((isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream'])) {
      stream_json_line(array('type' => 'llm_status', 'script' => $script, 'status' => 'attempt', 'attempt' => $attempt));
    }

    $ch = curl_init($llm_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_TIMEOUT, $llm_timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    $start = microtime(true);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    $dur = round(microtime(true) - $start, 2);
    error_log("LLM attempt $attempt/$max_attempts for $script: HTTP $code, err='" . $err . "', dur={$dur}s, resp_len=" . strlen($resp));
    if (!$err && $code >= 200 && $code < 300 && $resp) break;
    // announce attempt-level error to UI
    if ((isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream'])) {
      stream_json_line(array('type' => 'llm_status', 'script' => $script, 'status' => 'attempt_error', 'attempt' => $attempt, 'http_code' => $code, 'err' => $err));
    }
    // small backoff before retrying
    if ($attempt < $max_attempts) { usleep(300000); }
  }
  $out = array('analysis' => '', 'raw' => '');
  // Surface curl/network errors into analysis so UI shows diagnostics
  if ($err) {
    $out['raw'] = '';
    $out['analysis'] = 'LLM request error: ' . $err;
    // stream error to client when streaming
    if ((isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream'])) {
      stream_json_line(array('type' => 'llm_error', 'script' => $script, 'message' => $out['analysis']));
    }
    return $out;
  }
  if (!$resp || $code < 200 || $code >= 300) {
    $out['raw'] = $resp ?: '';
    $out['analysis'] = "LLM server returned HTTP $code" . ($resp ? ": " . substr($resp,0,200) : '');
    if ((isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream'])) {
      stream_json_line(array('type' => 'llm_error', 'script' => $script, 'message' => $out['analysis']));
    }
    return $out;
  }

  if ($resp && $code >= 200 && $code < 300) {
    // Store the raw curl response
    $out['raw'] = $resp;
    $json = json_decode($resp, true);
    if ($json && isset($json['response'])) {
      // LLM server wrapped assistant reply in a 'response' field
      $resp_text = trim($json['response']);
    } else {
      // Some LLM servers return plain text directly; treat entire body as assistant text
      $resp_text = trim($resp);
    }
    $out['raw'] = $resp_text;
    // Try to parse assistant's reply as JSON (assistant may return structured JSON)
    $parsed = json_decode($resp_text, true);
    if ($parsed && is_array($parsed)) {
      $parts = array();
      if (isset($parsed['summary'])) $parts[] = 'Summary: ' . trim($parsed['summary']);
      if (isset($parsed['reason'])) $parts[] = 'Inferred Purpose: ' . trim($parsed['reason']);
      if (isset($parsed['findings'])) {
        $f = $parsed['findings'];
        $parts[] = 'AI Findings: ' . (is_array($f) ? implode('; ', $f) : trim($f));
      }
      if (isset($parsed['remediation'])) {
        $rem = $parsed['remediation'];
        if (is_array($rem)) $parts[] = 'Remediation: ' . implode('; ', $rem);
        else $parts[] = 'Remediation: ' . trim($rem);
      }
      if (isset($parsed['notes'])) $parts[] = 'Notes: ' . trim($parsed['notes']);
      $out['analysis'] = trim(implode("\n", $parts));
    } else {
      // fallback: use raw assistant text
      $out['analysis'] = $resp_text;
    }
    // stream result to client when streaming (analysis and raw may be large; truncate raw to 2k)
    if ((isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream'])) {
      stream_json_line(array('type' => 'llm_result', 'script' => $script, 'analysis' => $out['analysis'], 'raw' => substr($out['raw'],0,2000)));
    }
  }
  return $out;
}

// Direct LLM call helper for follow-up questions. Returns array with keys: response (parsed/fallback), raw (raw assistant reply), code, error
function call_llm_direct($prompt, $system = null, $timeout = 12) {
  $llm_url = getenv('LLM_SERVER_URL') ?: 'http://ashy.tplinkdns.com:5005/ask';
  $payload = array('prompt' => $prompt);
  if ($system) $payload['system_prompt'] = $system;
  $payload_json = json_encode($payload);

  // log request for debugging
  error_log("LLM direct request to $llm_url; prompt_len=" . strlen($prompt));

  $ch = curl_init($llm_url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $payload_json);
  curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
  curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
  $resp = curl_exec($ch);
  $err = curl_error($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  curl_close($ch);

  if ($err) {
    error_log("LLM direct curl error: " . $err);
  }

  $out = array('response' => '', 'raw' => $resp ?: '', 'code' => $code, 'error' => $err);
  if ($resp && $code >= 200 && $code < 300) {
    $json = json_decode($resp, true);
    if ($json && isset($json['response'])) {
      $resp_text = trim($json['response']);
      $out['raw'] = $resp_text;
    // try to parse JSON returned by assistant
    $parsed = json_decode($resp_text, true);
    if ($parsed && is_array($parsed)) {
      // if assistant returned structured JSON, return it under 'response'
      $out['response'] = $parsed;
    } else {
      $out['response'] = $resp_text;
    }
  }
  }
  return $out;
}

// Return scripts and level metadata
if ($method === 'GET' && $action === 'scripts') {
  respond_json(array('scripts' => array_keys($SCRIPTS), 'labels' => $SCRIPTS, 'levels' => $AUDIT_LEVELS, 'icons' => $ICONS));
}

// Stop control endpoints (create/clear a stop-flag file)
$stop_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security_stop';
$pid_file = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security_pids';
// helper: add pid to pid file
function add_pid_to_file($pid_file, $pid) {
  if (!$pid) return;
  @file_put_contents($pid_file, $pid . "\n", FILE_APPEND | LOCK_EX);
}
function remove_pid_from_file($pid_file, $pid) {
  if (!file_exists($pid_file)) return;
  $data = @file($pid_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
  if (!$data) { @unlink($pid_file); return; }
  $data = array_filter($data, function($v) use ($pid) { return trim($v) != trim($pid); });
  if (count($data)) @file_put_contents($pid_file, implode("\n", $data) . "\n", LOCK_EX); else @unlink($pid_file);
}
if ($method === 'POST' && $action === 'stop_all') {
  @file_put_contents($stop_file, "1");
  // attempt to kill any tracked pids
  if (file_exists($pid_file)) {
    $pids = file($pid_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($pids) {
      foreach ($pids as $pid) {
        $pid = intval($pid);
        if ($pid <= 0) continue;
        // Best-effort: try to terminate the process, its group, and its children.
        // 1) posix_kill on PID
        if (function_exists('posix_kill')) {
          @posix_kill($pid, SIGTERM);
        }
        // 2) kill process (normal) and process group (negative PID)
        @exec("kill -TERM $pid 2>/dev/null");
        @exec("kill -TERM -$pid 2>/dev/null");
        // give it a moment
        usleep(200000);
        // 3) try to kill child processes
        @exec("pkill -P $pid 2>/dev/null");
        // 4) escalate to KILL on pid and group
        if (function_exists('posix_kill')) {
          @posix_kill($pid, SIGKILL);
        }
        @exec("kill -KILL $pid 2>/dev/null");
        @exec("kill -KILL -$pid 2>/dev/null");
        @exec("pkill -9 -P $pid 2>/dev/null");
      }
    }
    @unlink($pid_file);
  }
  respond_json(array('ok' => true, 'msg' => 'stop requested'));
}
if ($method === 'POST' && $action === 'clear_stop') {
  if (file_exists($stop_file)) { @unlink($stop_file); }
  if (file_exists($pid_file)) { @unlink($pid_file); }
  respond_json(array('ok' => true, 'msg' => 'cleared'));
}

// Handle LLM connection test
if ($method === 'GET' && $action === 'test_llm') {
  $prompt = "Respond with 'Connected'";
  $res = call_llm_direct($prompt, "You are a connectivity tester.", 5);
  $llm_url = getenv('LLM_SERVER_URL') ?: 'http://ashy.tplinkdns.com:5005/ask';
  respond_json(array(
    'ok' => ($res['code'] >= 200 && $res['code'] < 300),
    'llm' => $res,
    'url' => $llm_url,
    'method' => 'POST'
  ));
}

// Handle follow-up LLM ask requests from the UI
if ($method === 'POST' && $action === 'ask_llm') {
  $body = json_decode(file_get_contents('php://input'), true);
  if (!$body) { respond_json(array('error' => 'Invalid JSON body')); }
  $script = isset($body['script']) ? $body['script'] : 'unknown';
  $question = isset($body['question']) ? $body['question'] : '';
  $context = isset($body['context']) ? $body['context'] : '';
  if (!$question) { respond_json(array('error' => 'Missing question')); }

  $prompt = "Follow-up question about script: $script\n";
  if ($context) {
    $prompt .= "Context (previous assistant reply or output excerpt):\n" . substr($context,0,2000) . "\n\n";
  }
  $prompt .= "Question:\n" . $question . "\n";

  $system = 'You are a concise security analyst. Respond with JSON: {"answer":string, "notes": optional string}. Keep replies short.';
  $res = call_llm_direct($prompt, $system, 20);
  // normalize response: if parsed JSON present return it, otherwise return raw text under answer
  $out = array('ok' => true, 'script' => $script, 'question' => $question, 'llm' => $res);
  // respond JSON
  header('Content-Type: application/json'); echo json_encode($out); exit;
}

// Handle run request
if ($method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);
    if (!$body) { respond_json(array('error' => 'Invalid JSON body')); }

    // Allow caller to opt-out of LLM queries (default: enabled)
    $enable_llm = isset($body['llm']) ? boolval($body['llm']) : true;
    // Respect LLM response mode from client: 'structured' or 'free-text'
    $llm_mode = isset($body['llm_mode']) ? $body['llm_mode'] : 'structured';

    $url = isset($body['url']) ? $body['url'] : null;
    if (!$url) { respond_json(array('error' => 'Missing url parameter')); }
    if (strpos($url, '://') === false) { $url = 'http://' . $url; }

    $tests = isset($body['tests']) ? $body['tests'] : null;
    $level = isset($body['level']) ? $body['level'] : null;
    $ports = isset($body['ports']) ? $body['ports'] : $DEFAULT_VULN_PORTS;
    $scan_type = isset($body['scan_type']) ? $body['scan_type'] : 'ack';
    $include_mitigation = isset($body['include_mitigation']) ? boolval($body['include_mitigation']) : false;
    $prefer_connect_scan = isset($body['prefer_connect_scan']) ? boolval($body['prefer_connect_scan']) : true;

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
    $stream = (isset($_SERVER['HTTP_X_STREAM']) && $_SERVER['HTTP_X_STREAM'] === '1') || isset($_GET['stream']);
    if ($stream) {
      header('Content-Type: text/plain');
      header('Cache-Control: no-cache');
      // disable implicit output buffering where possible
      if (function_exists('apache_setenv')) { @apache_setenv('no-gzip', '1'); }
      ini_set('output_buffering', '0');
      ini_set('zlib.output_compression', '0');
      while (ob_get_level() > 0) { ob_end_flush(); }
      echo "STREAM-START\n"; if (ob_get_level()) { @ob_flush(); } @flush();
    }

    $aggregated_llm_ideas = array();
    // Ensure any previous stop flag and pid file are cleared at run start
    if (file_exists($stop_file)) { @unlink($stop_file); }
    if (file_exists($pid_file)) { @unlink($pid_file); }
    foreach ($tests_to_run as $t) {
      // Check for a stop request before starting a new test
      if (file_exists($stop_file)) break;

      $entry = array('script' => $t, 'script_path' => '', 'stdout' => '', 'stderr' => '', 'findings' => array(), 'ai_analysis' => '');

      // Special-case: run nmap directly (if selected)
      if ($t === 'nmap') {
        // get host from URL
        $host = parse_url($url, PHP_URL_HOST);
        if (!$host) { $host = preg_replace('#^https?://#', '', $url); $host = preg_replace('#/.*$#', '', $host); }
        $entry['script_path'] = 'nmap';
        if (!function_exists('exec')) { $entry['stderr'] = 'exec() not available on this PHP build'; $results[] = $entry; if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); } continue; }
        $python = 'python3';
        $conn_script = __DIR__ . DIRECTORY_SEPARATOR . 'simple_connect_scan.py';
        $timeout = 'timeout 180s';
        $script_timeout = 180;
        $cmd = 'exec ' . $timeout . ' ' . escapeshellcmd($python) . ' ' . escapeshellarg($conn_script) . ' ' . escapeshellarg($host) . ' --ports ' . escapeshellarg($ports) . ' --timeout 1.5 --workers 50 2>&1';
        if ($stream) { stream_json_line(array('type' => 'start', 'script' => $t, 'timeout' => $script_timeout, 'cmd' => $cmd)); }
        $entry['cmd'] = $cmd;
        $entry_stdout = '';
        $entry_stderr = '';
        $descriptorspec = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
        $process = @proc_open($cmd, $descriptorspec, $pipes);
        if (is_resource($process)) {
          $pinfo = proc_get_status($process);
          $ppid = isset($pinfo['pid']) ? intval($pinfo['pid']) : 0;
          if ($ppid) { add_pid_to_file($pid_file, $ppid); }
          fclose($pipes[0]);
          stream_set_blocking($pipes[1], false);
          stream_set_blocking($pipes[2], false);
          while (true) {
            $status = proc_get_status($process);
            $running = $status['running'];
            $read = array();
            if (!feof($pipes[1])) $read[] = $pipes[1];
            if (!feof($pipes[2])) $read[] = $pipes[2];
            if ($read) {
              $write = null; $except = null;
              $n = @stream_select($read, $write, $except, 0, 200000);
              if ($n > 0) {
                foreach ($read as $rpipe) {
                  $chunk = fgets($rpipe);
                  if ($chunk !== false) {
                    if ($rpipe === $pipes[1]) {
                      $entry_stdout .= $chunk;
                      if ($stream) {
                        stream_json_line(array('type' => 'chunk', 'script' => $t, 'chunk' => $chunk, 'stdout' => $entry_stdout));
                      }
                    } else {
                      $entry_stderr .= $chunk;
                      if ($stream) {
                        stream_json_line(array('type' => 'chunk', 'script' => $t, 'chunk' => $chunk, 'stderr' => $entry_stderr));
                      }
                    }
                  }
                }
              }
            }
            // Check for a stop request
            if (file_exists($stop_file)) {
              @proc_terminate($process);
              if (!empty($ppid)) {
                if (function_exists('posix_kill')) { @posix_kill($ppid, SIGTERM); @posix_kill($ppid, SIGKILL); }
                else { @exec("kill -TERM $ppid 2>/dev/null"); @exec("kill -KILL $ppid 2>/dev/null"); }
              }
              $entry_stderr = $entry_stderr ?: 'Stopped by user';
              break;
            }
            if (!$running) break;
            usleep(100000);
          }
          fclose($pipes[1]); fclose($pipes[2]);
          $ret = proc_close($process);
          if (!empty($ppid)) { remove_pid_from_file($pid_file, $ppid); }
        } else {
          $entry_stderr = 'Failed to start process';
          $ret = 1;
        }
        $stdout = $entry_stdout;
        $entry['stdout'] = $stdout;
        if ($ret !== 0) {
          if ($ret === -1) {
            $entry['stderr'] = $entry_stderr ?: "Process terminated or timed out";
          } else {
            $entry['stderr'] = $entry_stderr ?: "Exit code: $ret";
          }
        }
        foreach (explode("\n", $entry_stdout) as $line) {
          if (preg_match('/^(\d+)\/tcp\s+(open|closed|filtered)/i', $line, $m)) { $entry['findings'][] = trim($line); }
        }
        // Query the LLM server for a short AI analysis (non-blocking best-effort)
        if (!empty($enable_llm)) {
          try {
            $reason = $level ? "Selected level: $level" : (isset($body['tests']) ? "User selected specific tests" : "Default/basic level run");
            if (!empty($include_mitigation)) { $reason .= " | Include mitigation tips: yes"; }
            $aiobj = call_llm_php($t, $entry['findings'], $entry['findings'], $entry['stdout'], $reason, $llm_mode);
            if ($aiobj && is_array($aiobj)) {
              if (!empty($aiobj['analysis'])) { $entry['ai_analysis'] = $aiobj['analysis']; }
              if (!empty($aiobj['raw'])) { $entry['ai_raw'] = $aiobj['raw']; }
              if (!empty($aiobj['analysis'])) { $aggregated_llm_ideas[] = array('script' => $t, 'analysis' => $aiobj['analysis']); }
            }
          } catch (Exception $e) { /* ignore LLM failures */ }
        }
        $results[] = $entry;
        if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); }
        continue;
      }

      // Special-case: firewall probe using nmap ACK scan to detect filtered ports
      if ($t === 'firewall') {
        // get host from URL
        $host = parse_url($url, PHP_URL_HOST);
        if (!$host) { $host = preg_replace('#^https?://#', '', $url); $host = preg_replace('#/.*$#', '', $host); }
        $entry['script_path'] = 'nmap-firewall';
        if (!function_exists('exec')) { $entry['stderr'] = 'exec() not available on this PHP build'; $results[] = $entry; if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); } continue; }
        $python = 'python3';
        $conn_script = __DIR__ . DIRECTORY_SEPARATOR . 'simple_connect_scan.py';
        $timeout = 'timeout 180s';
        $script_timeout = 180;
        $cmd = 'exec ' . $timeout . ' ' . escapeshellcmd($python) . ' ' . escapeshellarg($conn_script) . ' ' . escapeshellarg($host) . ' --ports ' . escapeshellarg($ports) . ' --timeout 1.5 --workers 50 2>&1';
        if ($stream) { stream_json_line(array('type' => 'start', 'script' => $t, 'timeout' => $script_timeout, 'cmd' => $cmd)); }
        $entry['cmd'] = $cmd;
        $entry_stdout = '';
        $entry_stderr = '';
        $descriptorspec = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
        $process = @proc_open($cmd, $descriptorspec, $pipes);
        if (is_resource($process)) {
          $pinfo = proc_get_status($process);
          $ppid = isset($pinfo['pid']) ? intval($pinfo['pid']) : 0;
          if ($ppid) { add_pid_to_file($pid_file, $ppid); }
          fclose($pipes[0]);
          stream_set_blocking($pipes[1], false);
          stream_set_blocking($pipes[2], false);
          while (true) {
            $status = proc_get_status($process);
            $running = $status['running'];
            $read = array();
            if (!feof($pipes[1])) $read[] = $pipes[1];
            if (!feof($pipes[2])) $read[] = $pipes[2];
            if ($read) {
              $write = null; $except = null;
              $n = @stream_select($read, $write, $except, 0, 200000);
              if ($n > 0) {
                foreach ($read as $rpipe) {
                  $chunk = fgets($rpipe);
                  if ($chunk !== false) {
                    if ($rpipe === $pipes[1]) {
                      $entry_stdout .= $chunk;
                      if ($stream) {
                        stream_json_line(array('type' => 'chunk', 'script' => $t, 'chunk' => $chunk, 'stdout' => $entry_stdout));
                      }
                    } else {
                      $entry_stderr .= $chunk;
                      if ($stream) {
                        stream_json_line(array('type' => 'chunk', 'script' => $t, 'chunk' => $chunk, 'stderr' => $entry_stderr));
                      }
                    }
                  }
                }
              }
            }
            if (file_exists($stop_file)) {
              @proc_terminate($process);
              if (!empty($ppid)) {
                if (function_exists('posix_kill')) { @posix_kill($ppid, SIGTERM); @posix_kill($ppid, SIGKILL); }
                else { @exec("kill -TERM $ppid 2>/dev/null"); @exec("kill -KILL $ppid 2>/dev/null"); }
              }
              $entry_stderr = $entry_stderr ?: 'Stopped by user';
              break;
            }
            if (!$running) break;
            usleep(100000);
          }
          fclose($pipes[1]); fclose($pipes[2]);
          $ret = proc_close($process);
          if (!empty($ppid)) { remove_pid_from_file($pid_file, $ppid); }
        } else {
          $entry_stderr = 'Failed to start process';
          $ret = 1;
        }
        $stdout = $entry_stdout;
        $entry['stdout'] = $stdout;
        if ($ret !== 0) {
          if ($ret === -1) {
            $entry['stderr'] = $entry_stderr ?: "Process terminated or timed out";
          } else {
            $entry['stderr'] = $entry_stderr ?: "Exit code: $ret";
          }
        }
        // Parse connect-scan output for port states
        foreach (explode("\n", $entry_stdout) as $line) {
          if (preg_match('/^(\d+)\/tcp\s+(open|closed|filtered)/i', $line, $m)) { $entry['findings'][] = trim($line); }
        }
        // Query the LLM server for a short AI analysis (non-blocking best-effort)
        if (!empty($enable_llm)) {
          try {
            $reason = $level ? "Selected level: $level" : (isset($body['tests']) ? "User selected specific tests" : "Default/basic level run");
            if (!empty($include_mitigation)) { $reason .= " | Include mitigation tips: yes"; }
            $aiobj = call_llm_php($t, $entry['findings'], $entry['findings'], $entry['stdout'], $reason, $llm_mode);
            if ($aiobj && is_array($aiobj)) {
              if (!empty($aiobj['analysis'])) { $entry['ai_analysis'] = $aiobj['analysis']; }
              if (!empty($aiobj['raw'])) { $entry['ai_raw'] = $aiobj['raw']; }
              if (!empty($aiobj['analysis'])) { $aggregated_llm_ideas[] = array('script' => $t, 'analysis' => $aiobj['analysis']); }
            }
          } catch (Exception $e) { /* ignore LLM failures */ }
        }
        $results[] = $entry;
        if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); }
        continue;
      }

      if (!isset($SCRIPTS[$t])) { $entry['stderr'] = "Unknown script: $t"; $results[] = $entry; if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); } continue; }

      $script_path = __DIR__ . DIRECTORY_SEPARATOR . $SCRIPTS[$t];
      $entry['script_path'] = $script_path;
      if (!file_exists($script_path)) { $entry['stderr'] = "Script not found: $script_path"; $results[] = $entry; if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); } continue; }

      // Build command. Use `timeout` to prevent long-running scripts (Linux utility)
      $python = 'python3';
      $timeout = 'timeout 60s';
      $script_timeout = 60;
      if ($t === 'dns' || $t === 'dns-whois' || $t === 'dns_whois_nslookup') { $timeout = 'timeout 120s'; $script_timeout = 120; }
      // give sitemap more time by default (crawling can be slow)
      if ($t === 'sitemap') { $timeout = 'timeout 300s'; $script_timeout = 300; }
      // pass host-only for tools that expect a hostname (ping/traceroute)
      $targetArg = $url;
      if ($t === 'ping' || $t === 'traceroute') {
        $host = parse_url($url, PHP_URL_HOST);
        if (!$host) { $host = preg_replace('#^https?://#', '', $url); $host = preg_replace('#/.*$#', '', $host); }
        $targetArg = $host;
      }
      $cmd = 'exec ' . $timeout . ' ' . escapeshellcmd($python) . ' ' . escapeshellarg($script_path) . ' ' . escapeshellarg($targetArg) . ' 2>&1';
      if ($stream) { stream_json_line(array('type' => 'start', 'script' => $t, 'timeout' => $script_timeout, 'cmd' => $cmd)); }
      $entry['cmd'] = $cmd;

      $entry_stdout = '';
      $entry_stderr = '';
      $descriptorspec = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
      $process = @proc_open($cmd, $descriptorspec, $pipes);
      if (is_resource($process)) {
        // track pid for stop/kill support
        $pinfo = proc_get_status($process);
        $ppid = isset($pinfo['pid']) ? intval($pinfo['pid']) : 0;
        if ($ppid) { add_pid_to_file($pid_file, $ppid); }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        while (true) {
          $read = array();
          if (!feof($pipes[1])) $read[] = $pipes[1];
          if (!feof($pipes[2])) $read[] = $pipes[2];
          
          if (!$read) {
            $status = proc_get_status($process);
            if (!$status['running']) break;
            usleep(50000);
            continue;
          }

          $write = null; $except = null;
          $n = @stream_select($read, $write, $except, 0, 100000);
          if ($n > 0) {
            foreach ($read as $rpipe) {
              $chunk = fread($rpipe, 8192);
              if ($chunk !== false && strlen($chunk) > 0) {
                if ($rpipe === $pipes[1]) {
                  $entry_stdout .= $chunk;
                  if ($stream) {
                    stream_json_line(array('type' => 'chunk', 'script' => $t, 'chunk' => $chunk, 'stdout' => $entry_stdout));
                  }
                } else {
                  $entry_stderr .= $chunk;
                  if ($stream) {
                    stream_json_line(array('type' => 'chunk', 'script' => $t, 'chunk' => $chunk, 'stderr' => $entry_stderr));
                  }
                }
              }
            }
          }
          
          // Check process status after trying to read
          $status = proc_get_status($process);
          if (!$status['running'] && feof($pipes[1]) && feof($pipes[2])) break;

          // Check for a stop request
          if (file_exists($stop_file)) {
            @proc_terminate($process);
            if (!empty($ppid)) {
              if (function_exists('posix_kill')) { @posix_kill($ppid, SIGTERM); @posix_kill($ppid, SIGKILL); }
              else { @exec("kill -TERM $ppid 2>/dev/null"); @exec("kill -KILL $ppid 2>/dev/null"); }
            }
            $entry_stderr = $entry_stderr ?: 'Stopped by user';
            break;
          }
          usleep(10000);
        }
        fclose($pipes[1]); fclose($pipes[2]);
        $ret = proc_close($process);
        // remove pid from tracking file
        if (!empty($ppid)) { remove_pid_from_file($pid_file, $ppid); }
      } else {
        $entry_stderr = 'Failed to start process';
        $ret = 1;
      }
      $stdout = $entry_stdout;
      $entry['stdout'] = $stdout;
      if ($ret !== 0) {
        if ($ret === -1) {
          $entry['stderr'] = $entry_stderr ?: "Process terminated or timed out";
        } else {
          $entry['stderr'] = $entry_stderr ?: "Exit code: $ret";
        }
      }

      // find findings
      foreach (explode("\n", $stdout) as $line) {
        foreach ($VULN_KEYWORDS as $kw) {
          if (strpos($line, $kw) !== false) { $entry['findings'][] = trim($line); break; }
        }
      }

      // Query the LLM server for a short AI analysis (non-blocking best-effort)
      if (!empty($enable_llm)) {
        try {
            // Provide a reason string so the LLM knows why this test was run
            $reason = $level ? "Selected level: $level" : (isset($body['tests']) ? "User selected specific tests" : "Default/basic level run");
            $aiobj = call_llm_php($t, $entry['findings'], $entry['findings'], $entry['stdout'], $reason, $llm_mode);
            if ($aiobj && is_array($aiobj)) {
              if (!empty($aiobj['analysis'])) { $entry['ai_analysis'] = $aiobj['analysis']; }
              if (!empty($aiobj['raw'])) { $entry['ai_raw'] = $aiobj['raw']; }
              if (!empty($aiobj['analysis'])) { $aggregated_llm_ideas[] = array('script' => $t, 'analysis' => $aiobj['analysis']); }
          }
        } catch (Exception $e) { /* ignore LLM failures */ }
      }

      $results[] = $entry;
      if ($stream) { stream_json_line(array('type' => 'result', 'entry' => $entry)); }
    }

    // Build summary
    $summary = array();
    foreach ($results as $r) { foreach ($r['findings'] as $f) { $summary[] = "[" . strtoupper($r['script']) . "] " . $f; } }

    if ($stream) {
      $payload = array('type' => 'summary', 'summary' => $summary);
      if ($aggregated_llm_ideas) $payload['llm_ideas'] = $aggregated_llm_ideas;
      stream_json_line($payload);
      echo "STREAM-END\n";
      exit;
    }

    $respObj = array('url' => $url, 'results' => $results, 'summary' => $summary);
    if ($aggregated_llm_ideas) $respObj['llm_ideas'] = $aggregated_llm_ideas;
    respond_json($respObj);
}

// If GET without action, serve a simple UI that posts back to this file.
?><!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Audit (WARNING: ADVANCED LLM/AI)</title>
  <style>
    :root{--bg:#ffffff;--muted:#666;--panel:#fafafa;--accent:#2b7cff}
    body{font-family:system-ui,Arial,sans-serif;margin:20px;background:var(--bg);color:#111}
    label{display:block;margin:8px 0;color:var(--muted)}
    /* Tests grid */
    #tests{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:8px}
    label.test-card{display:flex;align-items:center;padding:12px;border-radius:10px;border:1px solid #e9eef8;background:#ffffff;cursor:pointer;transition:box-shadow .12s,transform .06s}
    label.test-card:hover{box-shadow:0 6px 18px rgba(43,124,255,0.08);transform:translateY(-2px)}
    label.test-card input{margin-right:12px;width:18px;height:18px;flex:0 0 auto}
    label.test-card .icon{font-size:18px;margin-right:8px;opacity:0.9}
    label.test-card .meta{display:flex;flex-direction:column}
    label.test-card .meta strong{font-size:14px;color:#0b2545}
    label.test-card .meta small{font-size:12px;color:#6b7a90;margin-top:4px}
    label.test-card .meta .status{font-size:12px;color:#6b7a90;margin-top:6px}
    label.test-card input:checked + .meta strong{color:var(--accent)}
    label.test-card.running{border-color:rgba(43,124,255,0.3);box-shadow:0 10px 30px rgba(43,124,255,0.06)}
    label.test-card.done{border-color:#dff3e6}
    label.test-card.error{border-color:#ffdede}
    /* spinner */
    .spinner{display:inline-block;width:14px;height:14px;border-radius:50%;border:2px solid rgba(0,0,0,0.08);border-top-color:var(--accent);animation:spin .9s linear infinite;vertical-align:middle;margin-left:6px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .card-progress{margin-top:8px}
    .card-progress-bar{transition:width .3s ease}
    .controls{margin:12px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
    input[type=text], input[type=url], input#url{padding:8px 10px;border:1px solid #e1e8ff;border-radius:8px;width:300px;background:#fbfdff}
    .btn{margin-right:8px;padding:8px 12px;border-radius:8px;border:0;background:var(--accent);color:#fff;cursor:pointer;box-shadow:0 6px 18px rgba(43,124,255,0.12)}
    .btn.ghost{background:#fff;color:var(--accent);border:1px solid #e6eef8;box-shadow:none}
    pre{background:#f7f7f7;color:#111;padding:8px;white-space:pre-wrap;border-radius:4px;border:1px solid #eee}
    .stderr{background:#fff5f5;color:#7a0000;padding:8px;border-radius:4px;border:1px solid #f2c6c6}
    .findings{background:#fff8e1;padding:8px;margin-top:8px;border-radius:4px}
    section.script-result{border:1px solid #eee;padding:8px;margin:8px 0;border-radius:6px;background:var(--panel)}
    h1{margin-top:0}
    /* LLM status animations */
    .pulse-dot.online { background: #28a745 !important; box-shadow: 0 0 0 rgba(40, 167, 69, 0.4); animation: pulse 2s infinite; }
    .pulse-dot.offline { background: #dc3545 !important; }
    @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(40, 167, 69, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(40, 167, 69, 0); } 100% { box-shadow: 0 0 0 0 rgba(40, 167, 69, 0); } }
  </style>
</head>
<body>
  <div style="display:flex; align-items:center; gap:15px; margin-bottom:10px;">
    <h1 style="margin:0;">Security Audit</h1>
    <div id="llm-status-badge" style="padding:4px 10px; border-radius:15px; background:#eee; font-size:12px; font-weight:bold; color:#666; display:flex; align-items:center; gap:6px;">
      <span class="pulse-dot" style="width:8px; height:8px; border-radius:50%; background:#bbb;"></span>
      LLM: <span id="llm-status-text">Checking...</span>
    </div>
    <button id="btn-test-llm" class="btn ghost" style="padding:4px 8px; font-size:11px;">Test Connection</button>
  </div>
  <label>Target URL: <input id="url" placeholder="example.com" type="text"></label>
  <div id="tests">
    <?php
      // Render checkboxes server-side as a fallback if JS fetch fails
      foreach ($SCRIPTS as $key => $file) {
        $id = 'chk_' . htmlspecialchars($key);
        $icon = isset($ICONS[$key]) ? $ICONS[$key] : '🔎';
        echo '<label class="test-card" data-key="' . htmlspecialchars($key) . '">';
        echo '<input type="checkbox" id="' . $id . '" value="' . htmlspecialchars($key) . '">';
        echo '<span class="icon">' . htmlspecialchars($icon) . '</span>';
        echo '<div class="meta">';
        echo '<strong>' . htmlspecialchars($key) . '</strong>';
        echo '<small>' . htmlspecialchars($file) . '</small>';
        echo '<span class="status">Idle</span>';
        echo '</div>';
        echo '</label>';
      }
    ?>
  </div>
  <div class="controls">
    <button id="select-all" class="btn ghost" title="Select all tests">Select All</button>
    <button id="clear-selection" class="btn ghost" title="Clear selection">Clear</button>
    <label style="margin-left:12px"><input type="checkbox" id="enable-llm" checked> Enable LLM analysis</label>
    <label style="margin-left:12px"><input type="checkbox" id="show-llm-debug"> Show LLM debug</label>
    <label style="margin-left:12px">LLM response mode:
      <select id="llm-response-mode"><option value="structured">Structured JSON (answer,severity,confidence)</option><option value="free-text">Free text</option></select>
    </label>
    <label>Ports to scan: <input id="ports" type="text" style="width:520px" value="<?php echo htmlspecialchars($DEFAULT_VULN_PORTS); ?>"></label>
    <label style="margin-left:12px">Nmap scan type:
      <select id="nmap-scan-type"><option value="ack">ACK (firewall probe)</option><option value="syn">SYN (stealth)</option><option value="udp">UDP</option></select>
    </label>
    <label style="margin-left:12px"><input type="checkbox" id="include-mitigation"> Include mitigation tips in AI analysis</label>
    <label style="margin-left:12px"><input type="checkbox" id="prefer-connect-scan" checked> Prefer unprivileged connect scan (no root required)</label>
    <label>Level:
      <select id="level"><option value="basic">basic</option><option value="advanced">advanced</option><option value="extreme">extreme</option></select>
    </label>
    <button id="run-selected" class="btn">Run Selected</button>
    <button id="run-level" class="btn">Run Level</button>
    <button id="run-all" class="btn">Run All</button>
    <button id="stop-all" class="btn ghost" style="background:#ff4d4d;color:#fff">Stop All</button>
    <div style="margin-left:12px; display:flex; align-items:center; gap:8px;">
      <textarea id="llm-global-question" rows="2" style="min-width:420px; max-width:720px;" placeholder="Ask any security question (no scan required)"></textarea>
      <button id="ask-llm-global" class="btn">Ask LLM</button>
    </div>
  </div>

  <h3>Summary</h3>
  <div id="summary"></div>
  <!-- LLM debug / prompt console (populated during scanning when LLM prompts are emitted) -->
  <div id="ai-console" style="margin-top:8px"></div>
  <div id="global-progress" style="margin:12px 0">
    <div style="height:10px;background:#eef5ff;border-radius:8px;overflow:hidden">
      <div id="global-progress-bar" style="height:10px;width:0%;background:linear-gradient(90deg,var(--accent),#6cc1ff);transition:width .2s;border-radius:8px"></div>
    </div>
  </div>
  <h3>Results</h3>
  <div id="results"></div>

  <script>
    // Configuration from PHP environment - defined globally for static/security.js
    window.LLM_SERVER_URL = '<?php echo htmlspecialchars(getenv("LLM_SERVER_URL") ?: "http://ashy.tplinkdns.com:5005/ask"); ?>';
    window.FOLLOWUP_SYSTEM_PROMPT = '<?php echo htmlspecialchars("You are a concise security analyst. Respond ONLY with a JSON object with keys: \"answer\" (string), \"severity\" (High|Medium|Low), and \"confidence\" (a number between 0.0 and 1.0). Do not include any other text outside the JSON."); ?>';
  </script>
  <script src="static/security.js"></script>
</body>
</html>
