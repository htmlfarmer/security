#!/usr/bin/env python3
import sys
import subprocess
import shlex
import re
import time
import statistics
import json

def main():
    if len(sys.argv) < 2:
        print('Usage: ping.py <host>')
        sys.exit(2)
    host = sys.argv[1]
    # Use system ping - send 10 packets for better analysis
    count = 10
    cmd = f"ping -c {count} {shlex.quote(host)}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    times = []
    seen_summary = False
    start = time.time()
    time_pattern = re.compile(r"time[=<]\s*([0-9]+\.?[0-9]*)\s*ms")
    try:
        for line in proc.stdout:
            line_str = line.rstrip()
            print(line_str)
            sys.stdout.flush()
            # capture reply times like 'time=33.974 ms'
            m = time_pattern.search(line_str)
            if m:
                try:
                    times.append(float(m.group(1)))
                except Exception:
                    pass
            # detect if system ping already printed summaries
            if 'packets transmitted' in line_str or 'packet loss' in line_str or line_str.startswith('rtt ') or line_str.startswith('round-trip'):
                seen_summary = True
    except KeyboardInterrupt:
        proc.kill()
    rc = proc.wait()
    end = time.time()

    # Always analyze the results
    transmitted = count
    received = len(times)
    loss_pct = int(round((transmitted - received) / transmitted * 100)) if transmitted > 0 else 0
    total_ms = int(round((end - start) * 1000))
    
    # If system didn't print a summary, print our computed one
    if not seen_summary:
        print(f"\n--- {host} ping statistics ---")
        print(f"{transmitted} packets transmitted, {received} received, {loss_pct}% packet loss, time {total_ms}ms")

    if times:
        mn = min(times)
        av = statistics.mean(times)
        mx = max(times)
        mdev = statistics.pstdev(times) if len(times) > 1 else 0.0
        if not seen_summary:
            print(f"rtt min/avg/max/mdev = {mn:.3f}/{av:.3f}/{mx:.3f}/{mdev:.3f} ms")

    # Analyze for anomalies
    findings = []
    suggestions = []

    if times:
        # Re-calculate stats to be safe
        
        # Check for packet loss
        if loss_pct > 0:
            findings.append(f"Packet loss detected: {loss_pct}% ({transmitted - received} of {transmitted} packets lost)")
            if loss_pct >= 50:
                suggestions.append("Critical packet loss (≥50%) indicates severe network issues or host unavailability")
            elif loss_pct >= 20:
                suggestions.append("High packet loss (≥20%) suggests network congestion, routing issues, or firewall interference")
            elif loss_pct >= 5:
                suggestions.append("Moderate packet loss (≥5%) may indicate intermittent network problems")
        else:
            findings.append(f"No packet loss detected ({received}/{transmitted} packets received)")
        
        # Check for latency spikes (response time > 2x average)
        spike_threshold = av * 2 if av > 0 else 200
        spikes = [t for t in times if t > spike_threshold]
        if spikes:
            findings.append(f"Latency spikes detected: {len(spikes)} responses exceeded 2x average ({spike_threshold:.1f}ms)")
            findings.append(f"Spike values: {', '.join([f'{s:.1f}ms' for s in spikes])}")
            suggestions.append("Latency spikes may indicate network congestion, CPU throttling, or intermittent routing issues")
        
        # Check for unusual response times
        if av > 200:
            findings.append(f"High average latency: {av:.1f}ms (typically <100ms is good)")
            suggestions.append("High latency may indicate distant server, network congestion, or slow routing path")
        elif av > 100:
            findings.append(f"Moderate average latency: {av:.1f}ms")
        
        # Check for high jitter (variation in latency)
        if mdev > 50:
            findings.append(f"High jitter detected: {mdev:.1f}ms standard deviation")
            suggestions.append("High jitter indicates inconsistent network performance; problematic for real-time applications")
        elif mdev > 20:
            findings.append(f"Moderate jitter: {mdev:.1f}ms standard deviation")
        
        # Check for unusually fast responses (potential ICMP deprioritization or local response)
        if av < 1 and mx < 5:
            findings.append(f"Unusually fast response times (avg: {av:.2f}ms)")
            suggestions.append("Very low latency may indicate local network host or cached response")
        
        # Variance between min and max
        if mx - mn > 100:
            findings.append(f"Large latency variance: min={mn:.1f}ms, max={mx:.1f}ms (range: {mx-mn:.1f}ms)")
            suggestions.append("Wide latency range suggests unstable connection or varying network paths")
    
    else:
        findings.append("No responses received - host may be down or blocking ICMP")
        suggestions.append("Verify host is online, check firewall rules, and ensure ICMP is not blocked")
    
    # Print analysis
    print("\n=== PING ANALYSIS ===")
    if findings:
        print("\nFindings:")
        for f in findings:
            print(f"  • {f}")
    
    if suggestions:
        print("\nSuggestions:")
        for s in suggestions:
            print(f"  • {s}")
    
    # Output JSON for programmatic access
    result = {
        'host': host,
        'transmitted': transmitted,
        'received': received,
        'loss_percent': loss_pct,
        'times': times,
        'findings': findings,
        'suggestions': suggestions
    }
    if times:
        result['stats'] = {
            'min': mn,
            'avg': av,
            'max': mx,
            'mdev': mdev,
            'spikes': len(spikes) if 'spikes' in locals() else 0
        }
    
    print(f"\n### JSON_OUTPUT ###\n{json.dumps(result)}\n### END_JSON ###")

    sys.exit(rc)

if __name__ == '__main__':
    main()
