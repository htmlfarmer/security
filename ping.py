#!/usr/bin/env python3
import sys
import subprocess
import shlex
import re
import time
import statistics

def main():
    if len(sys.argv) < 2:
        print('Usage: ping.py <host>')
        sys.exit(2)
    host = sys.argv[1]
    # Use system ping - send 5 packets
    count = 5
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

    # If system didn't print a summary, print our computed one
    if not seen_summary:
        transmitted = count
        received = len(times)
        loss = int(round((transmitted - received) / transmitted * 100))
        total_ms = int(round((end - start) * 1000))
        print(f"\n--- {host} ping statistics ---")
        print(f"{transmitted} packets transmitted, {received} received, {loss}% packet loss, time {total_ms}ms")
        if times:
            mn = min(times)
            av = statistics.mean(times)
            mx = max(times)
            mdev = statistics.pstdev(times) if len(times) > 1 else 0.0
            print(f"rtt min/avg/max/mdev = {mn:.3f}/{av:.3f}/{mx:.3f}/{mdev:.3f} ms")

    sys.exit(rc)

if __name__ == '__main__':
    main()
