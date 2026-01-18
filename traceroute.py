#!/usr/bin/env python3
import sys
import subprocess
import shlex

def main():
    if len(sys.argv) < 2:
        print('Usage: traceroute.py <host>')
        sys.exit(2)
    host = sys.argv[1]
    # Prefer traceroute; fall back to tracepath if missing
    traceroute_cmd = None
    for candidate in ('traceroute', 'tracepath'):
        cmd_check = f"which {candidate}"
        if subprocess.call(cmd_check, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            traceroute_cmd = candidate
            break
    if not traceroute_cmd:
        print('No traceroute or tracepath utility found on the system')
        sys.exit(1)
    cmd = f"{traceroute_cmd} {shlex.quote(host)}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for line in proc.stdout:
            print(line.rstrip())
            sys.stdout.flush()
    except KeyboardInterrupt:
        proc.kill()
    rc = proc.wait()
    sys.exit(rc)

if __name__ == '__main__':
    main()
