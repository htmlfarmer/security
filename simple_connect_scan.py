#!/usr/bin/env python3
"""simple_connect_scan.py
Lightweight unprivileged TCP connect port scanner.
Prints lines like: 22/tcp open
"""
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_ports(s):
    parts = [p.strip() for p in s.split(',') if p.strip()]
    out = []
    for p in parts:
        if '-' in p:
            a, b = p.split('-', 1)
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(p))
    return sorted(set(out))


def probe(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, 'open'
    except ConnectionRefusedError:
        return port, 'closed'
    except socket.timeout:
        return port, 'filtered'
    except Exception:
        return port, 'filtered'


def main():
    p = argparse.ArgumentParser(description='Simple TCP connect port scanner')
    p.add_argument('host')
    p.add_argument('--ports', default='22,80,443', help='comma-separated ports or ranges (e.g. 20-25,80,443)')
    p.add_argument('--timeout', type=float, default=1.0)
    p.add_argument('--workers', type=int, default=50)
    args = p.parse_args()
    ports = parse_ports(args.ports)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(probe, args.host, port, args.timeout): port for port in ports}
        for fut in as_completed(futures):
            port, state = fut.result()
            print(f"{port}/tcp {state}")


if __name__ == '__main__':
    main()
