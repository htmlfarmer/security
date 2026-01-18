#!/usr/bin/env python3
"""
website_debug.py - simple diagnostic scanner for a URL/host.
Prints DNS resolution, TCP port checks, SSL cert info, redirect chain, HTTP status and headers, and robots.txt summary.
Streams output line-by-line for the UI.
"""
import sys
import socket
import ssl
import urllib.parse
import http.client
import time


def print_flush(s=''):
    print(s)
    sys.stdout.flush()


def resolve_host(host):
    print_flush(f"[DNS] Resolving {host}...")
    try:
        infos = socket.getaddrinfo(host, None)
        ips = []
        for info in infos:
            ips.append(info[4][0])
        ips = sorted(set(ips))
        for ip in ips:
            print_flush(f"[DNS] -> {ip}")
        return ips
    except Exception as e:
        print_flush(f"[DNS] Error: {e}")
        return []


def tcp_check(host, port, timeout=3):
    print_flush(f"[TCP] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        start = time.time()
        s.connect((host, port))
        elapsed = (time.time() - start) * 1000
        print_flush(f"[TCP] Connected to {host}:{port} ({int(elapsed)}ms)")
        s.close()
        return True
    except Exception as e:
        print_flush(f"[TCP] Failed: {e}")
        try:
            s.close()
        except:
            pass
        return False


def get_ssl_info(host, timeout=5):
    print_flush(f"[SSL] Retrieving certificate for {host}:443 ...")
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(timeout)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()
        subj = cert.get('subject', ())
        issuer = cert.get('issuer', ())
        notBefore = cert.get('notBefore')
        notAfter = cert.get('notAfter')
        # try to get CN
        cn = None
        for part in subj:
            for k,v in part:
                if k == 'commonName': cn = v
        issuer_cn = None
        for part in issuer:
            for k,v in part:
                if k == 'commonName': issuer_cn = v
        print_flush(f"[SSL] Subject CN: {cn}")
        print_flush(f"[SSL] Issuer: {issuer_cn}")
        print_flush(f"[SSL] Valid: {notBefore} -> {notAfter}")
        return cert
    except Exception as e:
        print_flush(f"[SSL] Error: {e}")
        return None


def fetch_url(url, max_redirects=8, timeout=8):
    visited = []
    current = url
    for i in range(max_redirects+1):
        visited.append(current)
        parsed = urllib.parse.urlparse(current)
        scheme = parsed.scheme or 'http'
        host = parsed.hostname
        port = parsed.port
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        print_flush(f"[HTTP] {scheme.upper()} request to {host}{path} (redirect #{i})")
        try:
            if scheme == 'https':
                conn = http.client.HTTPSConnection(host, port or 443, timeout=timeout)
            else:
                conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
            conn.request('GET', path, headers={'User-Agent': 'Website-Debug/1.0'})
            resp = conn.getresponse()
            status = resp.status
            reason = resp.reason
            headers = resp.getheaders()
            print_flush(f"[HTTP] Status: {status} {reason}")
            for h,v in headers:
                # only print key headers to reduce noise
                if h.lower() in ('server','content-type','content-length','location','set-cookie','cache-control','x-frame-options','strict-transport-security'):
                    print_flush(f"[HTTP] Header: {h}: {v}")
            # read a small body preview
            try:
                body = resp.read(1024)
                if body:
                    body_preview = body.decode('utf-8', errors='replace').strip().split('\n')[0]
                    print_flush(f"[HTTP] Body Preview: {body_preview[:200]}")
            except Exception as e:
                print_flush(f"[HTTP] Body read error: {e}")
            conn.close()
            # follow redirect
            if status in (301,302,303,307,308):
                loc = dict(headers).get('Location')
                if not loc:
                    print_flush('[HTTP] Redirect without Location header')
                    break
                # make absolute
                loc = urllib.parse.urljoin(current, loc)
                print_flush(f"[HTTP] Redirect -> {loc}")
                current = loc
                continue
            else:
                return {'final_url': current, 'status': status, 'headers': headers}
        except Exception as e:
            print_flush(f"[HTTP] Error: {e}")
            return {'error': str(e)}
    print_flush('[HTTP] Too many redirects')
    return {'error': 'too many redirects'}


def fetch_robots(host, scheme='http'):
    url = f"{scheme}://{host}/robots.txt"
    print_flush(f"[ROBOTS] Fetching {url}")
    try:
        parsed = urllib.parse.urlparse(url)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=6)
        conn.request('GET', '/robots.txt', headers={'User-Agent': 'Website-Debug/1.0'})
        resp = conn.getresponse()
        status = resp.status
        print_flush(f"[ROBOTS] Status: {status}")
        if status == 200:
            body = resp.read(2048).decode('utf-8', errors='replace')
            lines = [l.strip() for l in body.splitlines() if l.strip()]
            for ln in lines[:20]:
                print_flush(f"[ROBOTS] {ln}")
        conn.close()
    except Exception as e:
        print_flush(f"[ROBOTS] Error: {e}")


def main():
    if len(sys.argv) < 2:
        print_flush('Usage: website_debug.py <url_or_host>')
        sys.exit(2)
    target = sys.argv[1]
    print_flush(f"[DEBUG] Starting diagnostics for: {target}")
    parsed = urllib.parse.urlparse(target)
    host = parsed.hostname or target
    scheme = parsed.scheme or 'http'

    # DNS
    ips = resolve_host(host)

    # TCP checks
    ports = [80, 443]
    open_ports = []
    for p in ports:
        ok = tcp_check(host, p)
        if ok: open_ports.append(p)

    # SSL cert
    if 443 in open_ports:
        get_ssl_info(host)

    # HTTP fetch and redirect chain
    if scheme not in ('http','https'):
        scheme = 'http'
    http_res = fetch_url(f"{scheme}://{host}")
    if 'error' in http_res:
        print_flush(f"[DIAG] HTTP error: {http_res['error']}")
    else:
        print_flush(f"[DIAG] Final URL: {http_res.get('final_url')}")
        print_flush(f"[DIAG] Status: {http_res.get('status')}")

    # robots.txt
    fetch_robots(host, scheme=scheme)

    print_flush('[DEBUG] Diagnostics complete')

if __name__ == '__main__':
    main()
