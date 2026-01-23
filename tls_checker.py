#!/usr/bin/env python3
"""tls_checker.py
Checks TLS certificate validity and supported TLS versions (1.2/1.3).
"""
import ssl
import socket
import argparse
from datetime import datetime
from urllib.parse import urlparse


def get_cert(host, port=443, timeout=5):
    ctx = ssl.create_default_context()
    conn = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(conn, server_hostname=host)
    cert = sock.getpeercert()
    sock.close()
    return cert


def check_version_support(host, port=443, timeout=3):
    results = {}
    # try TLSv1.3 and TLSv1.2
    for proto_name, proto in (('TLSv1.3', ssl.PROTOCOL_TLS_CLIENT), ('TLSv1.2', ssl.TLSVersion.TLSv1_2 if hasattr(ssl, 'TLSVersion') else None)):
        try:
            # create context with minimum version
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if proto_name == 'TLSv1.3' and hasattr(ctx, 'minimum_version'):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            if proto_name == 'TLSv1.2' and hasattr(ctx, 'minimum_version'):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = socket.create_connection((host, port), timeout=timeout)
            s = ctx.wrap_socket(conn, server_hostname=host)
            s.close()
            results[proto_name] = True
        except Exception:
            results[proto_name] = False
    return results


def main():
    p = argparse.ArgumentParser(description='Check TLS certificate and protocol support')
    p.add_argument('host')
    args = p.parse_args()
    host = args.host
    # Accept either a bare host, host:port, or a full URL (http(s)://host[:port]/...)
    # Use urlparse for robust parsing and fall back to port 443.
    parsed = urlparse(host if '://' in host else '//' + host)
    netloc = parsed.netloc or parsed.path or host
    # strip possible trailing slashes
    netloc = netloc.rstrip('/')
    if ':' in netloc:
        h, pport = netloc.split(':', 1)
        try:
            port = int(pport)
        except Exception:
            port = 443
    else:
        h = netloc
        port = 443
    try:
        cert = get_cert(h, port)
    except Exception as e:
        print(f"Error fetching cert: {e}")
        return
    notbefore = cert.get('notBefore')
    notafter = cert.get('notAfter')
    subj = cert.get('subject')
    issuer = cert.get('issuer')
    print(f"Certificate subject: {subj}")
    print(f"Issuer: {issuer}")
    print(f"Valid from: {notbefore}")
    print(f"Valid until: {notafter}")
    try:
        exp = datetime.strptime(notafter, '%b %d %H:%M:%S %Y %Z')
        days = (exp - datetime.utcnow()).days
        print(f"Expires in: {days} days")
    except Exception:
        pass
    vers = check_version_support(h, port)
    print(f"Protocol support: {vers}")


if __name__ == '__main__':
    main()
