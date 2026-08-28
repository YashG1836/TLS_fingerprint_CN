"""Root-free TLS handshake capture relay.

macOS requires root (BPF device access) to sniff packets off a NIC, which
we cannot do non-interactively in this environment (sudo needs a
password). Instead, this tool sits between a real client and a real server
at the TCP layer:

    client  --TCP-->  this relay  --TCP-->  real server (e.g. example.com:443)

It never terminates or inspects TLS -- it just forwards bytes verbatim in
both directions while also copying them into a buffer. Because it's a pure
byte pass-through, the TLS handshake happening "through" it is completely
real: the client validates the server's real certificate, and the
ClientHello/ServerHello bytes are exactly what the client/server actually
sent. Only the *capture method* differs from a NIC tap -- that's recorded
in the resulting pcap's provenance notes, never hidden.

Two modes:

  tcp      Fixed target given via --target host:port. Use for clients that
           support "connect to a different address but keep the original
           SNI/Host" (curl --connect-to, openssl s_client -connect +
           -servername, a raw Python socket).

  connect  Speaks a minimal HTTP CONNECT proxy (just enough for Chrome's
           --proxy-server flag). The target host:port is read from the
           client's CONNECT request line instead of a fixed --target.

Usage:
    python -m tls_fingerprint.capture_proxy --mode tcp \\
        --target example.com:443 --listen-port 8443 \\
        --pcap pcaps/curl.pcap --client-ip 127.0.0.1 \\
        -- curl --connect-to example.com:443:127.0.0.1:8443 -sS https://example.com/ -o /dev/null

    python -m tls_fingerprint.capture_proxy --mode connect \\
        --listen-port 8446 --pcap pcaps/chrome.pcap \\
        -- "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \\
        --headless=new --proxy-server=127.0.0.1:8446 --disable-quic \\
        --virtual-time-budget=8000 --dump-dom https://example.com/
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import threading
import time

from .pcap_write import write_synthetic_pcap

MAX_CAPTURE_BYTES = 65536
ACCEPT_TIMEOUT_SEC = 20
RELAY_IDLE_TIMEOUT_SEC = 15
SUBPROCESS_TIMEOUT_SEC = 30


def _relay_direction(src: socket.socket, dst: socket.socket, buf: bytearray, done: threading.Event):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            if len(buf) < MAX_CAPTURE_BYTES:
                buf.extend(data[: MAX_CAPTURE_BYTES - len(buf)])
            try:
                dst.sendall(data)
            except OSError:
                break
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        done.set()


def _read_connect_request(conn: socket.socket) -> tuple[str, int, bytes]:
    """Read an HTTP CONNECT request line + headers, return (host, port, leftover)."""
    buf = b""
    conn.settimeout(10)
    while b"\r\n\r\n" not in buf and len(buf) < 8192:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    header, _, leftover = buf.partition(b"\r\n\r\n")
    first_line = header.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    # "CONNECT host:port HTTP/1.1"
    parts = first_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        raise ValueError(f"expected CONNECT request, got: {first_line!r}")
    host, _, port_s = parts[1].rpartition(":")
    return host, int(port_s), leftover


def run(args: argparse.Namespace) -> int:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("127.0.0.1", args.listen_port))
    listen_sock.listen(5)
    actual_port = listen_sock.getsockname()[1]
    print(f"[capture_proxy] listening on 127.0.0.1:{actual_port} (mode={args.mode})")

    proc = None
    if args.client_cmd:
        print(f"[capture_proxy] launching client: {' '.join(args.client_cmd)}")
        proc = subprocess.Popen(args.client_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # In --mode connect, a browser may open other proxied requests first
    # (e.g. Chrome's network-time check on startup). Keep accepting
    # connections until we see a CONNECT for the host we actually care
    # about (or any CONNECT, if --expect-host wasn't given), politely
    # rejecting the rest so the browser moves on instead of hanging.
    deadline = time.monotonic() + args.accept_timeout
    conn = None
    client_addr = None
    leftover = b""
    target_host, target_port = args.target_host, args.target_port

    while time.monotonic() < deadline:
        listen_sock.settimeout(max(0.5, deadline - time.monotonic()))
        try:
            candidate, addr = listen_sock.accept()
        except socket.timeout:
            break

        if args.mode == "connect":
            try:
                host, port, lo = _read_connect_request(candidate)
            except (ValueError, OSError) as e:
                print(f"[capture_proxy] skipping non-CONNECT connection: {e}", file=sys.stderr)
                candidate.close()
                continue
            if args.expect_host and host != args.expect_host:
                print(f"[capture_proxy] skipping CONNECT to unexpected host {host}", file=sys.stderr)
                try:
                    candidate.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except OSError:
                    pass
                candidate.close()
                continue
            conn, client_addr, leftover = candidate, addr, lo
            target_host, target_port = host, port
        else:
            conn, client_addr = candidate, addr
        break

    listen_sock.close()
    if conn is None:
        print("[capture_proxy] ERROR: no matching client connection within timeout", file=sys.stderr)
        if proc:
            proc.kill()
        return 1

    client_to_server = bytearray()
    server_to_client = bytearray()

    print(f"[capture_proxy] relaying to real target {target_host}:{target_port}")
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.settimeout(10)
    try:
        upstream.connect((target_host, target_port))
    except OSError as e:
        print(f"[capture_proxy] ERROR connecting upstream: {e}", file=sys.stderr)
        conn.close()
        return 1
    upstream.settimeout(None)
    server_ip, server_port_actual = upstream.getpeername()[0], target_port

    if args.mode == "connect":
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        if leftover:
            client_to_server.extend(leftover[:MAX_CAPTURE_BYTES])
            upstream.sendall(leftover)

    conn.settimeout(None)
    done_cs = threading.Event()
    done_sc = threading.Event()
    t1 = threading.Thread(target=_relay_direction, args=(conn, upstream, client_to_server, done_cs))
    t2 = threading.Thread(target=_relay_direction, args=(upstream, conn, server_to_client, done_sc))
    t1.start()
    t2.start()
    t1.join(timeout=RELAY_IDLE_TIMEOUT_SEC)
    t2.join(timeout=RELAY_IDLE_TIMEOUT_SEC)

    for s in (conn, upstream):
        try:
            s.close()
        except OSError:
            pass

    if proc:
        try:
            proc.wait(timeout=SUBPROCESS_TIMEOUT_SEC)
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            print(f"[capture_proxy] client process exited {proc.returncode}")
            if args.show_client_output and out.strip():
                print("[capture_proxy] client output:\n" + out)
        except subprocess.TimeoutExpired:
            print("[capture_proxy] WARNING: client process did not exit, killing it", file=sys.stderr)
            proc.kill()

    client_local_port = client_addr[1]
    write_synthetic_pcap(
        args.pcap,
        client_ip=args.client_ip,
        client_port=client_local_port,
        server_ip=server_ip,
        server_port=server_port_actual,
        client_bytes=bytes(client_to_server),
        server_bytes=bytes(server_to_client),
    )
    print(
        f"[capture_proxy] captured {len(client_to_server)}B client->server, "
        f"{len(server_to_client)}B server->client -> {args.pcap}"
    )
    if len(client_to_server) == 0:
        print("[capture_proxy] WARNING: captured 0 bytes from client -- handshake likely failed", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["tcp", "connect"], required=True)
    parser.add_argument("--target", dest="target_raw", default=None, help="host:port (required for --mode tcp)")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--pcap", required=True, help="Output pcap path")
    parser.add_argument("--client-ip", default="127.0.0.1", help="IP to label as the client in the synthetic pcap")
    parser.add_argument("--show-client-output", action="store_true")
    parser.add_argument(
        "--expect-host",
        default=None,
        help="--mode connect only: ignore CONNECT requests to any other host (e.g. browser startup pings)",
    )
    parser.add_argument("--accept-timeout", type=int, default=ACCEPT_TIMEOUT_SEC)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" in argv:
        idx = argv.index("--")
        own_args, client_cmd = argv[:idx], argv[idx + 1 :]
    else:
        own_args, client_cmd = argv, []

    parser = build_parser()
    args = parser.parse_args(own_args)
    args.client_cmd = client_cmd

    if args.mode == "tcp":
        if not args.target_raw:
            parser.error("--target host:port is required for --mode tcp")
        host, _, port_s = args.target_raw.rpartition(":")
        args.target_host, args.target_port = host, int(port_s)
    else:
        args.target_host, args.target_port = None, None

    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
