"""Experiment client: a plain Python TLS client using the stdlib `ssl`
module's default context (the same code path `requests`/`urllib3`/
`http.client` build on). Connects through capture_proxy.py so the TLS bytes
are captured without needing root.

Usage (run BY capture_proxy.py, not directly):
    python -m tls_fingerprint.capture_proxy --mode tcp \\
        --target example.com:443 --listen-port 8445 --pcap pcaps/python_ssl.pcap \\
        -- python experiments/python_client.py 127.0.0.1 8445 example.com
"""

import socket
import ssl
import sys


def main() -> int:
    proxy_host, proxy_port, sni_hostname = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    context = ssl.create_default_context()
    raw_sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    with context.wrap_socket(raw_sock, server_hostname=sni_hostname) as tls_sock:
        request = f"GET / HTTP/1.1\r\nHost: {sni_hostname}\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(request.encode("ascii"))
        response = tls_sock.recv(200)
        print(f"python_client: TLS version={tls_sock.version()} cipher={tls_sock.cipher()}")
        print(f"python_client: first response bytes={response[:40]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
