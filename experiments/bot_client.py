"""Experiment client: a script pretending, at the HTTP layer, to be Chrome
-- while its actual TLS stack is plain Python `ssl` (already known, from
python_client.py's own capture, to fingerprint completely differently from
real Chrome).

This is the "attacker" side of the bot-detection demo: a `User-Agent`
header is trivial to fake (it's just a text string the client chooses to
send) -- but the TLS ClientHello that got sent *before* that HTTP request
even existed is a much harder thing to fake convincingly, since it's
produced by whatever TLS library the program actually uses, not by a
string literal the author typed.

Usage (run BY capture_proxy.py, exactly like python_client.py):
    python -m tls_fingerprint.capture_proxy --mode tcp \\
        --target example.com:443 --listen-port 8470 --pcap pcaps/bot_client.pcap \\
        -- python experiments/bot_client.py 127.0.0.1 8470 example.com
"""

import socket
import ssl
import sys

FAKE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def main() -> int:
    proxy_host, proxy_port, sni_hostname = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    context = ssl.create_default_context()
    raw_sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    with context.wrap_socket(raw_sock, server_hostname=sni_hostname) as tls_sock:
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {sni_hostname}\r\n"
            f"User-Agent: {FAKE_USER_AGENT}\r\n"
            f"Connection: close\r\n\r\n"
        )
        tls_sock.sendall(request.encode("ascii"))
        response = tls_sock.recv(200)
        print(f"bot_client: sent fake User-Agent claiming to be Chrome")
        print(f"bot_client: actual TLS stack is Python's ssl module (real TLS version={tls_sock.version()})")
        print(f"bot_client: first response bytes={response[:40]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
