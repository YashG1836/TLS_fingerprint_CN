"""Experiment client: a from-scratch TLS ClientHello, built byte-by-byte
with no TLS library at all (no `ssl` module, no OpenSSL binding) -- just a
raw TCP socket. This is the "custom/other TLS implementation" experiment:
it demonstrates that JA3 is purely a function of what bytes the client puts
on the wire, and that we can make those bytes -- and therefore the JA3
hash -- whatever we want by hand-assembling the ClientHello ourselves.

We connect directly to a real server (no capture_proxy relay needed: this
script already controls every byte it sends, and reads the real bytes the
server sends back over a normal socket).

We deliberately build a legacy-style TLS 1.2 ClientHello (no
supported_versions/key_share extensions) so a real server will complete a
plaintext-visible ServerHello + Certificate flight without us having to
implement ECDHE key generation just to finish a TLS 1.3 handshake -- we
only need the ServerHello for JA3S, not a fully established session.

Usage:
    python experiments/custom_client.py example.com 443 pcaps/custom_client.pcap
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tls_fingerprint.pcap_write import write_synthetic_pcap  # noqa: E402

# --- Cipher suites (real IANA-registered values, RFC 5246 / RFC 8422) -----
CIPHER_ECDHE_RSA_AES128_GCM_SHA256 = 0xC02F
CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xC02B
CIPHER_RSA_AES128_CBC_SHA = 0x002F
CIPHER_RSA_AES256_CBC_SHA = 0x0035

CIPHERS = [
    CIPHER_ECDHE_RSA_AES128_GCM_SHA256,
    CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256,
    CIPHER_RSA_AES128_CBC_SHA,
    CIPHER_RSA_AES256_CBC_SHA,
]

CURVE_X25519 = 0x001D
CURVE_SECP256R1 = 0x0017
CURVES = [CURVE_X25519, CURVE_SECP256R1]

SIG_ALG_RSA_PKCS1_SHA256 = 0x0401
SIG_ALG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_ALG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_ALGS = [SIG_ALG_RSA_PKCS1_SHA256, SIG_ALG_ECDSA_SECP256R1_SHA256, SIG_ALG_RSA_PSS_RSAE_SHA256]


def u16(v: int) -> bytes:
    return v.to_bytes(2, "big")


def u24(v: int) -> bytes:
    return v.to_bytes(3, "big")


def build_extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + u16(len(data)) + data


def build_server_name_extension(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    entry = b"\x00" + u16(len(name)) + name  # name_type=host_name(0)
    server_name_list = u16(len(entry)) + entry
    return build_extension(0x0000, server_name_list)


def build_supported_groups_extension(groups: list[int]) -> bytes:
    body = b"".join(u16(g) for g in groups)
    return build_extension(0x000A, u16(len(body)) + body)


def build_ec_point_formats_extension() -> bytes:
    return build_extension(0x000B, b"\x01\x00")  # 1 format: uncompressed(0)


def build_signature_algorithms_extension(algs: list[int]) -> bytes:
    body = b"".join(u16(a) for a in algs)
    return build_extension(0x000D, u16(len(body)) + body)


def build_client_hello(hostname: str) -> bytes:
    """Assemble a complete TLS record containing a ClientHello handshake
    message, per RFC 5246 section 7.4.1.2."""
    extensions = (
        build_server_name_extension(hostname)
        + build_supported_groups_extension(CURVES)
        + build_ec_point_formats_extension()
        + build_signature_algorithms_extension(SIG_ALGS)
    )

    client_version = u16(0x0303)  # TLS 1.2
    random_bytes = bytes(32)  # all-zero is fine: JA3 doesn't use Random
    session_id = b""  # empty: no session to resume
    cipher_bytes = b"".join(u16(c) for c in CIPHERS)
    compression_methods = b"\x00"  # null compression only

    body = (
        client_version
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + u16(len(cipher_bytes))
        + cipher_bytes
        + bytes([len(compression_methods)])
        + compression_methods
        + u16(len(extensions))
        + extensions
    )

    handshake_msg = bytes([0x01]) + u24(len(body)) + body  # 0x01 = ClientHello
    record = bytes([0x16]) + u16(0x0301) + u16(len(handshake_msg)) + handshake_msg
    return record


def main() -> int:
    hostname = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    pcap_out = sys.argv[3] if len(sys.argv) > 3 else "pcaps/custom_client.pcap"

    client_hello = build_client_hello(hostname)

    sock = socket.create_connection((hostname, port), timeout=10)
    local_ip, local_port = sock.getsockname()[0], sock.getsockname()[1]
    remote_ip, remote_port = sock.getpeername()[0], sock.getpeername()[1]

    sock.sendall(client_hello)

    response = bytearray()
    sock.settimeout(5)
    try:
        while len(response) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    except socket.timeout:
        pass
    sock.close()

    print(f"custom_client: sent {len(client_hello)}B ClientHello to {hostname}:{port}")
    print(f"custom_client: received {len(response)}B in response")

    write_synthetic_pcap(
        pcap_out,
        client_ip=local_ip,
        client_port=local_port,
        server_ip=remote_ip,
        server_port=remote_port,
        client_bytes=client_hello,
        server_bytes=bytes(response),
    )
    print(f"custom_client: wrote {pcap_out}")
    return 0 if response else 1


if __name__ == "__main__":
    raise SystemExit(main())
