"""TCP stream reassembly + raw TLS record/handshake parsing.

We deliberately do NOT use Scapy's built-in TLS layer. Real JA3 tooling
(including the original Salesforce ja3.py) parses the ClientHello/ServerHello
handshake bytes directly against the TLS RFC layout, because that keeps the
byte offsets auditable and avoids depending on a full TLS stack just to read
a handshake header. This module does the same thing, by hand, so every field
JA3/JA3S needs can be pointed at in a viva.

Byte layout this module walks (RFC 8446 / RFC 5246):

TLS record:      [1B ContentType][2B Version][2B Length][Length bytes payload]
Handshake msg:    [1B HandshakeType][3B Length][Length bytes body]
ClientHello body: [2B Version][32B Random]
                  [1B SessionIDLen][SessionIDLen bytes]
                  [2B CipherSuitesLen][CipherSuitesLen bytes, uint16 each]
                  [1B CompressionMethodsLen][that many bytes]
                  [2B ExtensionsLen][ExtensionsLen bytes]  (optional, may be absent)
ServerHello body: same shape as ClientHello except CipherSuite is a single
                  uint16 (the server's chosen suite) and there is no
                  CompressionMethods *list* -- just one chosen byte.
Extension:        [2B Type][2B Length][Length bytes data]
"""

from __future__ import annotations

from dataclasses import dataclass, field

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A  # a.k.a. "elliptic curves"
EXT_EC_POINT_FORMATS = 0x000B
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B


class TLSParseError(ValueError):
    """Raised when bytes don't look like a well-formed TLS record/handshake."""


@dataclass
class Extension:
    ext_type: int
    data: bytes


@dataclass
class ClientHelloInfo:
    version: int
    random: bytes
    session_id: bytes
    cipher_suites: list[int]
    compression_methods: list[int]
    extensions: list[Extension] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    ec_point_formats: list[int] = field(default_factory=list)
    server_name: str | None = None

    @property
    def extension_types(self) -> list[int]:
        return [e.ext_type for e in self.extensions]


@dataclass
class ServerHelloInfo:
    version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: list[Extension] = field(default_factory=list)

    @property
    def extension_types(self) -> list[int]:
        return [e.ext_type for e in self.extensions]


# ---------------------------------------------------------------------------
# TCP stream reassembly
# ---------------------------------------------------------------------------


def reassemble_tcp_stream(segments: list[tuple[int, bytes]]) -> bytes:
    """Reassemble a one-directional TCP byte stream from (seq, payload) pairs.

    Segments are ordered by sequence number and de-duplicated on seq, which
    correctly handles simple in-order captures (no packet loss, no
    retransmission reordering). Full RFC 793 reassembly (out-of-order
    delivery, partial-overlap coalescing) is out of scope for this MVP --
    the pcaps produced by our experiments and by short-lived local captures
    are clean single-path captures where this is sufficient. See
    docs/STUDY_GUIDE.md for the limitation note.
    """
    seen: dict[int, bytes] = {}
    for seq, payload in segments:
        if not payload:
            continue
        if seq not in seen:
            seen[seq] = payload
    ordered = [seen[seq] for seq in sorted(seen)]
    return b"".join(ordered)


# ---------------------------------------------------------------------------
# TLS record walking
# ---------------------------------------------------------------------------


def _iter_tls_records(stream: bytes):
    """Yield (content_type, version, payload) for each well-formed TLS record."""
    offset = 0
    n = len(stream)
    while offset + 5 <= n:
        content_type = stream[offset]
        version = int.from_bytes(stream[offset + 1 : offset + 3], "big")
        length = int.from_bytes(stream[offset + 3 : offset + 5], "big")
        record_start = offset + 5
        record_end = record_start + length
        if record_end > n:
            # Record body not fully present yet (truncated capture / MTU
            # split we couldn't reassemble). Stop rather than guess.
            break
        yield content_type, version, stream[record_start:record_end]
        offset = record_end


def _iter_handshake_messages(stream: bytes):
    """Yield (msg_type, body) for each handshake message found in the
    handshake-type (content_type 0x16) TLS records of `stream`.

    Handles a handshake message that is split across two or more TLS
    records by buffering handshake-record payloads until a complete
    message (per its own 3-byte length) is available.
    """
    buf = bytearray()
    for content_type, _version, payload in _iter_tls_records(stream):
        if content_type != CONTENT_TYPE_HANDSHAKE:
            continue
        buf.extend(payload)
        while len(buf) >= 4:
            msg_type = buf[0]
            msg_len = int.from_bytes(buf[1:4], "big")
            if len(buf) < 4 + msg_len:
                break  # message body not fully buffered yet
            body = bytes(buf[4 : 4 + msg_len])
            del buf[: 4 + msg_len]
            yield msg_type, body


def _parse_extensions(data: bytes, offset: int) -> list[Extension]:
    extensions: list[Extension] = []
    if offset >= len(data):
        return extensions
    if offset + 2 > len(data):
        return extensions
    ext_total_len = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    end = min(offset + ext_total_len, len(data))
    while offset + 4 <= end:
        ext_type = int.from_bytes(data[offset : offset + 2], "big")
        ext_len = int.from_bytes(data[offset + 2 : offset + 4], "big")
        ext_start = offset + 4
        ext_end = ext_start + ext_len
        if ext_end > end:
            break
        extensions.append(Extension(ext_type, data[ext_start:ext_end]))
        offset = ext_end
    return extensions


def _parse_supported_groups(ext_data: bytes) -> list[int]:
    if len(ext_data) < 2:
        return []
    list_len = int.from_bytes(ext_data[0:2], "big")
    body = ext_data[2 : 2 + list_len]
    return [
        int.from_bytes(body[i : i + 2], "big") for i in range(0, len(body) - 1, 2)
    ]


def _parse_ec_point_formats(ext_data: bytes) -> list[int]:
    if len(ext_data) < 1:
        return []
    list_len = ext_data[0]
    body = ext_data[1 : 1 + list_len]
    return list(body)


def _parse_server_name(ext_data: bytes) -> str | None:
    # server_name_list: 2B length, then entries [1B type][2B len][name]
    if len(ext_data) < 2:
        return None
    offset = 2
    while offset + 3 <= len(ext_data):
        name_type = ext_data[offset]
        name_len = int.from_bytes(ext_data[offset + 1 : offset + 3], "big")
        name_start = offset + 3
        name_end = name_start + name_len
        if name_end > len(ext_data):
            break
        if name_type == 0:  # host_name
            try:
                return ext_data[name_start:name_end].decode("ascii")
            except UnicodeDecodeError:
                return None
        offset = name_end
    return None


def parse_client_hello_body(body: bytes) -> ClientHelloInfo:
    """Parse the body of a ClientHello handshake message (after the 4-byte
    handshake header has already been stripped)."""
    if len(body) < 34:
        raise TLSParseError("ClientHello body too short")
    version = int.from_bytes(body[0:2], "big")
    random_bytes = body[2:34]
    offset = 34

    session_id_len = body[offset]
    offset += 1
    session_id = body[offset : offset + session_id_len]
    offset += session_id_len

    if offset + 2 > len(body):
        raise TLSParseError("ClientHello truncated at cipher suites length")
    cipher_suites_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    cipher_bytes = body[offset : offset + cipher_suites_len]
    offset += cipher_suites_len
    cipher_suites = [
        int.from_bytes(cipher_bytes[i : i + 2], "big")
        for i in range(0, len(cipher_bytes) - 1, 2)
    ]

    if offset >= len(body):
        raise TLSParseError("ClientHello truncated at compression methods")
    compression_len = body[offset]
    offset += 1
    compression_methods = list(body[offset : offset + compression_len])
    offset += compression_len

    extensions = _parse_extensions(body, offset)

    info = ClientHelloInfo(
        version=version,
        random=random_bytes,
        session_id=session_id,
        cipher_suites=cipher_suites,
        compression_methods=compression_methods,
        extensions=extensions,
    )
    for ext in extensions:
        if ext.ext_type == EXT_SUPPORTED_GROUPS:
            info.supported_groups = _parse_supported_groups(ext.data)
        elif ext.ext_type == EXT_EC_POINT_FORMATS:
            info.ec_point_formats = _parse_ec_point_formats(ext.data)
        elif ext.ext_type == EXT_SERVER_NAME:
            info.server_name = _parse_server_name(ext.data)
    return info


def parse_server_hello_body(body: bytes) -> ServerHelloInfo:
    """Parse the body of a ServerHello handshake message."""
    if len(body) < 34:
        raise TLSParseError("ServerHello body too short")
    version = int.from_bytes(body[0:2], "big")
    random_bytes = body[2:34]
    offset = 34

    session_id_len = body[offset]
    offset += 1
    session_id = body[offset : offset + session_id_len]
    offset += session_id_len

    if offset + 2 > len(body):
        raise TLSParseError("ServerHello truncated at cipher suite")
    cipher_suite = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2

    if offset >= len(body):
        raise TLSParseError("ServerHello truncated at compression method")
    compression_method = body[offset]
    offset += 1

    extensions = _parse_extensions(body, offset)

    return ServerHelloInfo(
        version=version,
        random=random_bytes,
        session_id=session_id,
        cipher_suite=cipher_suite,
        compression_method=compression_method,
        extensions=extensions,
    )


def find_client_hello(stream: bytes) -> ClientHelloInfo | None:
    """Scan a reassembled client->server byte stream for the first
    ClientHello handshake message and parse it. Returns None if absent."""
    for msg_type, msg_body in _iter_handshake_messages(stream):
        if msg_type == HANDSHAKE_CLIENT_HELLO:
            return parse_client_hello_body(msg_body)
    return None


def find_server_hello(stream: bytes) -> ServerHelloInfo | None:
    """Scan a reassembled server->client byte stream for the first
    ServerHello handshake message and parse it. Returns None if absent."""
    for msg_type, msg_body in _iter_handshake_messages(stream):
        if msg_type == HANDSHAKE_SERVER_HELLO:
            return parse_server_hello_body(msg_body)
    return None
