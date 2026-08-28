"""Helpers to hand-build synthetic TLS record bytes for unit tests.

Building the bytes by hand (rather than trusting a captured pcap) means the
expected JA3/JA3S string can be derived independently, field by field, from
the RFC layout -- so the test is checking the parser+JA3 code against the
spec, not against itself.
"""

from __future__ import annotations


def u16(v: int) -> bytes:
    return v.to_bytes(2, "big")


def u24(v: int) -> bytes:
    return v.to_bytes(3, "big")


def extension(ext_type: int, data: bytes) -> bytes:
    return u16(ext_type) + u16(len(data)) + data


def ext_server_name(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    entry = b"\x00" + u16(len(name)) + name  # type=host_name(0)
    server_name_list = u16(len(entry)) + entry
    return extension(0x0000, server_name_list)


def ext_supported_groups(groups: list[int]) -> bytes:
    body = b"".join(u16(g) for g in groups)
    data = u16(len(body)) + body
    return extension(0x000A, data)


def ext_ec_point_formats(formats: list[int]) -> bytes:
    body = bytes(formats)
    data = bytes([len(body)]) + body
    return extension(0x000B, data)


def ext_raw(ext_type: int, data: bytes = b"") -> bytes:
    return extension(ext_type, data)


def client_hello_record(
    version: int,
    ciphers: list[int],
    extensions: bytes,
    compression_methods: list[int] | None = None,
    session_id: bytes = b"",
    random_bytes: bytes | None = None,
) -> bytes:
    compression_methods = compression_methods or [0]
    random_bytes = random_bytes or (b"\x11" * 32)

    body = u16(version)
    body += random_bytes
    body += bytes([len(session_id)]) + session_id
    cipher_bytes = b"".join(u16(c) for c in ciphers)
    body += u16(len(cipher_bytes)) + cipher_bytes
    body += bytes([len(compression_methods)]) + bytes(compression_methods)
    body += u16(len(extensions)) + extensions

    handshake = bytes([0x01]) + u24(len(body)) + body  # ClientHello = 1
    record = bytes([0x16]) + u16(0x0301) + u16(len(handshake)) + handshake
    return record


def server_hello_record(
    version: int,
    cipher: int,
    extensions: bytes,
    compression_method: int = 0,
    session_id: bytes = b"",
    random_bytes: bytes | None = None,
) -> bytes:
    random_bytes = random_bytes or (b"\x22" * 32)

    body = u16(version)
    body += random_bytes
    body += bytes([len(session_id)]) + session_id
    body += u16(cipher)
    body += bytes([compression_method])
    body += u16(len(extensions)) + extensions

    handshake = bytes([0x02]) + u24(len(body)) + body  # ServerHello = 2
    record = bytes([0x16]) + u16(0x0301) + u16(len(handshake)) + handshake
    return record
