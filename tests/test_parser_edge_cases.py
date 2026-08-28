import pytest

from tls_fingerprint.ja3 import build_ja3_string
from tls_fingerprint.parser import (
    TLSParseError,
    find_client_hello,
    find_server_hello,
    parse_client_hello_body,
    reassemble_tcp_stream,
)
from tls_bytes import client_hello_record, ext_raw, u16, u24


def test_empty_stream_has_no_client_hello():
    assert find_client_hello(b"") is None


def test_non_handshake_content_type_is_ignored():
    # content_type 0x17 = application_data, not 0x16 = handshake.
    fake_record = bytes([0x17]) + u16(0x0303) + u16(5) + b"hello"
    assert find_client_hello(fake_record) is None


def test_truncated_record_length_stops_cleanly_instead_of_crashing():
    # Declares 100 bytes of payload but only provides 3 -- must not raise.
    truncated = bytes([0x16]) + u16(0x0301) + u16(100) + b"xyz"
    assert find_client_hello(truncated) is None


def test_parse_client_hello_body_too_short_raises():
    with pytest.raises(TLSParseError):
        parse_client_hello_body(b"\x03\x03\x00\x00")


def test_all_grease_ciphers_produce_empty_cipher_field():
    record = client_hello_record(version=0x0303, ciphers=[0x0A0A, 0x1A1A], extensions=b"")
    stream = reassemble_tcp_stream([(1, record)])
    hello = find_client_hello(stream)
    ja3 = build_ja3_string(hello)
    # version=771, ciphers empty, rest empty -> "771,,,,"
    assert ja3 == "771,,,,"


def test_multiple_handshake_messages_in_one_record_first_one_wins():
    # A ClientHello immediately followed by a second bogus handshake
    # message type in the same TLS record -- find_client_hello must return
    # the first ClientHello and ignore what follows.
    ch_record = client_hello_record(version=0x0303, ciphers=[0x1301], extensions=b"")
    extra_handshake_msg = bytes([0x0B]) + u24(3) + b"\x00\x00\x00"  # fake Certificate msg
    # Re-wrap: strip ch_record's own 5-byte TLS header, append extra
    # handshake bytes into the SAME record payload.
    header, handshake_bytes = ch_record[:5], ch_record[5:]
    combined_payload = handshake_bytes + extra_handshake_msg
    combined_record = bytes([0x16]) + header[1:3] + u16(len(combined_payload)) + combined_payload

    stream = reassemble_tcp_stream([(1, combined_record)])
    hello = find_client_hello(stream)
    assert hello is not None
    assert hello.cipher_suites == [0x1301]


def test_server_hello_with_unparseable_extension_length_is_still_found():
    # Extension claims more data than actually present -- parser should
    # stop collecting extensions rather than throwing.
    bad_ext = ext_raw(0x000A, b"\xff\xff")  # says "65535 bytes of groups" but gives 2
    from tls_bytes import server_hello_record

    record = server_hello_record(version=0x0303, cipher=0x1301, extensions=bad_ext)
    stream = reassemble_tcp_stream([(1, record)])
    hello = find_server_hello(stream)
    assert hello is not None
    assert hello.cipher_suite == 0x1301
