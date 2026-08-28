import hashlib

from tls_fingerprint.ja3s import build_ja3s_string, compute_ja3s
from tls_fingerprint.parser import find_server_hello, reassemble_tcp_stream
from tls_bytes import ext_raw, server_hello_record


def _hello_and_expected_string():
    extensions = (
        ext_raw(0x002B, b"\x03\x04")  # supported_versions -> TLS 1.3, type 43
        + ext_raw(0x0A0A)  # GREASE extension -> must be stripped
        + ext_raw(0x0033, b"\x00")  # key_share, type 51
    )
    record = server_hello_record(version=0x0303, cipher=0x1301, extensions=extensions)
    stream = reassemble_tcp_stream([(1000, record)])
    hello = find_server_hello(stream)

    # version=771, cipher=4865 (0x1301), extensions = 43,[GREASE dropped],51
    expected = "771,4865,43-51"
    return hello, expected


def test_build_ja3s_string_matches_hand_derived_spec_value():
    hello, expected = _hello_and_expected_string()
    assert build_ja3s_string(hello) == expected


def test_compute_ja3s_hashes_with_md5():
    hello, expected = _hello_and_expected_string()
    result = compute_ja3s(hello)
    assert result.ja3s_string == expected
    assert result.ja3s_hash == hashlib.md5(expected.encode("ascii")).hexdigest()
    assert len(result.ja3s_hash) == 32


def test_ja3s_has_exactly_three_fields():
    record = server_hello_record(version=0x0303, cipher=0xC02F, extensions=b"")
    stream = reassemble_tcp_stream([(1, record)])
    hello = find_server_hello(stream)
    ja3s = build_ja3s_string(hello)
    assert ja3s.count(",") == 2
    assert ja3s == "771,49199,"
