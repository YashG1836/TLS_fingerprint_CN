import hashlib

from tls_fingerprint.ja3 import GREASE_VALUES, build_ja3_string, compute_ja3, is_grease
from tls_fingerprint.parser import find_client_hello, reassemble_tcp_stream
from tls_bytes import (
    client_hello_record,
    ext_ec_point_formats,
    ext_raw,
    ext_server_name,
    ext_supported_groups,
)


def _hello_and_expected_string():
    extensions = (
        ext_server_name("example.com")  # type 0
        + ext_raw(0x2A2A)  # GREASE extension -> must be stripped
        + ext_supported_groups([0xDADA, 0x001D, 0x0017])  # GREASE + x25519 + secp256r1
        + ext_ec_point_formats([0])  # type 11
    )
    record = client_hello_record(
        version=0x0303,
        ciphers=[0x1301, 0x0A0A, 0xC02B],  # real, GREASE, real
        extensions=extensions,
    )
    stream = reassemble_tcp_stream([(1000, record)])
    hello = find_client_hello(stream)

    # Hand-derived per the JA3 spec, field by field:
    #   version   = 0x0303 = 771
    #   ciphers   = 0x1301, 0xC02B (0x0A0A is GREASE, dropped) = 4865-49195
    #   extensions= server_name(0), [GREASE dropped], supported_groups(10),
    #               ec_point_formats(11) = 0-10-11
    #   curves    = 0x001D, 0x0017 (0xDADA is GREASE, dropped) = 29-23
    #   points    = 0
    expected = "771,4865-49195,0-10-11,29-23,0"
    return hello, expected


def test_grease_table_has_16_values():
    assert len(GREASE_VALUES) == 16
    assert 0x0A0A in GREASE_VALUES
    assert 0xFAFA in GREASE_VALUES
    assert 0x1A2B not in GREASE_VALUES


def test_is_grease():
    assert is_grease(0xCACA)
    assert not is_grease(0xC02B)


def test_build_ja3_string_matches_hand_derived_spec_value():
    hello, expected = _hello_and_expected_string()
    assert build_ja3_string(hello) == expected


def test_compute_ja3_hashes_the_string_with_md5():
    hello, expected = _hello_and_expected_string()
    result = compute_ja3(hello)
    assert result.ja3_string == expected
    assert result.ja3_hash == hashlib.md5(expected.encode("ascii")).hexdigest()
    assert len(result.ja3_hash) == 32


def test_ja3_string_always_has_five_fields_even_when_extensions_absent():
    record = client_hello_record(version=0x0301, ciphers=[0x002F], extensions=b"")
    stream = reassemble_tcp_stream([(1, record)])
    hello = find_client_hello(stream)
    ja3 = build_ja3_string(hello)
    assert ja3.count(",") == 4
    assert ja3 == "769,47,,,"
