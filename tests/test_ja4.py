"""JA4 tests. Every expected value here is copied verbatim from the
official published spec's own worked examples
(https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) --
these are not our own numbers being checked against themselves, they are
the spec's own ground truth.
"""

from tls_fingerprint.ja4 import (
    _alpn_chars,
    _cipher_hash,
    _extension_hash,
    compute_ja4,
)
from tls_fingerprint.parser import find_client_hello, reassemble_tcp_stream
from tls_bytes import (
    client_hello_record,
    ext_alpn,
    ext_ec_point_formats,
    ext_raw,
    ext_server_name,
    ext_signature_algorithms,
    ext_supported_groups,
    ext_supported_versions_client,
)

# --- ALPN first/last character extraction, straight from the spec table ---


def test_alpn_chars_normal_ascii_value():
    assert _alpn_chars(b"h2") == "h2"
    assert _alpn_chars(b"http/1.1") == "h1"


def test_alpn_chars_single_character_value():
    assert _alpn_chars(b"h") == "hh"


def test_alpn_chars_none_gives_00():
    assert _alpn_chars(None) == "00"
    assert _alpn_chars(b"") == "00"


def test_alpn_chars_non_ascii_fallback_table():
    # Every one of these is a literal example from the spec's ALPN section.
    assert _alpn_chars(bytes([0xAB])) == "ab"
    assert _alpn_chars(bytes([0x20])) == "20"
    assert _alpn_chars(bytes([0xAB, 0xCD])) == "ad"
    assert _alpn_chars(bytes([0x20, 0x61])) == "21"
    assert _alpn_chars(bytes([0x30, 0xAB])) == "3b"
    assert _alpn_chars(bytes([0x61, 0x20])) == "60"
    assert _alpn_chars(bytes([0x30, 0x31, 0xAB, 0xCD])) == "3d"
    assert _alpn_chars(bytes([0x30, 0xAB, 0xCD, 0x31])) == "01"


# --- Cipher hash, straight from the spec's "Cipher hash" worked example ---

_SPEC_CIPHERS_UNSORTED = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
    0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]


def test_cipher_hash_matches_spec_worked_example():
    assert _cipher_hash(_SPEC_CIPHERS_UNSORTED) == "8daaf6152771"


def test_cipher_hash_ignores_order():
    # Sorted input must give the identical hash as the spec's unsorted
    # input above -- this IS the whole point of JA4 over JA3.
    assert _cipher_hash(sorted(_SPEC_CIPHERS_UNSORTED)) == "8daaf6152771"


def test_cipher_hash_strips_grease():
    with_grease = _SPEC_CIPHERS_UNSORTED + [0x0A0A, 0xFAFA]
    assert _cipher_hash(with_grease) == "8daaf6152771"


def test_cipher_hash_empty_list_is_literal_zeros():
    assert _cipher_hash([]) == "000000000000"
    assert _cipher_hash([0x0A0A]) == "000000000000"  # only GREASE offered


# --- Extension hash, straight from the spec's "Extension hash" example ---

_SPEC_EXT_TYPES_UNSORTED = [
    0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D,
    0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015,
]
_SPEC_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _fake_extensions(types):
    from tls_fingerprint.parser import Extension

    return [Extension(t, b"") for t in types]


def test_extension_hash_with_signature_algorithms_matches_spec():
    result = _extension_hash(_fake_extensions(_SPEC_EXT_TYPES_UNSORTED), _SPEC_SIG_ALGS)
    assert result == "e5627efa2ab1"


def test_extension_hash_without_signature_algorithms_matches_spec():
    result = _extension_hash(_fake_extensions(_SPEC_EXT_TYPES_UNSORTED), [])
    assert result == "6d807ffa2a79"


def test_extension_hash_excludes_sni_and_alpn_and_grease():
    types_with_grease = _SPEC_EXT_TYPES_UNSORTED + [0x1A1A]
    result = _extension_hash(_fake_extensions(types_with_grease), _SPEC_SIG_ALGS)
    assert result == "e5627efa2ab1"  # identical to without GREASE


def test_extension_hash_empty_is_literal_zeros():
    assert _extension_hash([], []) == "000000000000"
    # Only SNI/ALPN present -> nothing left after exclusion:
    assert _extension_hash(_fake_extensions([0x0000, 0x0010]), []) == "000000000000"


# --- Full end-to-end: build the ACTUAL ClientHello bytes the spec's ------
# --- example describes, and check compute_ja4() reproduces it exactly ---


def test_compute_ja4_matches_full_spec_example():
    extensions = b"".join(
        [
            ext_raw(0x001B),  # compress_certificate
            ext_server_name("example.com"),  # 0x0000 SNI
            ext_raw(0x0033),  # key_share
            ext_alpn(["h2"]),  # 0x0010 ALPN
            ext_raw(0x4469),  # unassigned/experimental
            ext_raw(0x0017),  # extended_master_secret
            ext_raw(0x002D),  # psk_key_exchange_modes
            ext_signature_algorithms(_SPEC_SIG_ALGS),  # 0x000D
            ext_raw(0x0005),  # status_request
            ext_raw(0x0023),  # session_ticket
            ext_raw(0x0012),  # signed_certificate_timestamp
            ext_supported_versions_client([0x0304]),  # 0x002B -> TLS 1.3
            ext_raw(0xFF01),  # renegotiation_info
            ext_ec_point_formats([0]),  # 0x000B
            ext_supported_groups([0x001D, 0x0017]),  # 0x000A
            ext_raw(0x0015),  # padding
        ]
    )
    record = client_hello_record(
        version=0x0303,  # legacy field; real version comes from the extension
        ciphers=_SPEC_CIPHERS_UNSORTED,
        extensions=extensions,
    )
    stream = reassemble_tcp_stream([(1, record)])
    hello = find_client_hello(stream)

    result = compute_ja4(hello)

    assert result.part_a == "t13d1516h2"
    assert result.part_b == "8daaf6152771"
    assert result.part_c == "e5627efa2ab1"
    assert result.ja4_string == "t13d1516h2_8daaf6152771_e5627efa2ab1"


def test_compute_ja4_no_sni_gives_i_flag():
    record = client_hello_record(version=0x0303, ciphers=[0x1301], extensions=b"")
    hello = find_client_hello(reassemble_tcp_stream([(1, record)]))
    result = compute_ja4(hello)
    assert result.part_a[3] == "i"  # 4th char of part_a is the SNI flag


def test_compute_ja4_falls_back_to_legacy_version_without_extension():
    record = client_hello_record(version=0x0303, ciphers=[0x1301], extensions=b"")
    hello = find_client_hello(reassemble_tcp_stream([(1, record)]))
    result = compute_ja4(hello)
    assert result.part_a[1:3] == "12"  # 0x0303 legacy version -> TLS 1.2 code
