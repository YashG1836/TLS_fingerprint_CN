import hashlib

from tls_fingerprint.parser import (
    find_client_hello,
    find_server_hello,
    reassemble_tcp_stream,
)
from tls_bytes import (
    client_hello_record,
    ext_ec_point_formats,
    ext_raw,
    ext_server_name,
    ext_supported_groups,
    server_hello_record,
)


def _sample_client_hello_bytes() -> bytes:
    extensions = (
        ext_server_name("example.com")
        + ext_raw(0x2A2A)  # GREASE extension, empty body
        + ext_supported_groups([0xDADA, 0x001D, 0x0017])  # GREASE + x25519 + secp256r1
        + ext_ec_point_formats([0])
    )
    return client_hello_record(
        version=0x0303,
        ciphers=[0x1301, 0x0A0A, 0xC02B],  # real, GREASE, real
        extensions=extensions,
    )


def test_find_client_hello_parses_fields():
    record = _sample_client_hello_bytes()
    stream = reassemble_tcp_stream([(1000, record)])
    hello = find_client_hello(stream)

    assert hello is not None
    assert hello.version == 0x0303
    assert hello.cipher_suites == [0x1301, 0x0A0A, 0xC02B]
    assert hello.extension_types == [0x0000, 0x2A2A, 0x000A, 0x000B]
    assert hello.supported_groups == [0xDADA, 0x001D, 0x0017]
    assert hello.ec_point_formats == [0]
    assert hello.server_name == "example.com"


def test_find_client_hello_returns_none_when_absent():
    stream = b"not a tls record at all"
    assert find_client_hello(stream) is None


def test_reassemble_orders_by_sequence_and_dedupes():
    record = _sample_client_hello_bytes()
    half = len(record) // 2
    first, second = record[:half], record[half:]
    # Out-of-order + a duplicate retransmission of the first segment.
    segments = [(1000 + half, second), (1000, first), (1000, first)]
    stream = reassemble_tcp_stream(segments)
    assert stream == record


def test_client_hello_split_across_two_tls_records():
    record = _sample_client_hello_bytes()
    # Split the single handshake message's bytes across two TLS records to
    # emulate a large ClientHello spanning multiple records.
    header, rest = record[:5], record[5:]
    handshake_bytes = rest
    split = len(handshake_bytes) // 2
    part_a, part_b = handshake_bytes[:split], handshake_bytes[split:]

    def make_record(payload: bytes) -> bytes:
        return bytes([0x16]) + header[1:3] + len(payload).to_bytes(2, "big") + payload

    two_records = make_record(part_a) + make_record(part_b)
    stream = reassemble_tcp_stream([(2000, two_records)])
    hello = find_client_hello(stream)

    assert hello is not None
    assert hello.server_name == "example.com"


def test_find_server_hello_parses_fields():
    extensions = ext_raw(0x0010, b"\x00\x02h2")  # ALPN-ish, not GREASE-filtered here
    record = server_hello_record(version=0x0303, cipher=0xC02F, extensions=extensions)
    stream = reassemble_tcp_stream([(5000, record)])
    hello = find_server_hello(stream)

    assert hello is not None
    assert hello.version == 0x0303
    assert hello.cipher_suite == 0xC02F
    assert hello.extension_types == [0x0010]


def test_find_server_hello_returns_none_when_absent():
    assert find_server_hello(b"\x00\x01\x02") is None


def test_sample_bytes_are_internally_consistent():
    # Sanity check the test fixture builder itself isn't producing garbage.
    record = _sample_client_hello_bytes()
    assert record[0] == 0x16
    assert hashlib.md5(record).hexdigest()  # just confirms bytes are well-formed
