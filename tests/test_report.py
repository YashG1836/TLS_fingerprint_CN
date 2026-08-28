from tls_fingerprint.analyzer import FlowReport
from tls_fingerprint.database import FingerprintDatabase, FingerprintEntry
from tls_fingerprint.ja3 import compute_ja3
from tls_fingerprint.parser import find_client_hello, find_server_hello, reassemble_tcp_stream
from tls_fingerprint.report import effective_tls_version, format_report, version_name
from tls_bytes import client_hello_record, ext_raw, server_hello_record


def _report_with_known_client():
    ch = find_client_hello(
        reassemble_tcp_stream(
            [(1, client_hello_record(version=0x0303, ciphers=[0x1301], extensions=b""))]
        )
    )
    report = FlowReport(
        client_endpoint=("192.168.1.10", 53124),
        server_endpoint=("93.184.216.34", 443),
        client_hello=ch,
        server_hello=None,
    )
    report.ja3 = compute_ja3(ch)
    db = FingerprintDatabase(
        [
            FingerprintEntry(
                hash=report.ja3.ja3_hash,
                fingerprint_type="ja3",
                name="curl",
                category="client",
                source_type="measured",
                source="test",
            )
        ]
    )
    report.ja3_match = db.lookup(report.ja3.ja3_hash, "ja3")
    return report


def test_version_name_known_and_unknown():
    assert version_name(0x0303) == "TLS 1.2"
    assert "Unknown" in version_name(0x9999)


def test_effective_version_prefers_supported_versions_extension():
    sh = find_server_hello(
        reassemble_tcp_stream(
            [
                (
                    1,
                    server_hello_record(
                        version=0x0303,
                        cipher=0x1301,
                        extensions=ext_raw(0x002B, b"\x03\x04"),
                    ),
                )
            ]
        )
    )
    report = FlowReport(("a", 1), ("b", 443), client_hello=None, server_hello=sh)
    assert effective_tls_version(report) == 0x0304


def test_format_report_shows_known_match():
    report = _report_with_known_client()
    text = format_report(report)
    assert "192.168.1.10:53124" in text
    assert "93.184.216.34:443" in text
    assert "Likely Client: curl" in text
    assert "Known match" in text
    assert "No ServerHello captured" in text


def test_format_report_shows_unknown_when_no_db_match():
    ch = find_client_hello(
        reassemble_tcp_stream(
            [(1, client_hello_record(version=0x0303, ciphers=[0x1301], extensions=b""))]
        )
    )
    report = FlowReport(("a", 1), ("b", 443), client_hello=ch, server_hello=None)
    report.ja3 = compute_ja3(ch)
    report.ja3_match = FingerprintDatabase([]).lookup(report.ja3.ja3_hash, "ja3")
    text = format_report(report)
    assert "Unknown fingerprint" in text
