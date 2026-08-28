"""Integration test: synthetic PCAP -> parser -> JA3/JA3S -> DB lookup.

We build the pcap ourselves with Scapy (rather than depending on a captured
file) so the test is self-contained and deterministic, but it still
exercises the real end-to-end path: rdpcap -> flow reassembly -> handshake
parsing -> JA3/JA3S -> FingerprintDatabase.lookup, exactly as the CLI does
against real captures in experiments/.
"""

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from tls_fingerprint.analyzer import analyze_packets
from tls_fingerprint.database import FingerprintDatabase, FingerprintEntry
from tls_fingerprint.ja3 import compute_ja3
from tls_fingerprint.ja3s import compute_ja3s
from tls_bytes import (
    client_hello_record,
    ext_ec_point_formats,
    ext_supported_groups,
    server_hello_record,
)

CLIENT_IP, CLIENT_PORT = "10.0.0.5", 51234
SERVER_IP, SERVER_PORT = "93.184.216.34", 443


def _build_packets():
    ch_extensions = ext_supported_groups([0x001D, 0x0017]) + ext_ec_point_formats([0])
    client_hello = client_hello_record(
        version=0x0303, ciphers=[0x1301, 0xC02B], extensions=ch_extensions
    )
    server_hello = server_hello_record(version=0x0303, cipher=0xC02B, extensions=b"")

    client_pkt = (
        Ether()
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, seq=1000, flags="PA")
        / Raw(load=client_hello)
    )
    server_pkt = (
        Ether()
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, seq=2000, flags="PA")
        / Raw(load=server_hello)
    )
    return [client_pkt, server_pkt], client_hello, server_hello


def test_pcap_round_trip_produces_expected_ja3(tmp_path):
    packets, client_hello_bytes, server_hello_bytes = _build_packets()
    pcap_path = tmp_path / "sample.pcap"
    wrpcap(str(pcap_path), packets)

    from scapy.all import rdpcap

    reports = analyze_packets(rdpcap(str(pcap_path)))

    assert len(reports) == 1
    report = reports[0]
    assert report.client_endpoint == (CLIENT_IP, CLIENT_PORT)
    assert report.server_endpoint == (SERVER_IP, SERVER_PORT)
    assert report.ja3 is not None
    assert report.ja3s is not None
    assert report.ja3.ja3_string == "771,4865-49195,10-11,29-23,0"
    assert report.ja3s.ja3s_string == "771,49195,"


def test_pcap_analysis_matches_against_database(tmp_path):
    packets, client_hello_bytes, server_hello_bytes = _build_packets()
    pcap_path = tmp_path / "sample.pcap"
    wrpcap(str(pcap_path), packets)

    # Independently recompute the expected hash the same way ja3.py does,
    # to seed a database entry -- this checks the lookup wiring, not JA3
    # correctness (that's covered in test_ja3.py).
    from tls_fingerprint.parser import find_client_hello, find_server_hello

    ch = find_client_hello(client_hello_bytes)
    sh = find_server_hello(server_hello_bytes)
    ja3_hash = compute_ja3(ch).ja3_hash
    ja3s_hash = compute_ja3s(sh).ja3s_hash

    db = FingerprintDatabase(
        [
            FingerprintEntry(
                hash=ja3_hash,
                fingerprint_type="ja3",
                name="synthetic-test-client",
                category="client",
                source_type="measured",
                source="unit test fixture",
            ),
            FingerprintEntry(
                hash=ja3s_hash,
                fingerprint_type="ja3s",
                name="synthetic-test-server",
                category="server",
                source_type="measured",
                source="unit test fixture",
            ),
        ]
    )

    from scapy.all import rdpcap

    reports = analyze_packets(rdpcap(str(pcap_path)), db=db)

    assert len(reports) == 1
    report = reports[0]
    assert report.ja3_match.status == "known"
    assert report.ja3_match.entries[0].name == "synthetic-test-client"
    assert report.ja3s_match.status == "known"
    assert report.ja3s_match.entries[0].name == "synthetic-test-server"


def test_pcap_analysis_unknown_fingerprint_when_db_empty(tmp_path):
    packets, _, _ = _build_packets()
    pcap_path = tmp_path / "sample.pcap"
    wrpcap(str(pcap_path), packets)

    from scapy.all import rdpcap

    reports = analyze_packets(rdpcap(str(pcap_path)), db=FingerprintDatabase([]))
    assert reports[0].ja3_match.status == "unknown"
