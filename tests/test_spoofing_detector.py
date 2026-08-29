from tls_fingerprint.analyzer import FlowReport
from tls_fingerprint.database import FingerprintDatabase, FingerprintEntry
from tls_fingerprint.ja3 import compute_ja3
from tls_fingerprint.parser import find_client_hello, reassemble_tcp_stream
from tls_fingerprint.spoofing_detector import check_identity_claim, format_verdict
from tls_bytes import client_hello_record


def _make_report(cipher: int) -> FlowReport:
    record = client_hello_record(version=0x0303, ciphers=[cipher], extensions=b"")
    hello = find_client_hello(reassemble_tcp_stream([(1, record)]))
    report = FlowReport(("client", 1), ("server", 443), client_hello=hello, server_hello=None)
    report.ja3 = compute_ja3(hello)
    return report


def _db_with(name: str, hash_value: str) -> FingerprintDatabase:
    return FingerprintDatabase(
        [
            FingerprintEntry(
                hash=hash_value,
                fingerprint_type="ja3",
                name=name,
                category="client",
                source_type="measured",
                source="test",
            )
        ]
    )


def test_consistent_claim_when_hash_matches():
    report = _make_report(0x1301)
    db = _db_with("Google Chrome 120", report.ja3.ja3_hash)
    verdict = check_identity_claim(report, "Chrome", db)
    assert verdict.consistent is True
    assert not verdict.is_suspicious


def test_mismatch_flagged_when_claim_does_not_match_measured_hash():
    report = _make_report(0x1301)  # measured hash won't match Chrome's stored hash
    db = FingerprintDatabase(
        [
            FingerprintEntry(
                hash="not-the-real-hash-at-all",
                fingerprint_type="ja3",
                name="Google Chrome 120",
                category="client",
                source_type="measured",
                source="test",
            ),
            FingerprintEntry(
                hash=report.ja3.ja3_hash,
                fingerprint_type="ja3",
                name="Python stdlib ssl",
                category="client",
                source_type="measured",
                source="test",
            ),
        ]
    )
    verdict = check_identity_claim(report, "Chrome", db)
    assert verdict.consistent is False
    assert verdict.is_suspicious
    assert "Python stdlib ssl" in {e.name for e in verdict.actual_match.entries}


def test_unknown_claim_when_no_reference_data_exists():
    report = _make_report(0x1301)
    db = FingerprintDatabase([])  # nothing on file for "Chrome" at all
    verdict = check_identity_claim(report, "Chrome", db)
    assert verdict.consistent is None
    assert not verdict.is_suspicious  # can't accuse without any reference data


def test_claim_matching_is_case_insensitive_substring():
    report = _make_report(0x1301)
    db = _db_with("Google Chrome 151.0.7922.174 (headless)", report.ja3.ja3_hash)
    verdict = check_identity_claim(report, "chrome", db)
    assert verdict.consistent is True


def test_format_verdict_flags_mismatch_visibly():
    report = _make_report(0x1301)
    db = _db_with("Google Chrome 120", "a-completely-different-hash")
    verdict = check_identity_claim(report, "Chrome", db)
    text = format_verdict(verdict)
    assert "MISMATCH" in text
    assert "SUSPICIOUS" in text
