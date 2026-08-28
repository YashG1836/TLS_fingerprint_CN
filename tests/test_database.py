import json

import pytest

from tls_fingerprint.database import FingerprintDatabase, FingerprintEntry


def _entry(name="curl", hash_value="abc123", fingerprint_type="ja3"):
    return FingerprintEntry(
        hash=hash_value,
        fingerprint_type=fingerprint_type,
        name=name,
        category="client",
        source_type="measured",
        source="unit test",
    )


def test_invalid_fingerprint_type_rejected():
    with pytest.raises(ValueError):
        FingerprintEntry(
            hash="x", fingerprint_type="ja4", name="x", category="client"
        )


def test_lookup_unknown_when_absent():
    db = FingerprintDatabase([_entry()])
    result = db.lookup("does-not-exist", "ja3")
    assert result.status == "unknown"
    assert result.entries == []


def test_lookup_known_on_exact_single_match():
    db = FingerprintDatabase([_entry(name="curl", hash_value="abc123")])
    result = db.lookup("abc123", "ja3")
    assert result.status == "known"
    assert result.entries[0].name == "curl"


def test_lookup_possible_when_hash_shared_by_multiple_names():
    db = FingerprintDatabase(
        [
            _entry(name="curl", hash_value="shared"),
            _entry(name="python-requests", hash_value="shared"),
        ]
    )
    result = db.lookup("shared", "ja3")
    assert result.status == "possible"
    assert {e.name for e in result.entries} == {"curl", "python-requests"}


def test_fingerprint_type_isolates_lookups():
    db = FingerprintDatabase([_entry(hash_value="same", fingerprint_type="ja3")])
    assert db.lookup("same", "ja3s").status == "unknown"
    assert db.lookup("same", "ja3").status == "known"


def test_save_and_load_round_trip(tmp_path):
    db = FingerprintDatabase([_entry(name="openssl", hash_value="deadbeef")])
    path = tmp_path / "db.json"
    db.save(path)

    raw = json.loads(path.read_text())
    assert raw["fingerprints"][0]["name"] == "openssl"

    reloaded = FingerprintDatabase.load(path)
    assert len(reloaded) == 1
    assert reloaded.lookup("deadbeef", "ja3").status == "known"


def test_load_missing_file_returns_empty_db(tmp_path):
    db = FingerprintDatabase.load(tmp_path / "nope.json")
    assert len(db) == 0
