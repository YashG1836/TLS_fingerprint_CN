"""Guards against data/fingerprint_db.json drifting from the pcaps it was
built from -- re-derives every entry straight from pcaps/ using the same
logic as experiments/build_reference_db.py and diffs it against what's
checked in. Nothing here is hand-typed."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

from build_reference_db import EXPERIMENTS, SERVER_NAME  # noqa: E402

from tls_fingerprint.analyzer import analyze_pcap

DB_PATH = ROOT / "data" / "fingerprint_db.json"
PCAP_DIR = ROOT / "pcaps"


def _db_entries():
    with open(DB_PATH, encoding="utf-8") as f:
        return json.load(f)["fingerprints"]


def _fresh_entries():
    fresh = []
    for exp in EXPERIMENTS:
        report = analyze_pcap(PCAP_DIR / exp["pcap"])[0]
        fresh.append(("ja3", report.ja3.ja3_hash, exp["client_name"]))
        if report.ja4 is not None:
            fresh.append(("ja4", report.ja4.ja4_string, exp["client_name"]))
        if report.ja3s is not None:
            fresh.append(("ja3s", report.ja3s.ja3s_hash, SERVER_NAME))
    return fresh


def test_reference_db_entry_count_matches_source_experiments():
    assert len(_db_entries()) == len(_fresh_entries())


def test_every_db_entry_reproduces_from_its_source_pcap():
    for db_entry, (ftype, fresh_hash, name) in zip(_db_entries(), _fresh_entries()):
        assert db_entry["fingerprint_type"] == ftype
        assert db_entry["name"] == name
        assert db_entry["hash"] == fresh_hash, (
            f"{db_entry['name']} {ftype} hash is stale in {DB_PATH}: "
            f"file has {db_entry['hash']!r}, its source pcap now gives {fresh_hash!r}"
        )
