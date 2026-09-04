"""Local JSON fingerprint reference database + lookup/matching.

Every entry in data/fingerprint_db.json is something WE actually measured
on this machine (source_type "measured") -- we do not ship invented
"published" hashes. See docs/IMPLEMENTATION.md for how each entry was
produced and docs/PROJECT_REPORT.md for why a JA3 hash is a strong hint, not
proof, of client identity.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

VALID_FINGERPRINT_TYPES = {"ja3", "ja3s", "ja4"}
VALID_CATEGORIES = {"client", "server"}
VALID_SOURCE_TYPES = {"measured", "published_reference"}


@dataclass
class FingerprintEntry:
    hash: str
    fingerprint_type: str  # "ja3" | "ja3s" | "ja4"
    name: str
    category: str  # "client" | "server"
    fingerprint_string: str | None = None
    library: str | None = None
    source_type: str = "measured"  # "measured" | "published_reference"
    source: str = ""
    command: str | None = None
    notes: str | None = None

    def __post_init__(self):
        if self.fingerprint_type not in VALID_FINGERPRINT_TYPES:
            raise ValueError(f"invalid fingerprint_type: {self.fingerprint_type!r}")
        if self.category not in VALID_CATEGORIES:
            raise ValueError(f"invalid category: {self.category!r}")
        if self.source_type not in VALID_SOURCE_TYPES:
            raise ValueError(f"invalid source_type: {self.source_type!r}")


@dataclass(frozen=True)
class MatchResult:
    status: str  # "known" | "possible" | "unknown"
    queried_hash: str
    fingerprint_type: str
    entries: list[FingerprintEntry]


class FingerprintDatabase:
    def __init__(self, entries: list[FingerprintEntry] | None = None):
        self.entries: list[FingerprintEntry] = entries or []

    @classmethod
    def load(cls, path: str | Path) -> "FingerprintDatabase":
        path = Path(path)
        if not path.exists():
            return cls([])
        raw = json.loads(path.read_text())
        entries = [FingerprintEntry(**e) for e in raw.get("fingerprints", [])]
        return cls(entries)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        payload = {"fingerprints": [asdict(e) for e in self.entries]}
        path.write_text(json.dumps(payload, indent=2) + "\n")

    def add(self, entry: FingerprintEntry) -> None:
        self.entries.append(entry)

    def lookup(self, hash_value: str, fingerprint_type: str) -> MatchResult:
        matches = [
            e
            for e in self.entries
            if e.hash == hash_value and e.fingerprint_type == fingerprint_type
        ]
        distinct_names = {e.name for e in matches}
        if not matches:
            status = "unknown"
        elif len(distinct_names) == 1:
            status = "known"
        else:
            # Same hash, different named clients/tools -- a real JA3
            # limitation, not a bug: report it as ambiguous rather than
            # silently picking one name.
            status = "possible"
        return MatchResult(
            status=status,
            queried_hash=hash_value,
            fingerprint_type=fingerprint_type,
            entries=matches,
        )

    def __len__(self) -> int:
        return len(self.entries)
