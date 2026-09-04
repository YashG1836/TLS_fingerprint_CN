"""Identity-claim vs. TLS-fingerprint consistency check ("bot detection").

A bot can trivially claim to be Chrome by sending a
`User-Agent: ... Chrome ...` HTTP header -- that's just a string literal.
It can't as easily fake *which TLS library actually produced its
ClientHello*, since that's a structural property of the library, not
something typed by hand.

This module never reads the User-Agent itself -- we never decrypt
anything here, on principle. The claimed identity is supplied by the
caller, exactly like a real reverse proxy/WAF would have it: that's the
one vantage point that legitimately sees both the ClientHello
(pre-decryption) and the User-Agent (post-decryption) together, because
it's the box terminating TLS. We just implement the comparison.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analyzer import FlowReport, analyze_pcap
from .database import FingerprintDatabase, MatchResult


@dataclass(frozen=True)
class SpoofingVerdict:
    claimed_identity: str
    measured_ja3_hash: str
    measured_ja4_string: str
    claimed_identity_known_hashes: frozenset[str]
    actual_match: MatchResult
    consistent: bool | None  # None = we have no reference data for the claim at all

    @property
    def is_suspicious(self) -> bool:
        return self.consistent is False


def check_identity_claim(
    report: FlowReport, claimed_identity: str, db: FingerprintDatabase
) -> SpoofingVerdict:
    claimed_lower = claimed_identity.lower()
    matching_entries = [
        e
        for e in db.entries
        if e.fingerprint_type == "ja3"
        and e.category == "client"
        and claimed_lower in e.name.lower()
    ]
    known_hashes = frozenset(e.hash for e in matching_entries)

    measured_hash = report.ja3.ja3_hash if report.ja3 else ""
    measured_ja4 = report.ja4.ja4_string if report.ja4 else ""

    if not known_hashes:
        consistent = None
    else:
        consistent = measured_hash in known_hashes

    # Computed directly rather than trusting report.ja3_match to already be
    # populated -- keeps this function correct regardless of whether the
    # caller's FlowReport went through analyzer.py's db-lookup step.
    actual_match = db.lookup(measured_hash, "ja3")

    return SpoofingVerdict(
        claimed_identity=claimed_identity,
        measured_ja3_hash=measured_hash,
        measured_ja4_string=measured_ja4,
        claimed_identity_known_hashes=known_hashes,
        actual_match=actual_match,
        consistent=consistent,
    )


def format_verdict(verdict: SpoofingVerdict) -> str:
    lines = [
        "Identity Claim Check",
        "-" * 32,
        f"Claims to be: {verdict.claimed_identity}",
        f"Measured JA3: {verdict.measured_ja3_hash}",
        f"Measured JA4: {verdict.measured_ja4_string}",
        "",
    ]

    if verdict.consistent is None:
        lines.append(
            f"VERDICT: Cannot verify -- no reference fingerprint for "
            f"'{verdict.claimed_identity}' in the database yet."
        )
    elif verdict.consistent:
        lines.append(
            f"VERDICT: Consistent -- measured JA3 matches a known "
            f"'{verdict.claimed_identity}' fingerprint."
        )
    else:
        actual_names = (
            sorted({e.name for e in verdict.actual_match.entries})
            if verdict.actual_match and verdict.actual_match.entries
            else ["an unrecognized fingerprint"]
        )
        lines.append(
            f"VERDICT: *** MISMATCH -- SUSPICIOUS *** claims to be "
            f"'{verdict.claimed_identity}' but its real TLS fingerprint "
            f"matches: {', '.join(actual_names)}"
        )
    return "\n".join(lines)


def check_pcap(
    pcap_path: str | Path, claimed_identity: str, db: FingerprintDatabase
) -> SpoofingVerdict:
    reports = analyze_pcap(pcap_path, db=db)
    if not reports:
        raise ValueError(f"no ClientHello found in {pcap_path}")
    return check_identity_claim(reports[0], claimed_identity, db)
