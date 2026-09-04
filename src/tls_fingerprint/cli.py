"""Command-line entry point.

    tls-fingerprint analyze pcaps/curl.pcap
    tls-fingerprint analyze pcaps/curl.pcap --json
    tls-fingerprint db list
    tls-fingerprint db add --hash ... --type ja3 --name curl --category client
    tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_pcap
from .database import FingerprintDatabase, FingerprintEntry
from .report import format_report
from .spoofing_detector import check_pcap, format_verdict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "fingerprint_db.json"


def _match_summary(match) -> dict:
    if match is None:
        return {"status": None, "names": []}
    return {"status": match.status, "names": sorted({e.name for e in match.entries})}


def _report_to_dict(r) -> dict:
    return {
        "client": f"{r.client_endpoint[0]}:{r.client_endpoint[1]}",
        "server": f"{r.server_endpoint[0]}:{r.server_endpoint[1]}",
        "sni": r.client_hello.server_name if r.client_hello else None,
        "ja3": {"string": r.ja3.ja3_string, "hash": r.ja3.ja3_hash, **_match_summary(r.ja3_match)}
        if r.ja3
        else None,
        "ja4": {"string": r.ja4.ja4_string, **_match_summary(r.ja4_match)} if r.ja4 else None,
        "ja3s": {
            "string": r.ja3s.ja3s_string,
            "hash": r.ja3s.ja3s_hash,
            **_match_summary(r.ja3s_match),
        }
        if r.ja3s
        else None,
    }


def _cmd_analyze(args: argparse.Namespace) -> int:
    db = FingerprintDatabase.load(args.db)
    reports = analyze_pcap(args.pcap, db=db)

    if not reports:
        print(f"No TLS ClientHello found in {args.pcap}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps([_report_to_dict(r) for r in reports], indent=2))
        return 0

    for i, report in enumerate(reports, start=1):
        print(format_report(report, index=i if len(reports) > 1 else None))
    return 0


def _cmd_db_list(args: argparse.Namespace) -> int:
    db = FingerprintDatabase.load(args.db)
    if len(db) == 0:
        print(f"(empty) {args.db}")
        return 0
    for e in db.entries:
        print(f"[{e.fingerprint_type}] {e.hash}  {e.name} ({e.category}, {e.source_type})")
    return 0


def _cmd_db_add(args: argparse.Namespace) -> int:
    db = FingerprintDatabase.load(args.db)
    entry = FingerprintEntry(
        hash=args.hash,
        fingerprint_type=args.type,
        name=args.name,
        category=args.category,
        fingerprint_string=args.string,
        library=args.library,
        source_type=args.source_type,
        source=args.source or "",
        command=args.command,
        notes=args.notes,
    )
    db.add(entry)
    db.save(args.db)
    print(f"Added {entry.fingerprint_type} entry '{entry.name}' -> {args.db}")
    return 0


def _cmd_check_spoofing(args: argparse.Namespace) -> int:
    db = FingerprintDatabase.load(args.db)
    verdict = check_pcap(args.pcap, args.claims, db)
    print(format_verdict(verdict))
    return 1 if verdict.is_suspicious else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tls-fingerprint", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a PCAP file for JA3/JA3S/JA4")
    p_analyze.add_argument("pcap", help="Path to a .pcap file")
    p_analyze.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Fingerprint DB JSON path")
    p_analyze.add_argument("--json", action="store_true", help="Output JSON instead of text")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_db = sub.add_parser("db", help="Inspect/edit the fingerprint reference database")
    db_sub = p_db.add_subparsers(dest="db_command", required=True)

    p_db_list = db_sub.add_parser("list", help="List all entries")
    p_db_list.add_argument("--db", default=str(DEFAULT_DB_PATH))
    p_db_list.set_defaults(func=_cmd_db_list)

    p_db_add = db_sub.add_parser("add", help="Add a measured fingerprint entry")
    p_db_add.add_argument("--db", default=str(DEFAULT_DB_PATH))
    p_db_add.add_argument("--hash", required=True)
    p_db_add.add_argument("--type", required=True, choices=["ja3", "ja3s", "ja4"])
    p_db_add.add_argument("--name", required=True)
    p_db_add.add_argument("--category", required=True, choices=["client", "server"])
    p_db_add.add_argument("--string", default=None, help="The full fingerprint string")
    p_db_add.add_argument("--library", default=None)
    p_db_add.add_argument(
        "--source-type", default="measured", choices=["measured", "published_reference"]
    )
    p_db_add.add_argument("--source", default="")
    p_db_add.add_argument("--command", default=None)
    p_db_add.add_argument("--notes", default=None)
    p_db_add.set_defaults(func=_cmd_db_add)

    p_spoof = sub.add_parser(
        "check-spoofing",
        help="Check whether a pcap's real JA3 matches a claimed client identity (bot detection)",
    )
    p_spoof.add_argument("pcap", help="Path to a .pcap file")
    p_spoof.add_argument("--claims", required=True, help="Claimed identity, e.g. 'Chrome'")
    p_spoof.add_argument("--db", default=str(DEFAULT_DB_PATH))
    p_spoof.set_defaults(func=_cmd_check_spoofing)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
