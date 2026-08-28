"""Command-line entry point.

    python -m tls_fingerprint.cli analyze pcaps/curl.pcap
    python -m tls_fingerprint.cli db list
    python -m tls_fingerprint.cli db add --hash ... --type ja3 --name curl --category client
    python -m tls_fingerprint.cli live --iface en0 --count 20 --out pcaps/live.pcap
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import analyze_pcap
from .database import FingerprintDatabase, FingerprintEntry
from .report import format_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "fingerprint_db.json"


def _cmd_analyze(args: argparse.Namespace) -> int:
    db = FingerprintDatabase.load(args.db)
    reports = analyze_pcap(args.pcap, db=db)

    if not reports:
        print(f"No TLS ClientHello found in {args.pcap}", file=sys.stderr)
        return 1

    if args.json:
        payload = []
        for r in reports:
            payload.append(
                {
                    "client": f"{r.client_endpoint[0]}:{r.client_endpoint[1]}",
                    "server": f"{r.server_endpoint[0]}:{r.server_endpoint[1]}",
                    "sni": r.client_hello.server_name if r.client_hello else None,
                    "ja3": r.ja3.ja3_string if r.ja3 else None,
                    "ja3_hash": r.ja3.ja3_hash if r.ja3 else None,
                    "ja3_match_status": r.ja3_match.status if r.ja3_match else None,
                    "ja3_match_names": (
                        sorted({e.name for e in r.ja3_match.entries})
                        if r.ja3_match
                        else []
                    ),
                    "ja3s": r.ja3s.ja3s_string if r.ja3s else None,
                    "ja3s_hash": r.ja3s.ja3s_hash if r.ja3s else None,
                    "ja3s_match_status": r.ja3s_match.status if r.ja3s_match else None,
                    "ja3s_match_names": (
                        sorted({e.name for e in r.ja3s_match.entries})
                        if r.ja3s_match
                        else []
                    ),
                }
            )
        print(json.dumps(payload, indent=2))
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


def _cmd_live(args: argparse.Namespace) -> int:
    # Live capture needs raw-socket privileges (root) on macOS. We keep it
    # optional per the project scope -- pcap analysis above is the primary,
    # reproducible path. See docs/SETUP_MAC.md for the sudo requirement.
    try:
        from scapy.all import wrpcap, sniff
    except ImportError:
        print("scapy is required for live capture", file=sys.stderr)
        return 1

    print(f"Sniffing on {args.iface} for {args.count} TLS-looking packets... (Ctrl+C to stop)")
    print("Note: this requires sudo on macOS. Run: sudo python -m tls_fingerprint.cli live ...")
    packets = sniff(iface=args.iface, filter="tcp port 443", count=args.count)
    wrpcap(args.out, packets)
    print(f"Wrote {len(packets)} packets to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tls-fingerprint", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a PCAP file for JA3/JA3S")
    p_analyze.add_argument("pcap", help="Path to a .pcap/.pcapng file")
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
    p_db_add.add_argument("--type", required=True, choices=["ja3", "ja3s"])
    p_db_add.add_argument("--name", required=True)
    p_db_add.add_argument("--category", required=True, choices=["client", "server"])
    p_db_add.add_argument("--string", default=None, help="The full JA3/JA3S string")
    p_db_add.add_argument("--library", default=None)
    p_db_add.add_argument(
        "--source-type", default="measured", choices=["measured", "published_reference"]
    )
    p_db_add.add_argument("--source", default="")
    p_db_add.add_argument("--command", default=None)
    p_db_add.add_argument("--notes", default=None)
    p_db_add.set_defaults(func=_cmd_db_add)

    p_live = sub.add_parser("live", help="Optional: live-capture TLS packets (needs sudo)")
    p_live.add_argument("--iface", required=True)
    p_live.add_argument("--count", type=int, default=20)
    p_live.add_argument("--out", default=str(PROJECT_ROOT / "pcaps" / "live_capture.pcap"))
    p_live.set_defaults(func=_cmd_live)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
