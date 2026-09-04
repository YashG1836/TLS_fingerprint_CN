"""Build data/fingerprint_db.json from the pcaps captured in pcaps/.

Reads each experiment's pcap, computes JA3/JA3S directly (no hand-typed
hashes -- avoids transcription mistakes), and writes one measured entry per
client and one per server response. Re-run this any time you re-capture an
experiment; it regenerates the whole file from scratch so it never drifts
from what's actually in pcaps/.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tls_fingerprint.analyzer import analyze_pcap  # noqa: E402
from tls_fingerprint.database import FingerprintDatabase, FingerprintEntry  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PCAP_DIR = ROOT / "pcaps"
DB_PATH = ROOT / "data" / "fingerprint_db.json"

MEASURED_ON = "macOS 26.5.2 (Darwin 25F84), 2026-08-25, captured via capture_proxy.py relay (see docs/IMPLEMENTATION.md)"
SERVER_NAME = "Cloudflare edge (fronting example.com)"

EXPERIMENTS = [
    {
        "pcap": "curl.pcap",
        "client_name": "curl 8.7.1 (macOS system, SecureTransport/LibreSSL)",
        "library": "SecureTransport backed by LibreSSL 3.3.6",
        "command": "curl --connect-to example.com:443:127.0.0.1:8443 -sS https://example.com/",
        "notes": "System /usr/bin/curl on macOS 26.5. Captured via the root-free capture_proxy.py relay, not a NIC tap.",
    },
    {
        "pcap": "openssl.pcap",
        "client_name": "openssl s_client 3.6.2 (Homebrew)",
        "library": "OpenSSL 3.6.2",
        "command": "openssl s_client -connect 127.0.0.1:8444 -servername example.com -brief < /dev/null",
        "notes": "Homebrew-installed OpenSSL, not the macOS system LibreSSL. Captured via capture_proxy.py relay.",
    },
    {
        "pcap": "python_ssl.pcap",
        "client_name": "Python 3.14.6 stdlib ssl (ssl.create_default_context)",
        "library": "CPython ssl module, linked against OpenSSL 3.6.2 (Homebrew build)",
        "command": "python experiments/python_client.py 127.0.0.1 8445 example.com",
        "notes": "Same underlying OpenSSL version as the openssl.pcap entry, but a different JA3 -- the cipher list/order differs because ssl.create_default_context() curates its own suite list. Captured via capture_proxy.py relay.",
    },
    {
        "pcap": "chrome.pcap",
        "client_name": "Google Chrome 151.0.7922.174 (headless)",
        "library": "BoringSSL (Chromium's TLS stack)",
        "command": "Google Chrome --headless=new --proxy-server=127.0.0.1:8446 --dump-dom https://example.com/",
        "notes": "Headless Chrome driven through capture_proxy.py's HTTP CONNECT relay mode so it needed no OS-level proxy config.",
    },
    {
        "pcap": "custom_client.pcap",
        "client_name": "custom hand-built ClientHello (raw socket, no TLS library)",
        "library": "None -- experiments/custom_client.py assembles the TLS record by hand",
        "command": "python experiments/custom_client.py example.com 443 pcaps/custom_client.pcap",
        "notes": "Deliberately legacy TLS 1.2, no supported_versions/key_share extensions. Connected directly to the real server, no relay needed since the script already controls every byte sent.",
    },
]


def main() -> int:
    db = FingerprintDatabase([])

    for exp in EXPERIMENTS:
        pcap_path = PCAP_DIR / exp["pcap"]
        if not pcap_path.exists():
            print(f"SKIP (not captured): {pcap_path}")
            continue
        reports = analyze_pcap(pcap_path)
        if not reports:
            print(f"SKIP (no ClientHello found): {pcap_path}")
            continue
        report = reports[0]

        db.add(
            FingerprintEntry(
                hash=report.ja3.ja3_hash,
                fingerprint_type="ja3",
                name=exp["client_name"],
                category="client",
                fingerprint_string=report.ja3.ja3_string,
                library=exp["library"],
                source_type="measured",
                source=MEASURED_ON,
                command=exp["command"],
                notes=exp["notes"],
            )
        )
        print(f"ja3  {report.ja3.ja3_hash}  {exp['client_name']}")

        if report.ja4 is not None:
            db.add(
                FingerprintEntry(
                    hash=report.ja4.ja4_string,
                    fingerprint_type="ja4",
                    name=exp["client_name"],
                    category="client",
                    fingerprint_string=report.ja4.ja4_string,
                    library=exp["library"],
                    source_type="measured",
                    source=MEASURED_ON,
                    command=exp["command"],
                    notes=exp["notes"]
                    + " JA4's own string already IS its identifier (no separate hash step needed).",
                )
            )
            print(f"ja4  {report.ja4.ja4_string}  {exp['client_name']}")

        if report.ja3s is not None:
            db.add(
                FingerprintEntry(
                    hash=report.ja3s.ja3s_hash,
                    fingerprint_type="ja3s",
                    name=SERVER_NAME,
                    category="server",
                    fingerprint_string=report.ja3s.ja3s_string,
                    library="unknown (Cloudflare does not publish its edge TLS stack)",
                    source_type="measured",
                    source=MEASURED_ON,
                    command=exp["command"],
                    notes=f"ServerHello observed in response to: {exp['client_name']}",
                )
            )
            print(f"ja3s {report.ja3s.ja3s_hash}  {SERVER_NAME}  (vs {exp['client_name']})")

    db.save(DB_PATH)
    print(f"\nWrote {len(db)} entries to {DB_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
