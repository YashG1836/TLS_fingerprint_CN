"""Demo: fire N rapid automated requests, each pretending (via a spoofed
User-Agent) to be Chrome, and show that every single one gets correctly
flagged by its real TLS fingerprint regardless of volume.

This is the "malicious client bombarding a server" scenario made
concrete: volume alone doesn't defeat TLS fingerprinting, because the
fingerprint is a property of *each individual connection's* TLS stack,
not something that degrades or gets diluted by request count.

Usage:
    python experiments/bombard_demo.py [N]     # default N=5
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from tls_fingerprint.database import FingerprintDatabase  # noqa: E402
from tls_fingerprint.spoofing_detector import check_pcap  # noqa: E402

DB_PATH = ROOT / "data" / "fingerprint_db.json"
BASE_PORT = 8490


def run_one_capture(index: int) -> Path:
    pcap_path = ROOT / "pcaps" / f"bombard_{index}.pcap"
    port = BASE_PORT + index
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tls_fingerprint.capture_proxy",
            "--mode",
            "tcp",
            "--target",
            "example.com:443",
            "--listen-port",
            str(port),
            "--pcap",
            str(pcap_path),
            "--",
            sys.executable,
            str(ROOT / "experiments" / "bot_client.py"),
            "127.0.0.1",
            str(port),
            "example.com",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"capture #{index} failed (exit {result.returncode})")
    return pcap_path


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    db = FingerprintDatabase.load(DB_PATH)

    print(f"Firing {n} rapid requests, each claiming to be Chrome via User-Agent...\n")
    flagged = 0
    for i in range(1, n + 1):
        pcap_path = run_one_capture(i)
        verdict = check_pcap(pcap_path, "Chrome", db)
        status = "FLAGGED (mismatch)" if verdict.is_suspicious else "not flagged"
        if verdict.is_suspicious:
            flagged += 1
        print(f"  request {i}/{n}: JA3={verdict.measured_ja3_hash}  -> {status}")

    print(f"\nResult: {flagged}/{n} requests correctly flagged as lying about their identity.")
    print("Every single one used a different TCP connection and a fresh real")
    print("handshake with the real server -- volume did not help the requests")
    print("blend in, because each one's TLS fingerprint is independent evidence.")
    return 0 if flagged == n else 1


if __name__ == "__main__":
    raise SystemExit(main())
