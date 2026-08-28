# TLS Fingerprinting with JA3/JA3S

> **Feeling lost / want the plain-English version first?** Read
> [`SIMPLE_GUIDE.md`](SIMPLE_GUIDE.md) — one page, no jargon, tells you
> what this does, what to run, and what to present.

A passive TLS fingerprinting tool for a Computer Networks course project.
It reads TLS handshake traffic from `.pcap` files, computes JA3 (client)
and JA3S (server) fingerprints per the published Salesforce spec, and
identifies the likely client/server software against a small, self-curated
reference database — without decrypting anything, since the ClientHello
and ServerHello messages TLS fingerprinting relies on are sent
unencrypted by design.

New to the underlying networking/TLS concepts? Start with
[`docs/STUDY_GUIDE.md`](docs/STUDY_GUIDE.md) — it teaches everything from
IP addresses up through JA3/JA3S from zero.

## Motivation

Firewalls and monitors increasingly see only encrypted traffic. JA3/JA3S
turn the *unencrypted, structural* part of a TLS handshake — which
ciphers a client offers, in what order, which extensions it includes —
into a short, comparable hash, giving defenders a lightweight signal for
client identification and anomaly/malware-C2 detection without breaking
TLS's confidentiality guarantees anywhere.

## Architecture

```
PCAP file --> Packet Parser --> ClientHello/ServerHello --> JA3/JA3S Generator
                                                                    |
                                                                    v
                        CLI Output <-- Fingerprint Matcher <-- Fingerprint Database
```

| Module | Responsibility |
|---|---|
| `src/tls_fingerprint/parser.py` | TCP stream reassembly + raw TLS record/handshake byte parsing |
| `src/tls_fingerprint/ja3.py` / `ja3s.py` | JA3/JA3S string construction + MD5 hashing |
| `src/tls_fingerprint/database.py` | JSON-backed reference database + known/possible/unknown lookup |
| `src/tls_fingerprint/analyzer.py` | Orchestrates pcap → flows → hellos → JA3/JA3S → DB lookup |
| `src/tls_fingerprint/cli.py` / `report.py` | Command-line interface + human-readable output |
| `src/tls_fingerprint/capture_proxy.py` | Root-free relay used only to *generate* real experiment traffic |

## Features

- Analyze any `.pcap`/`.pcapng` file — no elevated privileges needed
- RFC-faithful JA3 and JA3S computation, including RFC 8701 GREASE
  stripping
- Local JSON reference database with `known` / `possible` (ambiguous) /
  `unknown` match reporting — never silently guesses
- Text or JSON CLI output
- Optional live capture (needs `sudo` on macOS — see `docs/SETUP_MAC.md`)
- Root-free traffic-generation tooling (`capture_proxy.py`) used to build
  5 real, distinct client fingerprints for this project's own reference
  database — see `docs/EXPERIMENTS.md`

## Installation

```bash
git clone <this repo>
cd CN_tls_fingerprint
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
```

Full step-by-step macOS instructions (including common permission
gotchas): [`docs/SETUP_MAC.md`](docs/SETUP_MAC.md).

## Quick Start

```bash
tls-fingerprint analyze pcaps/curl.pcap
```

## Example Output

Real output from `tls-fingerprint analyze pcaps/curl.pcap` (a genuine
curl → example.com handshake, see `docs/EXPERIMENTS.md`):

```
Flow
--------------------------------
Source:      127.0.0.1:49187
Destination: 104.20.23.154:443
SNI:         example.com

TLS
--------------------------------
Version: TLS 1.3

JA3 (client)
--------------------------------
String: 771,4867-4866-4865-52393-...-255,43-51-0-11-10-13-16,29-23-24-25,0
Hash:   375c6162a492dfbf2795909110ce8424

Client Identification
--------------------------------
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)

JA3S (server)
--------------------------------
String: 771,4867,51-43
Hash:   d75f9129bb5d05492a65ff78e081bcb2

Server Identification
--------------------------------
Likely Server Stack: Cloudflare edge (fronting example.com)
Match:               Known match (reference database)
```

## Experiments

Five genuinely different real TLS clients were captured and fingerprinted
— curl, OpenSSL, Python's stdlib `ssl`, headless Chrome, and a hand-built
raw-socket ClientHello with no TLS library at all — producing **five
distinct JA3 hashes**, including two clients sharing the exact same
underlying crypto library. Exact commands, real command output, and
discussion: [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md).

Rebuild the reference database from the captured pcaps at any time:
```bash
python experiments/build_reference_db.py
```

## Testing

```bash
pytest
```
36 tests: JA3/JA3S string construction (checked against hand-derived
expected values, not just re-checking the code against itself), parser
edge cases, database lookup semantics, report formatting, and an
end-to-end integration test through a synthetic pcap.

## Limitations

TLS fingerprinting is a hint, not proof of identity. See
[`docs/STUDY_GUIDE.md` §20](docs/STUDY_GUIDE.md#20-limitations-randomization-and-evasion--read-this-carefully)
and [`docs/PROJECT_REPORT.md` §9](docs/PROJECT_REPORT.md#9-limitations)
for the full discussion — in short: identical JA3 doesn't imply identical
software, JA3S depends on the client it's responding to, GREASE and
(in modern Chrome) extension-order randomization actively work against
fingerprint stability, and any client can trivially mimic another's
fingerprint since it's entirely client-controlled bytes.

## Future Work / Stretch Goals

Not implemented in this MVP by design — see `docs/PROJECT_REPORT.md` §10:
JA4/JA4S, a larger cross-platform reference database, verified
non-headless browser capture, and (Linux-only) eBPF/XDP-based capture.

## Documentation Index

- [`SIMPLE_GUIDE.md`](SIMPLE_GUIDE.md) — start here if anything feels too complicated
- [`docs/BIG_PICTURE.md`](docs/BIG_PICTURE.md) — why this project, what's the catch, what came before/after JA3
- [`docs/STUDY_GUIDE.md`](docs/STUDY_GUIDE.md) — CN/TLS/JA3 from zero
- [`docs/SETUP_MAC.md`](docs/SETUP_MAC.md) — macOS setup, step by step
- [`docs/EXPERIMENTS.md`](docs/EXPERIMENTS.md) — reproducible experiment commands
- [`docs/VIVA.md`](docs/VIVA.md) — 40 likely viva Q&A
- [`docs/PROJECT_REPORT.md`](docs/PROJECT_REPORT.md) — full report
- [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — requirement-by-requirement status
