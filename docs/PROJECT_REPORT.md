# Project Report: TLS Fingerprinting using JA3/JA3S

**Course:** Computer Networks
**Author:** Yash Goyal 24110399
**Date:** 27/08/2026 (submission date : 11/09/2026)

---

## 1. Introduction

This project implements a passive TLS fingerprinting tool that extracts
JA3 (client) and JA3S (server) fingerprints from TLS handshake traffic and
identifies the likely client/server software from a small, self-curated
reference database — without decrypting anything, since TLS's
ClientHello/ServerHello messages are sent unencrypted by design.

## 2. Motivation

Firewalls and network monitors increasingly see only encrypted traffic,
which hides application-layer content (URLs, headers, payloads) but not
the *shape* of the TLS handshake itself. Different TLS implementations —
browsers, command-line tools, custom scripts, malware — configure their
ClientHello differently (cipher suite lists, extension sets, ordering),
and those differences are visible in plaintext before encryption even
starts. JA3/JA3S turn that visible structure into a short, comparable
identifier, giving defenders a lightweight signal for client
identification, anomaly detection, and malware C2 traffic detection
without needing to break TLS's confidentiality guarantees anywhere.

## 3. Background

### 3.1 TCP/IP and packet capture

See `docs/STUDY_GUIDE.md` §1–7 for a from-scratch treatment. In short: IP
addresses a device, TCP turns unreliable IP delivery into an ordered byte
stream, and a `.pcap` file is a recording of packets crossing an
interface. Reading a `.pcap` needs no special privileges on macOS; live
capture off a real interface does (root, via `sudo`).

### 3.2 TLS and the handshake

TLS adds encryption, integrity, and (typically) server authentication on
top of TCP. The handshake begins with two unencrypted messages:
**ClientHello** (the client's TLS version, ordered cipher suite list, and
extensions) and **ServerHello** (the server's negotiated version, single
chosen cipher, and its own extensions). Everything after the ServerHello
in TLS 1.3 (and after the key exchange completes in TLS 1.2) is
encrypted and out of scope for this project.

### 3.3 TLS fingerprinting

Different TLS libraries and configurations produce structurally different
ClientHellos even for functionally-equivalent requests, because each
library ships its own defaults for cipher/extension ordering and
inclusion. TLS fingerprinting exploits this: it doesn't read *meaning*
out of a ClientHello, just its *shape*.

### 3.4 JA3

Published by Salesforce Engineering (John B. Althouse et al., 2017). JA3
builds the string:
```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```
from a ClientHello (each list field `-`-joined, in the order sent, with
RFC 8701 GREASE values stripped from every field they can appear in), then
takes its MD5 hash. Implemented in
[`src/tls_fingerprint/ja3.py`](../src/tls_fingerprint/ja3.py).

### 3.5 JA3S

The server-side counterpart: `SSLVersion,Cipher,SSLExtension` from a
ServerHello, MD5-hashed. Implemented in
[`src/tls_fingerprint/ja3s.py`](../src/tls_fingerprint/ja3s.py). Because a
ServerHello only ever reflects a single choice made from what the client
offered, JA3S is context-dependent on the client, not a pure server
identity — demonstrated empirically in §9 below.

## 4. Architecture

```
PCAP file (real packets)
        |
        v   scapy.rdpcap()
Packet list
        |
        v   group into TCP flows, reassemble each direction
ClientHello / ServerHello byte streams
        |
        v   walk TLS records, extract handshake fields (parser.py)
ClientHelloInfo / ServerHelloInfo
        |
        v   build JA3/JA3S string + MD5 (ja3.py / ja3s.py)
JA3 hash / JA3S hash
        |
        v   FingerprintDatabase.lookup() (database.py)
known / possible / unknown match
        |
        v   format_report() (report.py)
CLI text/JSON output
```

Each stage is an independently importable, independently unit-tested
module — see `tests/` for one test file per stage plus an end-to-end
integration test (`tests/test_integration.py`) that builds a synthetic
pcap with Scapy and runs it through the entire pipeline.

## 5. Implementation

- **Packet/TCP layer** (`parser.reassemble_tcp_stream`): orders and
  de-duplicates `(seq, payload)` segments per flow direction into one
  byte stream. Handles simple in-order captures; documented as not
  implementing full RFC 793 out-of-order/loss recovery, which is
  unnecessary for the clean, low-latency captures this project produces.
- **TLS record/handshake parsing** (`parser.py`): hand-parses the raw
  byte layout of TLS records and Handshake messages directly against RFC
  5246/8446, rather than depending on Scapy's TLS layer — every field
  offset is traceable to a comment citing the spec section. Handles a
  handshake message split across multiple TLS records.
- **JA3/JA3S** (`ja3.py`, `ja3s.py`): pure functions building the exact
  spec string and MD5 hash; GREASE filtering implemented from RFC 8701's
  16-value table, generated programmatically rather than hard-coded.
- **Reference database** (`database.py`): a `FingerprintEntry` dataclass
  with strict field validation, backed by a flat JSON file
  (`data/fingerprint_db.json`). Lookup distinguishes `known` (unique
  match), `possible` (hash shared by multiple distinct names — a real,
  intentionally-surfaced ambiguity), and `unknown`.
- **Orchestration** (`analyzer.py`): wires the above together per TCP
  flow found in a pcap.
- **CLI** (`cli.py`, `report.py`): `tls-fingerprint analyze <pcap>` for
  the primary path, plus `db list`/`db add` and an optional (untested by
  us, needs root) `live` subcommand.
- **Root-free traffic generation** (`capture_proxy.py`,
  `pcap_write.py`): a TCP/HTTP-CONNECT relay used only to *produce*
  experiment pcaps without requiring `sudo` — not part of the analysis
  pipeline itself. See §9 and `docs/EXPERIMENTS.md` for why this was
  necessary and how it works.

## 6. Experiments

Five distinct real clients were used, all against the same real server
(`example.com`, Cloudflare-fronted), so the TLS implementation is the
only variable. Full commands, raw output, and discussion for each are in
`docs/EXPERIMENTS.md`:

1. `curl` 8.7.1 (macOS system, SecureTransport/LibreSSL)
2. `openssl s_client` 3.6.2 (Homebrew OpenSSL)
3. Python 3.14.6 stdlib `ssl` module
4. Google Chrome 151 (headless, real browser binary)
5. A hand-built ClientHello over a raw socket, no TLS library at all

Two further experiments go beyond the base MVP requirement:

6. **JA4 vs JA3 stability** — the same real Chrome install, run twice,
   produced two different JA3 hashes (extension-order randomization,
   caught live rather than assumed). Computing JA4 on the same two
   captures showed its cipher-hash segment stayed byte-identical across
   both runs, while its extension-count segment correctly changed from 16
   to 17 because Chrome genuinely sent one additional extension the
   second time. JA4 isolates *what* changed instead of collapsing
   everything into one opaque, order-sensitive hash.
7. **Bot/spoofing detection** — a script sends a real TLS handshake
   (Python stdlib `ssl`, already fingerprinted in Experiment 3) while
   claiming, via a spoofed HTTP `User-Agent` header, to be Chrome. A new
   `check-spoofing` command compares the real measured JA3 against the
   database's known hashes for the *claimed* identity and flags the
   mismatch. A follow-up "bombardment" run (5 independent live
   connections) showed detection holding at 5/5 regardless of request
   volume.

## 7. Results

| Client | TLS lib | TLS ver. | JA3 hash | JA3S hash |
|---|---|---|---|---|
| curl 8.7.1 (macOS) | SecureTransport/LibreSSL | 1.3 | `375c6162a492dfbf2795909110ce8424` | `d75f9129bb5d05492a65ff78e081bcb2` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | 1.3 | `0b85eb0d4981e69064e40753e4f0ac5f` | `907bf3ecef1c987c889946b737b43de8` |
| Python 3.14.6 `ssl` | OpenSSL 3.6.2 | 1.3 | `f21f8e6cf70d5980ecfe9fa2e0ef401c` | `907bf3ecef1c987c889946b737b43de8` |
| Chrome 151 (headless) | BoringSSL | 1.3 | `81a2542af8442fcd7802f178d9f2a626` | `eb1d94daa7e0344597e756a1fb6e7054` |
| Custom raw ClientHello | none | 1.2 | `c53113116bb0508ad66a61bbbe6fedc9` | `ba02d4299a6e8c8482ecf2af07631993` |

**JA4 vs JA3 stability (Experiment 6), same real Chrome, two runs:**

| Run | JA3 | JA4 |
|---|---|---|
| First | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Second | `825cf36b22c9ab3e25a5bc094aecde86` | `t13d1517h2_8daaf6152771_cb7bf5808d99` |

JA3 changed completely between runs. JA4's cipher-hash segment
(`8daaf6152771`) is identical in both — the reordering-immunity JA4 was
designed to provide, demonstrated on real, not synthetic, data.

**Bot/spoofing detection (Experiment 7):** a script sending a real
Python-`ssl` handshake while claiming to be Chrome (spoofed
`User-Agent`) was correctly flagged: `check-spoofing` reported
`MISMATCH -- SUSPICIOUS ... matches: Python 3.14.6 stdlib ssl`. A 5-request
burst (`experiments/bombard_demo.py`) was flagged 5/5, each a
genuinely separate live connection.

All 56 automated tests pass (`pytest`): unit tests for JA3/JA3S string
construction against hand-derived expected values, JA4 string
construction against the *official FoxIO spec's own worked examples*
(not just internal self-consistency), parser edge cases (truncated
records, GREASE-only cipher lists, multi-record handshake messages,
malformed extensions), database lookup semantics, spoofing-detector
logic, report formatting, and one end-to-end integration test through a
synthetic pcap. `USER MUST VERIFY` by re-running `pytest` locally if you
want to confirm this independently — the exact count may have changed if
this report is read after further edits.

## 8. Security Applications

- **Malware/C2 detection:** unusual or hand-rolled TLS stacks (as our own
  "custom raw ClientHello" experiment illustrates) stand out from normal
  browser/OS traffic patterns, even fully encrypted.
- **Anomaly detection:** flagging a JA3 never seen before from a given
  host is a useful signal independent of knowing exactly what software
  produced it.
- **Asset/software inventory:** identifying which TLS library versions
  are actually active on a network without endpoint agents.
- **JA3+JA3S pairing:** combining both narrows identification to a
  specific client talking to a specific server in a specific way — more
  specific than either fingerprint alone (see the Salesforce JA3
  publication for the original malware-C2 pairing use case this was
  designed for).
- **Identity-claim verification (bot detection):** the most concrete
  application this project demonstrates directly (Experiment 7) — an
  `HTTP User-Agent` header is a string the client chooses, trivial to
  fake; the TLS ClientHello it sent moments earlier is a structural
  property of whatever library actually built it, much harder to fake
  convincingly. Comparing the two catches automated clients
  impersonating real browsers, which is exactly how production bot-
  mitigation products use this technique.

## 9. Limitations

- **A JA3/JA3S match is a hint, not proof of identity.** Two different
  programs using the same TLS library version and configuration produce
  identical JA3; our database models this explicitly as a `possible`
  (ambiguous) match rather than guessing.
- **JA3S is context-dependent, not a pure server identity.** Demonstrated
  empirically above: `openssl s_client` and our Python client produced
  *identical* JA3S hashes against the same server, because their
  ClientHellos overlapped enough for Cloudflare to make the same choice
  both times.
- **GREASE and extension-order randomization actively work against
  fingerprint stability.** RFC 8701 GREASE values are stripped per the
  spec (`ja3.GREASE_VALUES`), but modern Chrome also randomizes
  ClientHello extension *order* per connection specifically to weaken
  JA3 as a tracking mechanism — standard (order-sensitive) JA3, as
  implemented here per the published spec, can produce different hashes
  for the *same* real browser install across connections. **This was
  independently re-verified directly**, not just cited from
  documentation: re-running the identical headless Chrome command a
  second time (Experiment 6) produced a different JA3 hash for the same
  real Chrome 151 install. Implementing JA4 alongside JA3 (originally
  listed as future work below) let us isolate *why*: its cipher-hash
  segment stayed identical across both runs while its extension-count
  segment correctly changed, showing the instability was specifically in
  extension handling, not a wholesale re-fingerprinting.
- **Version/config drift.** The same tool can shift to a different JA3
  after a library upgrade or OS update; every database entry records the
  OS/date it was measured on for exactly this reason.
- **Deliberate evasion is trivial in principle.** Since JA3 is entirely a
  function of client-controlled bytes, any client (including malware) can
  mimic a popular browser's exact cipher/extension list.
- **Capture method caveat.** Four of the five experiment pcaps were
  produced via a root-free local TCP/CONNECT relay
  (`capture_proxy.py`) rather than a NIC-level tap, because this
  environment cannot supply an interactive `sudo` password. The TLS
  bytes captured are genuinely what the real client sent and the real
  server returned (certificate validation succeeded end-to-end in every
  experiment); only the *capture mechanism* differs from classic
  `tcpdump`, and this is disclosed in every database entry's `source`
  field and in `docs/EXPERIMENTS.md`. The traditional `sudo tcpdump`
  path is documented in `docs/SETUP_MAC.md` §6b as an alternative,
  `NOT EXECUTED` by this project.
- **No confidentiality is broken anywhere in this project.** Only the
  unencrypted ClientHello/ServerHello preamble is read.

## 10. Future Work

**Done, originally listed here as a stretch goal:** JA4 (client) is now
implemented and spec-verified (§6–7 above) — kept in this section's
history to show the project's actual trajectory rather than rewriting it
away.

**Still genuinely out of scope:**

- **JA4S/JA4H/JA4X/JA4SSH** (the rest of the JA4 family) and **JARM**
  (active server fingerprinting) — this project only implemented client-
  side JA4.
- **Larger, more diverse reference database:** more OS versions, more
  tools (wget, Node.js, Go's `net/http`, mobile app stacks), and ideally
  contributions of `published_reference`-tagged entries from trustworthy
  external sources (with citations), which this project deliberately did
  not fabricate.
- **Interactive/live browser capture** (real, non-headless browsing) to
  see whether interactive Chrome shows the same run-to-run instability as
  the headless captures in Experiment 6.
- **eBPF/XDP-based high-performance capture** — Linux-only, and
  unnecessary at this traffic scale; explicitly excluded from the MVP
  per project scope.
- **Live capture UX polish** (the `tls-fingerprint live` subcommand
  exists but requires `sudo` and was not part of this project's tested
  demonstration path).
- **Reading the real HTTP `User-Agent`** rather than supplying it
  out-of-band to `check-spoofing` — would require this project to
  actually terminate TLS itself (act as a mock server/WAF), which was
  deliberately avoided to keep "never decrypt anything" a hard rule
  throughout.

## 11. Conclusion

This project builds a working, tested, passively-observing JA3/JA3S
fingerprinting pipeline from a `.pcap` file down to a human-readable
client/server identification, validated end-to-end against five genuinely
different real TLS clients producing five genuinely different JA3
hashes — including two clients sharing an identical underlying crypto
library, which still fingerprinted differently due to configuration
differences alone. Every fingerprint in the reference database, and every
number in this report's results table, was computed from real captured
traffic, never invented. The project also documents, rather than glosses
over, the real limitations of hash-based TLS fingerprinting: ambiguous
matches, GREASE, extension-order randomization, and version drift are all
either demonstrated directly or explicitly flagged as a known gap.

Beyond the base requirement, the project implements JA4 (spec-verified
against FoxIO's own published worked examples) and uses it to explain,
not just cite, why the same real Chrome install fingerprinted
differently across two runs — and builds a working bot/spoofing
detector on top of JA3 that catches a script lying about its identity
via a spoofed `User-Agent`, holding at 5/5 detections under a burst of
independent live connections. Both extensions were motivated directly by
findings from the base experiments, not chosen arbitrarily.
