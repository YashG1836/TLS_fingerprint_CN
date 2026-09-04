# Project Report: TLS Fingerprinting using JA3 / JA3S / JA4

**Course:** Computer Networks
**Author:** Yash Goyal, 24110399
**Date:** 27/08/2026 (submission: 11/09/2026)

---

## 1. Introduction

This project implements a passive TLS fingerprinting tool that extracts
JA3 (client) and JA3S (server) fingerprints from TLS handshake traffic
and identifies the likely client/server software from a small,
self-curated reference database — without decrypting anything, since
ClientHello/ServerHello are sent unencrypted by design. It also
implements JA4 (a newer, more robust client fingerprint) and a
bot/spoofing detector built on top of JA3, both added in direct response
to findings made while testing the base project.

## 2. Motivation

Firewalls increasingly see only encrypted traffic — hidden are the URLs,
headers, and payloads, but not the *shape* of the handshake that sets
the encryption up. Different TLS implementations (browsers, CLI tools,
scripts, malware) configure their ClientHello differently — cipher
lists, extensions, ordering — visible in plaintext before encryption
starts. JA3/JA3S turn that structure into a short, comparable identifier,
giving defenders a signal for client identification and anomaly/malware
detection without breaking any confidentiality guarantee.

## 3. Background

**TCP/IP and packet capture.** IP addresses a device; TCP turns
unreliable IP delivery into an ordered byte stream; a `.pcap` file
records packets crossing an interface. Reading a `.pcap` needs no
special privileges on macOS; live capture off a real interface does
(root, via `sudo`).

**TLS and the handshake.** TLS adds encryption, integrity, and
(typically) server authentication on top of TCP. The handshake opens
with two unencrypted messages: **ClientHello** (version, ordered cipher
list, extensions) and **ServerHello** (negotiated version, one chosen
cipher, its own extensions). Everything after is encrypted and out of
scope.

**TLS fingerprinting.** Different TLS libraries produce structurally
different ClientHellos for functionally-equivalent requests, because
each ships its own defaults for cipher/extension ordering. Fingerprinting
reads the *shape*, never the *meaning*.

**JA3** (Salesforce, 2017): `SSLVersion,Cipher,SSLExtension,
EllipticCurve,EllipticCurvePointFormat` built from a ClientHello (each
list `-`-joined, in send order, RFC 8701 GREASE stripped), MD5-hashed.

**JA3S**: the server-side mirror, `SSLVersion,Cipher,SSLExtension` from
a ServerHello. Because it reflects a choice made from what the client
offered, JA3S is context-dependent on the client, not a pure server
identity — demonstrated empirically in §7.

**JA4** (FoxIO, 2023): fixes JA3's order-sensitivity by sorting the
cipher and extension lists before hashing.

## 4. Architecture

```
PCAP file --> scapy.rdpcap() --> group into TCP flows, reassemble
    --> walk TLS records, extract ClientHello/ServerHello (parser.py)
    --> build JA3 / JA3S / JA4 (ja3.py / ja3s.py / ja4.py)
    --> FingerprintDatabase.lookup() (database.py)
    --> format_report() --> CLI output
```

Each stage is independently importable and independently unit-tested;
`tests/test_integration.py` builds a synthetic pcap with Scapy and runs
it through the whole pipeline end to end.

## 5. Implementation

- **`parser.py`** — hand-parses raw TLS record/handshake bytes directly
  against RFC 5246/8446 rather than depending on Scapy's TLS layer, so
  every field offset is traceable to the spec. Reassembles TCP streams
  and handles a handshake message split across multiple TLS records.
- **`ja3.py` / `ja3s.py` / `ja4.py`** — pure functions building the exact
  spec string(s) and hash(es); GREASE filtering from RFC 8701's 16-value
  table.
- **`database.py`** — a `FingerprintEntry` dataclass with field
  validation, backed by `data/fingerprint_db.json`. Lookup distinguishes
  `known` (unique match), `possible` (hash shared by multiple distinct
  names — a real, surfaced ambiguity), and `unknown`.
- **`analyzer.py`** — wires the above together per TCP flow in a pcap.
- **`cli.py` / `report.py`** — `tls-fingerprint analyze/db/check-spoofing`.
- **`spoofing_detector.py`** — compares a caller-supplied identity claim
  against the measured JA3, flagging a mismatch.
- **`capture_proxy.py` / `pcap_write.py`** — a root-free TCP/HTTP-CONNECT
  relay used only to *produce* real experiment pcaps, not part of the
  analysis pipeline. See §9 and `docs/IMPLEMENTATION.md` for why this was
  necessary (macOS needs `sudo` for a real NIC capture, unavailable
  non-interactively here) and how it works.

## 6. Experiments

Five distinct real clients against the same real server
(`example.com`, Cloudflare-fronted) — full commands and output in
`docs/IMPLEMENTATION.md`:

1. `curl` 8.7.1 (macOS system, SecureTransport/LibreSSL)
2. `openssl s_client` 3.6.2 (Homebrew OpenSSL)
3. Python 3.14.6 stdlib `ssl`
4. Google Chrome 151 (headless)
5. A hand-built ClientHello over a raw socket, no TLS library at all

Two further experiments, both motivated by findings during testing:

6. **JA4 vs JA3 stability** — the same real Chrome, run twice, produced
   two different JA3 hashes (extension-order randomization, caught live).
   JA4 on the same two captures kept its cipher-hash segment identical
   across both runs, while its extension-count segment correctly changed
   16→17 because Chrome genuinely sent one extra extension the second
   time — JA4 isolates *what* changed instead of hiding it in one opaque
   hash.
7. **Bot/spoofing detection** — a script sends a real Python-`ssl`
   handshake while claiming, via a spoofed `User-Agent`, to be Chrome.
   `check-spoofing` flags the mismatch. A 5-request "bombardment" run
   showed detection holding 5/5 regardless of volume.

## 7. Results

| Client | TLS lib | JA3 hash | JA3S hash |
|---|---|---|---|
| curl 8.7.1 | SecureTransport/LibreSSL | `375c6162a492…ce8424` | `d75f9129bb5d…e081bcb2` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | `0b85eb0d4981…f0ac5f` | `907bf3ecef1c…37b43de8` |
| Python 3.14.6 `ssl` | OpenSSL 3.6.2 | `f21f8e6cf70d…ef401c` | `907bf3ecef1c…37b43de8` |
| Chrome 151 (headless) | BoringSSL | `81a2542af844…f2a626` | `eb1d94daa7e0…56e7054` |
| Custom raw ClientHello | none | `c53113116bb0…6fedc9` | `ba02d4299a6e…7631993` |

**JA4 vs JA3, same real Chrome, two runs:**

| Run | JA3 | JA4 |
|---|---|---|
| First | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Second | `825cf36b22c9ab3e25a5bc094aecde86` | `t13d1517h2_8daaf6152771_cb7bf5808d99` |

JA3 changed completely; JA4's cipher-hash segment (`8daaf6152771`) is
identical in both — the reordering-immunity JA4 was designed to provide,
shown on real data.

**Bot detection:** a script sending a real Python-`ssl` handshake while
claiming Chrome was flagged `MISMATCH -- SUSPICIOUS ... matches: Python
3.14.6 stdlib ssl`. A 5-request burst (`experiments/bombard_demo.py`)
was flagged 5/5, each a genuinely separate live connection.

All 56 automated tests pass (`pytest`): JA3/JA3S checked against
hand-derived expected values, JA4 checked against the *official FoxIO
spec's own worked examples*, parser edge cases, database lookup logic,
spoofing-detector logic, and one end-to-end integration test.

## 8. Security Applications

- **Malware/C2 detection** — an unusual/hand-rolled TLS stack (our
  "custom raw ClientHello" experiment) stands out from normal
  browser/OS traffic even fully encrypted.
- **Anomaly detection** — a never-before-seen JA3 from a host is a
  useful signal without knowing exactly what produced it.
- **Asset inventory** — identifying active TLS library versions on a
  network without endpoint agents.
- **JA3+JA3S pairing** — narrows identification to a specific client
  talking to a specific server in a specific way.
- **Identity-claim verification (bot detection)** — the concrete
  application this project demonstrates directly: an `HTTP User-Agent`
  is a trivially-faked string; the ClientHello sent moments earlier is a
  structural property of the real library, much harder to fake. This is
  exactly how production bot-mitigation products use TLS fingerprinting.

## 9. Limitations

- **A match is a hint, not proof.** Two programs on the same TLS
  library+config produce identical JA3; the database models this
  explicitly as `possible` rather than guessing.
- **JA3S is context-dependent.** `openssl s_client` and our Python
  client got *identical* JA3S against the same server, because their
  offers overlapped enough for Cloudflare to choose the same way twice.
- **GREASE and extension-order randomization actively fight fingerprint
  stability.** GREASE is stripped per RFC 8701; Chrome also randomizes
  ClientHello extension *order* per connection to weaken JA3 — verified
  directly, not just cited: re-running the identical headless Chrome
  command produced a different JA3 for the same install. Implementing
  JA4 let us isolate *why*: its cipher-hash segment stayed identical
  across both runs while its extension-count segment correctly changed,
  showing the instability was specifically in extension handling.
- **Version/config drift.** The same tool can shift to a different JA3
  after a library/OS update; every database entry records the OS/date
  measured for this reason.
- **Deliberate evasion is trivial in principle.** Since JA3 is entirely
  client-controlled bytes, any client can mimic a popular browser's
  exact cipher/extension list.
- **Capture method caveat.** Experiment pcaps were produced via a
  root-free local TCP/CONNECT relay rather than a NIC-level tap, because
  this environment has no interactive `sudo`. The TLS bytes captured are
  genuinely what the real client sent and server returned (certificate
  validation succeeded end-to-end every time); only the *capture
  mechanism* differs from classic `tcpdump`, disclosed in every database
  entry's `source` field.
- **No confidentiality is broken anywhere.** Only the unencrypted
  ClientHello/ServerHello preamble is ever read.

## 10. Future Work

**Done, originally a stretch goal:** JA4 (client) and the bot/spoofing
detector are now implemented and validated (§6–7).

**Still out of scope:**
- JA4S/JA4H/JA4X/JA4SSH (the rest of the JA4 family) and JARM (active
  server fingerprinting) — only client-side JA4 was implemented.
- A larger, more diverse reference database (more OS versions, more
  tools: wget, Node.js, Go's `net/http`, mobile stacks), and ideally
  `published_reference`-tagged entries from a trustworthy external
  source (with citation) — this project deliberately fabricated none.
- Interactive/non-headless browser capture, to see whether it shows the
  same run-to-run JA3 instability as the headless captures did.
- Reading the real HTTP `User-Agent` instead of supplying it out-of-band
  to `check-spoofing` — would require this project to terminate TLS
  itself (act as a mock server/WAF), deliberately avoided to keep "never
  decrypt anything" a hard rule throughout.
- Live packet capture off a real NIC — needs `sudo`, out of scope for
  this environment; `docs/IMPLEMENTATION.md`'s relay method is the
  primary, reproducible path instead.
- eBPF/XDP-based high-performance capture — Linux-only, unnecessary at
  this traffic scale, excluded from scope.

## 11. Conclusion

This project builds a working, tested, passively-observing JA3/JA3S
pipeline from a `.pcap` file to a human-readable identification,
validated against five genuinely different real TLS clients producing
five genuinely different JA3 hashes — including two clients sharing an
identical crypto library that still fingerprinted differently on
configuration alone. Every number in this report was computed from real
captured traffic, never invented. Limitations — ambiguous matches,
GREASE, extension-order randomization, version drift — are demonstrated
directly rather than only asserted.

Beyond the base requirement, the project implements JA4 (spec-verified
against FoxIO's own published examples) to explain *why* the same real
Chrome install fingerprinted differently across two runs, and a working
bot/spoofing detector on top of JA3 that catches a script lying about
its identity, holding at 5/5 detections under a burst of independent
live connections. Both extensions were motivated directly by findings
from the base experiments, not chosen arbitrarily.
