# TLS Fingerprinting (JA3 / JA3S / JA4)

A Computer Networks course project: a tool that reads TLS handshakes from
`.pcap` files and identifies the client/server software from the
*shape* of the handshake alone — no decryption involved.

## Why this works

Right before HTTPS encryption kicks in, both sides send one message each
in **plain text**:

- **ClientHello** — the client's TLS version, its list of ciphers, and a
  list of extensions.
- **ServerHello** — the server's reply: the version and cipher it picked.

Different programs (Chrome, curl, Python, malware, a bot...) build this
"hello" message slightly differently — different cipher order, different
extensions. That difference is a fingerprint, and it's sitting in the
open, before any encryption starts.

## What this project does

1. **Reads a `.pcap`** (a recording of network traffic).
2. **Finds the ClientHello / ServerHello** inside it.
3. **Turns each one into a short hash** — using **JA3** (client) and
   **JA3S** (server), the published fingerprinting standard.
4. **Looks the hash up** in a small local database of fingerprints we
   measured ourselves from 5 real programs.
5. **Prints the result**: which client it's likely to be, or "unknown"
   if we've never seen that hash before.

On top of that base pipeline, this project adds two things that were
built in direct response to something we discovered while testing:

- **JA4** — a newer, improved fingerprint. We found that the *same real
  Chrome browser*, run twice, produced two *different* JA3 hashes
  (Chrome shuffles its handshake order on purpose to resist
  fingerprinting). JA4 sorts the cipher and extension lists before
  hashing, so we checked both runs against it: the cipher-hash segment
  came out byte-for-byte identical, exactly what sorting is supposed to
  guarantee. The extension-count segment legitimately changed (16 → 17)
  because the second run genuinely sent one extra extension — JA4
  isolates that as a real difference instead of hiding it behind one
  opaque hash the way JA3 does.
- **Bot / spoofing detection** — a tool that catches a program lying
  about its identity. A script can freely claim to be "Chrome" (that's
  just a text header), but it can't as easily fake the actual TLS
  handshake its real library produces. We built a checker that compares
  the claim against the real fingerprint and flags the mismatch — this
  is the real-world security use case for all of the above.

## Everything is real, nothing is invented

Every hash in this repo — in the database, in the docs, in the
presentation — was computed from an actual network connection this
project made to a real server (`example.com`). None of it is hardcoded
or guessed. `docs/IMPLEMENTATION.md` shows exactly which commands
produced which result.

## Project layout

```
src/tls_fingerprint/
  parser.py             reads raw TLS bytes -> ClientHello / ServerHello fields
  ja3.py, ja3s.py        turns a hello into a JA3 / JA3S hash
  ja4.py                 turns a ClientHello into a JA4 fingerprint
  database.py            the local JSON "known fingerprints" lookup
  analyzer.py             wires the above together for one pcap
  report.py, cli.py       command-line tool + printed output
  spoofing_detector.py     compares a claimed identity against the real fingerprint
  capture_proxy.py, pcap_write.py   used only to GENERATE real test traffic (see below)

data/fingerprint_db.json   15 real, measured entries (5 clients x JA3/JA3S/JA4; 14 distinct
                           fingerprints -- two clients legitimately share one JA3S, see below)
pcaps/                     the actual recordings used for every result in this repo
experiments/                scripts that generated those recordings
tests/                      61 automated tests
docs/
  IMPLEMENTATION.md          run this live to present the project (start here for a demo)
  STUDY_GUIDE.md              networking/TLS concepts from zero
  VIVA.md                      likely viva questions, short answers
  PROJECT_REPORT.md            formal write-up
```

## Setup (macOS)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
```

macOS needs `sudo` to sniff live network packets, which isn't available
in an automated environment — so this project generates real traffic
through a small relay (`capture_proxy.py`) instead of a raw packet
capture. It forwards every byte untouched to the real server (the
handshake and certificate check are fully real), while also saving a
copy as a `.pcap`. See `docs/IMPLEMENTATION.md` for exact commands.

## Quick start

```bash
pytest                                   # 61 tests should pass
tls-fingerprint db list                  # the known-fingerprint database
tls-fingerprint analyze pcaps/curl.pcap  # identify a real capture
```

Example output:
```
Client Identification
--------------------------------
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)
```

**For the full live demo** (5 clients, the JA3-vs-JA4 comparison, bot
detection) — everything is scripted step by step in
[`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md).

## Results, in one table

Five different real programs, same real server, five different JA3
hashes:

| Client | TLS library | JA3 hash |
|---|---|---|
| curl 8.7.1 | SecureTransport / LibreSSL | `375c6162a492…ce8424` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | `0b85eb0d4981…f0ac5f` |
| Python stdlib `ssl` | OpenSSL 3.6.2 (**same library as above**) | `f21f8e6cf70d…ef401c` |
| Google Chrome 151 | BoringSSL | `81a2542af844…f2a626` |
| Hand-built ClientHello | none — raw socket | `c53113116bb0…6fedc9` |

curl and openssl/Python share nothing; openssl and Python share the
*exact same* crypto library and still fingerprint differently — proof
JA3 reflects configuration, not just which library is linked.

## Limitations (read before trusting a match)

- **Same hash ≠ same software.** Two unrelated programs on the same
  library/config get the same JA3. The database reports this honestly
  as `possible`, never a silent guess.
- **JA3S depends on the client, too** — two of our own clients got an
  identical JA3S against the same server.
- **GREASE and handshake-order randomization actively fight this.**
  Chrome shuffles its own ClientHello on purpose (we caught it live —
  see `docs/IMPLEMENTATION.md`).
- **It's evadable.** Since the fingerprint is entirely client-controlled
  bytes, anyone can copy another program's exact signature.
- **A fingerprint is a hint, never proof.** Nothing here decrypts
  anything or claims certainty.

## Testing

```bash
pytest
```
61 tests: JA3/JA3S checked against hand-derived expected values, JA4
checked against the *official FoxIO spec's own worked examples*, parser
edge cases, database lookup logic, spoofing-detector logic, and an
end-to-end pcap-to-result integration test.
