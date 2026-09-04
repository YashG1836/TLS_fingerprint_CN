# TLS Fingerprinting (JA3 / JA3S / JA4)

A tool that reads TLS handshakes out of a packet capture and works out which
program opened the connection, using only the shape of the handshake. Nothing
is decrypted at any point.

Computer Networks course project, IIT Gandhinagar.

## Why this is possible

A TLS connection opens with two messages that travel in plaintext, because at
that point no keys exist yet:

* ClientHello, sent by the client. It carries the TLS version the client
  claims, an ordered list of every cipher suite it supports, an ordered list
  of extensions, the elliptic curve groups it accepts, and the EC point
  formats it accepts.
* ServerHello, the reply. It carries the negotiated version, the single
  cipher suite the server chose, and the server's own extensions.

Nothing in the TLS specification dictates what a client must offer or in what
order. Every TLS library ships its own defaults, and every application
configures those defaults differently. Chrome's list is not OpenSSL's list,
which is not Go's, which is not what curl sends on macOS. That ordered set of
numbers is in effect a signature of the library, its version, and how the
program configured it, and it is sitting in the clear on the wire.

Fingerprinting reads that signature. It never touches the content of the
connection, which is why a monitoring system can classify traffic it has no
ability to decrypt.

## What the tool does

Given a `.pcap` file:

1. Groups packets into TCP flows by address and port pair.
2. Reassembles each direction of each flow into a single byte stream, ordered
   by sequence number, so a handshake split across several packets is still
   readable.
3. Walks the TLS records in that stream and extracts handshake messages of
   type `0x01` (ClientHello) and `0x02` (ServerHello).
4. Parses those messages field by field against RFC 5246 and RFC 8446. The
   parser reads raw bytes rather than using Scapy's TLS layer, so every byte
   offset can be traced back to a line in the specification.
5. Computes JA3 and JA4 from the ClientHello, and JA3S from the ServerHello.
6. Looks each value up in a local reference database and reports the likely
   client or server.

On top of that it can compare a claimed identity against the measured
fingerprint, which is how TLS fingerprinting is actually used in production
bot detection.

## The three fingerprints

### JA3

Five fields pulled straight out of the ClientHello, joined by commas, each
field being a list joined by dashes:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
```

The hand-built client in this repository produces a short one:

```
771,49199-49195-47-53,0-10-11-13,29-23,0
```

The JA3 is the MD5 of that string. Order is preserved, which becomes
important further down.

GREASE values (RFC 8701) are stripped before hashing. These are reserved
numbers that Chrome and others insert at random positions on purpose, so that
the ecosystem does not hard-code around whatever value set happens to exist
today. Leaving them in would give the same browser a different hash on every
single connection.

### JA3S

The server-side counterpart, computed from the ServerHello. Three fields:
version, the one cipher suite the server chose, and its extension list. MD5
again.

A ServerHello is a response, so what the server sends depends on what the
client offered. A JA3S therefore only means something read next to the JA3
that produced it. This repository demonstrates that directly: two of the five
clients received an identical JA3S from the same server.

### JA4

A later design that removes JA3's order sensitivity. Chrome has shuffled its
ClientHello extension order on every connection since version 110, which
changes the JA3 hash each time and makes JA3 unusable as a browser
identifier.

A JA4 looks like this:

```
t13d1516h2_8daaf6152771_806a8c22fdea
```

Reading it left to right:

| Part | Meaning |
|---|---|
| `t` | TCP. `q` would mean QUIC |
| `13` | TLS 1.3, read from the `supported_versions` extension when present |
| `d` | an SNI hostname was sent. `i` means the client connected to a bare IP |
| `15` | fifteen cipher suites offered, GREASE excluded |
| `16` | sixteen extensions offered, GREASE excluded |
| `h2` | first and last character of the first ALPN value |
| `8daaf6152771` | truncated SHA256 of the cipher list, sorted numerically |
| `806a8c22fdea` | truncated SHA256 of the sorted extension list plus the signature algorithms in send order |

Sorting is what defeats reordering. The readable prefix means two
fingerprints can be compared field by field rather than only as equal or not
equal, so when a fingerprint does change you can see which part changed.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
```

`pip install -e .` installs the `tls-fingerprint` command onto your PATH.

## Usage

```bash
tls-fingerprint analyze pcaps/curl.pcap          # identify one capture
tls-fingerprint analyze pcaps/curl.pcap --json    # same output as JSON
tls-fingerprint db list                            # list known fingerprints
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
```

A run against `pcaps/curl.pcap` prints the flow endpoints, the SNI, the
negotiated TLS version, then the JA3 string and hash, the JA4 string, the
JA3S string and hash, and a database verdict for each:

```
Client Identification
--------------------------------
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)
```

A verdict is one of three values. `known` means exactly one database entry
carries that hash. `possible` means several entries with different names
share it, which is a real property of JA3 rather than a failure, and the tool
lists all of them instead of picking one. `unknown` means the hash is not on
file.

`docs/IMPLEMENTATION.md` walks through the full demonstration command by
command.

## Results

Five programs, one server (`example.com`), five different JA3 hashes:

| Client | TLS library | JA3 | JA4 |
|---|---|---|---|
| curl 8.7.1 | SecureTransport over LibreSSL 3.3.6 | `375c6162a492dfbf2795909110ce8424` | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | `0b85eb0d4981e69064e40753e4f0ac5f` | `t13d301100_1d37bd780c83_8e6e362c5eac` |
| Python 3.14.6 stdlib `ssl` | OpenSSL 3.6.2, same build | `f21f8e6cf70d5980ecfe9fa2e0ef401c` | `t13d171100_ab0a1bf427ad_8e6e362c5eac` |
| Chrome 151 headless | BoringSSL | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| hand-built ClientHello | none, raw socket | `c53113116bb0508ad66a61bbbe6fedc9` | `t12d040400_4fe0dd5c3cea_1d42f82b3e0b` |

The third and fourth rows are the interesting pair. `openssl s_client` and
Python's `ssl` module are linked against the same OpenSSL 3.6.2 build and
still fingerprint differently, because `ssl.create_default_context()` curates
a shorter and differently ordered cipher list than the `openssl` command line
tool's default. JA3 identifies the configuration a program presents, not
merely which library is loaded.

Running the same headless Chrome twice produced two different JA3 hashes.
That is Chrome's per-connection extension shuffling, observed directly rather
than cited. JA4 on the same two captures kept its cipher segment
(`8daaf6152771`) byte for byte identical across both runs, which is what
sorting is supposed to guarantee. Its extension count segment did move from
16 to 17, because the second run genuinely sent one extra extension. JA4
isolates that as a real difference instead of collapsing it into one opaque
number.

`data/fingerprint_db.json` holds 15 entries covering those 5 clients across
JA3, JA3S and JA4. Those 15 entries contain 14 distinct values, because two
clients legitimately share a JA3S.

## Identity claim checking

An HTTP `User-Agent` header is a string the client chooses, so any script can
claim to be Chrome for the cost of one line of code. The ClientHello was
already sent before that header existed, by whichever TLS library the program
actually links against.

`experiments/bot_client.py` sends a Chrome `User-Agent` over a plain Python
`ssl` handshake. Running:

```bash
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
```

reports a mismatch and names what the fingerprint really belongs to.

The claimed identity is supplied as an argument rather than read from the
traffic. Reading it would mean terminating TLS, and this project never
decrypts anything. In a real deployment the reverse proxy that terminates TLS
is the one component that legitimately sees the ClientHello and the
`User-Agent` together, and this mirrors that arrangement.

This check catches the cheap and common case, which is a fake label on an
off-the-shelf script. It does not catch a tool such as curl-impersonate or
uTLS that copies Chrome's ClientHello byte for byte, and it does not catch a
real browser driven by automation. Those produce genuinely Chrome-shaped
handshakes.

## How the captures were produced

The `.pcap` files in `pcaps/` were not taken off a network interface. Live
capture needs root, which was not available in the environment used to build
this project, so `src/tls_fingerprint/capture_proxy.py` was used instead. It
is a TCP relay: the client is pointed at `127.0.0.1`, the relay forwards every
byte to the real server without modification while keeping a copy, and
`pcap_write.py` wraps that copy in Ethernet, IP and TCP headers to produce a
readable `.pcap`.

The consequence is worth stating plainly. The TLS bytes are exactly what the
real client sent and the real server replied, and certificate validation
succeeded end to end on every capture. The packet framing around them is
synthetic, so each file contains one packet per direction rather than a full
TCP conversation. Wireshark reads these files and computes the same JA3
values from them, which is the check that matters here.

The analysis pipeline itself has no such limitation. It reads ordinary
captures the same way, including ones with real three-way handshakes,
segmented ClientHellos, out-of-order delivery and multiple concurrent flows.

## Verifying the implementation

Two independent checks.

The test suite:

```bash
pytest
```

61 tests. JA3 and JA3S string construction is checked against expected values
derived by hand from the RFC field layout. JA4 is checked against the worked
examples published in the FoxIO specification, so the ground truth comes from
outside this project. The rest cover parser edge cases (truncated records, a
ClientHello offering only GREASE ciphers, a handshake split across two TLS
records, a malformed extension length), database lookup logic, the
identity-claim comparison, one end-to-end run from pcap to printed report,
and a check that every entry in `data/fingerprint_db.json` still reproduces
from the pcap it was measured from.

Cross-checking against Wireshark, which implements JA3 and JA4 independently:

```bash
tshark -r pcaps/chrome_live.pcap -Y "tls.handshake.type==1" \
  -T fields -e tls.handshake.ja3 -e tls.handshake.ja4
tls-fingerprint analyze pcaps/chrome_live.pcap
```

The values agree on every capture in `pcaps/`, for JA3, JA3S and JA4.

## Limitations

An identical hash does not mean identical software. Two unrelated programs
built on the same library with the same configuration produce the same JA3.
The database reports this as `possible` rather than guessing.

JA3S depends on the client as well as the server, as two of the five clients
here demonstrate.

GREASE and extension-order randomisation exist specifically to weaken this
technique, and Chrome's randomisation is enough on its own to make JA3
unreliable for browsers. JA4 survives reordering but not a genuine change in
what the client offers.

Evasion is straightforward in principle. Every byte in a ClientHello is under
the client's control, so any program can copy a popular browser's exact
cipher and extension list. Tools that do this already exist.

Fingerprints drift. A library or OS update can move a program to a different
JA3, so every database entry records the operating system and date it was
measured on.

A fingerprint is a signal to correlate with others, not proof of identity.
Nothing here decrypts anything or claims certainty.

## Repository layout

```
src/tls_fingerprint/
  parser.py             raw TLS bytes to ClientHello / ServerHello fields
  ja3.py, ja3s.py       JA3 and JA3S construction and hashing
  ja4.py                JA4 construction
  database.py           JSON reference database and lookup
  analyzer.py           per-flow pipeline, ties the above together
  report.py, cli.py     command line interface and printed output
  spoofing_detector.py  claimed identity against measured fingerprint
  capture_proxy.py      relay used to produce the experiment captures
  pcap_write.py         writes captured bytes out as a .pcap

data/fingerprint_db.json   15 measured reference entries
pcaps/                     every capture used for a result in this repository
experiments/               the client scripts that generated those captures
tests/                     61 tests
screenshots/               terminal output for each demonstration step
docs/
  IMPLEMENTATION.md        step by step demonstration script
  PROJECT_REPORT.md        formal write-up
```

## References

* JA3 and JA3S: https://github.com/salesforce/ja3
* JA4: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
* RFC 8446, TLS 1.3
* RFC 8701, GREASE# TLS Fingerprinting (JA3 / JA3S / JA4)

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
