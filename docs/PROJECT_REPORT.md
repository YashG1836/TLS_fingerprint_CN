# TLS Fingerprinting with JA3, JA3S and JA4

## 1. Introduction

This project implements a tool that identifies the software behind a TLS
connection by examining the structure of its handshake, without decrypting
any part of the connection. It computes JA3 and JA4 fingerprints from the
ClientHello, JA3S from the ServerHello, and matches them against a reference
database built by measuring five distinct clients.

It also includes an identity-claim checker that compares a client's stated
identity against its measured fingerprint, which is the form in which TLS
fingerprinting is used commercially.

## 2. Motivation

Almost all web traffic is now encrypted. A firewall or monitoring system
placed on the network can no longer read URLs, headers or payloads. What it
can still read is the handshake that sets the encryption up, because the first
two messages of that handshake necessarily travel in plaintext.

Those messages are not uniform across clients. Every TLS library ships its
own defaults for which cipher suites to offer and in what order, which
extensions to include, and which elliptic curve groups to accept, and every
application layers its own configuration on top. The result is that the
opening message of a connection carries enough structure to distinguish a
browser from a scripting library from a purpose-built tool.

This gives a defender a signal for client identification, asset inventory and
malware detection that survives encryption, at the cost of a technique that is
approximate and evadable. Both halves of that trade are demonstrated here.

## 3. Background

### 3.1 TCP and packet capture

IP delivers packets between hosts and may drop, duplicate or reorder them.
TCP layers an ordered, reliable byte stream on top, using sequence numbers so
the receiver can reassemble what was sent. A `.pcap` file is a recording of
packets seen on an interface.

Reading a `.pcap` requires no privileges. Capturing one from a live interface
does, because it needs access to the kernel packet filter.

A single TLS handshake message can exceed one segment, so any tool that reads
handshakes from a capture must reassemble the TCP stream first rather than
parsing packets individually.

### 3.2 The TLS handshake

TLS provides encryption, integrity and server authentication above TCP. The
handshake begins with two messages sent before any key material exists, and
therefore in the clear:

ClientHello carries a legacy version field, a 32 byte random value, an ordered
list of cipher suites, a list of compression methods, and a list of
extensions. Among those extensions are `server_name` (the hostname being
requested), `supported_groups` (elliptic curve groups), `ec_point_formats`,
`signature_algorithms`, `application_layer_protocol_negotiation`, and, in TLS
1.3, `supported_versions`.

ServerHello carries the chosen version, a random value, the single cipher
suite the server selected, and the server's own extensions.

Under TLS 1.3 the legacy version field in both messages stays at `0x0303` for
compatibility with middleboxes, and the real negotiated version is carried in
the `supported_versions` extension. The tool reads that extension when it is
present so the version it reports is the one actually in use.

Everything after these two messages is encrypted and outside the scope of this
project.

### 3.3 Fingerprinting

Fingerprinting reads the shape of the ClientHello rather than its meaning.
Two functionally identical HTTPS requests made by different programs produce
structurally different handshakes, and that structure is stable for a given
library, version and configuration.

### 3.4 JA3 and JA3S

JA3 was published by Salesforce in 2017. It builds a string from five fields
of the ClientHello:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
```

Each field is a list of decimal values joined by dashes, in the order the
client sent them, and the five fields are joined by commas. The fingerprint is
the MD5 of that string. MD5 is used only to compress a long string into a
fixed-length comparable token, and no security property is being claimed for
it.

GREASE values, defined in RFC 8701, are removed before hashing. These are
reserved numbers that clients insert at random positions specifically so that
servers and middleboxes do not hard-code assumptions about the current value
set. If they were left in, a client that uses GREASE would produce a different
JA3 on every connection.

JA3S applies the same idea to the ServerHello, using three fields: version,
the single chosen cipher suite, and the extension list. Because a ServerHello
is a response to a specific offer, a JA3S describes a server plus the offer it
was answering, not a server on its own.

### 3.5 JA4

JA4, published by FoxIO in 2023, addresses JA3's dependence on ordering. It is
written as three segments separated by underscores, for example
`t13d1516h2_8daaf6152771_806a8c22fdea`.

The first segment is readable: transport (`t` for TCP, `q` for QUIC), TLS
version, whether an SNI hostname was sent (`d`) or the client connected to a
bare IP (`i`), the number of cipher suites, the number of extensions, and the
first and last character of the first ALPN value.

The second segment is a truncated SHA256 of the cipher list after sorting.

The third is a truncated SHA256 of the sorted extension list, excluding SNI
and ALPN since those already appear in the first segment, followed by the
signature algorithms in the order they were sent.

Sorting removes order sensitivity. The readable prefix allows two
fingerprints to be compared component by component, so a change can be
localised instead of only detected.

## 4. Architecture

```
.pcap file
  -> scapy.rdpcap
  -> group packets into TCP flows, reassemble each direction   (analyzer.py)
  -> walk TLS records, extract ClientHello and ServerHello     (parser.py)
  -> build JA3, JA3S, JA4                          (ja3.py, ja3s.py, ja4.py)
  -> look up in the reference database                        (database.py)
  -> format and print                              (report.py, cli.py)
```

Each stage is a separate module with no knowledge of the ones around it, and
each is unit tested on its own. `analyzer.py` is the only module that knows
about packets, and the fingerprint modules are pure functions over parsed
structures.

## 5. Implementation

`parser.py` walks raw TLS bytes directly against RFC 5246 and RFC 8446 rather
than using Scapy's TLS layer. The reason is auditability: every offset the
parser reads can be pointed at a specific line of the specification, and the
tool does not depend on a full TLS stack in order to read the two messages it
needs. It reassembles TCP streams by sequence number and handles a handshake
message split across multiple TLS records by buffering record payloads until a
complete message is available.

`ja3.py`, `ja3s.py` and `ja4.py` contain no parsing. They take a parsed hello
and produce a string and a hash, which makes them straightforward to test
against known values.

`database.py` holds a dataclass with field validation, backed by
`data/fingerprint_db.json`. A lookup returns one of three states. `known`
means one entry carries that hash. `possible` means several entries with
different names share it, which is a genuine property of JA3 rather than a
bug, and all candidates are reported. `unknown` means the hash is not on file.

`spoofing_detector.py` compares a caller-supplied identity claim against the
measured JA3 and reports agreement, mismatch, or insufficient reference data.

`capture_proxy.py` and `pcap_write.py` exist only to produce the experiment
captures and are not part of the analysis path. Section 10 covers what they do
and what that implies.

## 6. Experimental method

Five programs were pointed at `example.com`, a domain IANA reserves for
documentation and testing:

1. curl 8.7.1, the macOS system build, using SecureTransport over LibreSSL
2. openssl s_client 3.6.2, installed via Homebrew
3. Python 3.14.6 using `ssl.create_default_context()`
4. Google Chrome 151 in headless mode, using BoringSSL
5. A ClientHello assembled by hand over a raw socket, using no TLS library

The fourth and fifth are the two ends of the range. Chrome is the most
heavily engineered client in common use, and the hand-built hello was written
byte by byte for this project and deliberately offers legacy TLS 1.2 with no
`supported_versions` or `key_share` extension.

Two further experiments followed from observations made during testing rather
than being planned:

6. Chrome was captured a second time to test fingerprint stability across runs
   of the same install.
7. A script sending a real Python `ssl` handshake under a spoofed Chrome
   `User-Agent` was captured, to test whether the fingerprint contradicts the
   claim.

## 7. Results

### 7.1 Five clients

| Client | TLS library | JA3 | JA3S |
|---|---|---|---|
| curl 8.7.1 | SecureTransport over LibreSSL | `375c6162a492...ce8424` | `d75f9129bb5d...e081bcb2` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | `0b85eb0d4981...f0ac5f` | `907bf3ecef1c...37b43de8` |
| Python 3.14.6 `ssl` | OpenSSL 3.6.2 | `f21f8e6cf70d...ef401c` | `907bf3ecef1c...37b43de8` |
| Chrome 151 headless | BoringSSL | `81a2542af844...f2a626` | `eb1d94daa7e0...fb6e7054` |
| hand-built ClientHello | none | `c53113116bb0...6fedc9` | `ba02d4299a6e...7631993` |

Five clients, five distinct JA3 hashes, each correctly identified by the tool
from its handshake alone.

Rows two and three are the informative pair. They are linked against the same
OpenSSL 3.6.2 build and produce different JA3 hashes, because
`ssl.create_default_context()` curates a shorter and differently ordered
cipher list than the `openssl` command line tool's default. JA3 identifies the
configuration a program presents, not merely the library it loads.

Those same two rows also produced an identical JA3S. Their offers overlapped
enough that the server made the same choice twice. This is the predicted
behaviour of a server-side fingerprint and is discussed in section 10.

### 7.2 Chrome across two runs

| Run | JA3 | JA4 |
|---|---|---|
| First | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Second | `a00e551d2f4af85ede1156537ebf095a` | `t13d1517h2_8daaf6152771_541cd5a3d78e` |

The same browser install, run twice minutes apart, produced two completely
different JA3 hashes. Chrome randomises the order of its ClientHello
extensions on every connection, and JA3 hashes those extensions in send order.

JA4 on the same two captures kept its cipher segment, `8daaf6152771`,
identical across both runs. That segment is the hash of the cipher list after
sorting, and its stability is the property JA4 was designed to provide,
confirmed here on real traffic.

The remainder of the JA4 string did change, and correctly so. The extension
count moved from 16 to 17 because the second run genuinely offered one
additional extension. That is a real difference in what the client sent, not a
reordering. The value of JA4's layout is visible here: it localises the change
to the extension component, whereas JA3 reports only that the hash is
different.

### 7.3 Identity claim checking

A script sending a real Python `ssl` handshake while claiming to be Chrome was
flagged as a mismatch, and the tool named Python's `ssl` module as what the
fingerprint actually belongs to. Repeating the request five times over five
separate connections produced five flags, since each connection is evaluated
on its own handshake rather than against a threshold or a running average.

### 7.4 Verification

The test suite contains 61 tests. JA3 and JA3S string construction is checked
against values derived by hand from the RFC field layout, so the code is
compared against the specification rather than against itself. JA4 is checked
against the worked examples published in the FoxIO specification, which is
ground truth from outside this project. The remaining tests cover parser edge
cases including a truncated record, a ClientHello offering only GREASE
ciphers, a handshake split across two TLS records and a malformed extension
length; database lookup behaviour; the identity-claim comparison; one
end-to-end run from `.pcap` to printed report; and a check that every entry in
the reference database still reproduces from the capture it was measured from.

Separately, every fingerprint this tool produces was compared against
Wireshark, which implements JA3, JA3S and JA4 independently. The values agree
on every capture in `pcaps/`.

## 8. A specification conformance issue found during verification

The Wireshark comparison surfaced a disagreement on one capture. This
implementation had been stripping GREASE values from the
`signature_algorithms` list before hashing it into JA4's third segment.

The JA4 specification strips GREASE from the cipher list and the extension
list and says nothing about the signature algorithm list, and Wireshark's
dissector keeps GREASE there. Modern Chrome does insert a GREASE value into
`signature_algorithms`, so the two implementations diverged on the Chrome
capture and agreed everywhere else, since no other client in the set offers a
GREASE signature algorithm.

```
tshark:            t13d1517h2_8daaf6152771_541cd5a3d78e
before the fix:    t13d1517h2_8daaf6152771_cb7bf5808d99
```

The filter was removed and a regression test added that feeds a signature
algorithm list containing `0x4a4a` through the extension hash and asserts the
value Wireshark reports. All captures now agree with Wireshark on all three
fingerprint types.

The wider point is that cross-checking against an independent implementation
found a defect that a self-consistent test suite could not, because the suite
was verifying the code against the same assumption the code was built on.

## 9. Security applications

Malware command and control detection. Malware families reuse their TLS stack
across samples, and an unusual or hand-rolled stack stands out against ordinary
browser and operating system traffic even when the traffic itself cannot be
read. The hand-built client in this project is an instance of exactly that
shape.

Anomaly detection. A JA3 never previously seen from a given host is a useful
signal on its own, without knowing what produced it.

Asset inventory. Identifying which TLS library versions are active on a
network without installing anything on the endpoints.

Client and server pairing. A JA3 read together with the JA3S it produced
narrows identification further than either alone.

Identity claim verification. This is the application the project demonstrates
end to end. An HTTP `User-Agent` is a string the client chooses. The
ClientHello sent moments earlier is a structural consequence of the library
the program actually uses. Comparing the two catches a script wearing a
browser's label, and this is the mechanism behind commercial bot mitigation
products.

## 10. Limitations

An identical hash does not imply identical software. Two unrelated programs on
the same library and configuration produce the same JA3. The database reports
this as `possible` and lists every candidate rather than choosing one.

JA3S depends on the client as well as the server. Two clients in this project
received the same JA3S from the same server because their offers overlapped
enough for the server to choose identically. A JA3S should be read as a
property of a client and server pair.

GREASE and extension-order randomisation exist to weaken this technique.
GREASE is handled by stripping it where the specifications require. Chrome's
per-connection reordering is not something a fingerprint can undo, and section
7.2 shows it defeating JA3 outright. JA4 survives reordering but not a genuine
change in what a client offers.

Evasion is straightforward in principle. Every byte of a ClientHello is chosen
by the client, so a program can reproduce a popular browser's exact cipher and
extension list. Tools that do this are publicly available. A clean fingerprint
therefore proves nothing.

Fingerprints drift. A library or operating system update can move a program to
a different JA3, so every database entry records the platform and date it was
measured on.

Capture method. The captures in `pcaps/` were not taken from a network
interface. Live capture requires root, which was not available in the
environment this project was built in, so a local TCP relay was used instead:
the client connects to the relay, the relay forwards every byte to the real
server unmodified while keeping a copy, and that copy is written out as a
`.pcap`. The TLS bytes are exactly what the client sent and the server
returned, and certificate validation succeeded end to end on every capture.
The packet framing around them is synthetic, so each file holds one packet per
direction rather than a full TCP conversation. Every database entry records
this in its `source` field. The analysis pipeline itself has no such
limitation and reads ordinary captures, including segmented handshakes,
out-of-order delivery and multiple concurrent flows.

Nothing is decrypted anywhere. Only the plaintext preamble of the handshake is
ever read.

## 11. Future work

Completed during the project, having originally been a stretch goal: JA4 for
the client side, and the identity-claim detector.

Not attempted:

JA4S, JA4H, JA4X and JA4SSH, the rest of the JA4 family, and JARM, which
fingerprints servers actively by sending crafted hellos rather than observing.

A larger and more varied reference database. Five clients on one operating
system is enough to demonstrate the technique and not enough to deploy it.
More tools, more platforms and entries sourced from published reference sets
with citations would all improve it.

Live capture from a network interface, which needs root and would replace the
relay described in section 10.

Capture at higher rates using eBPF or XDP, which would allow fingerprints to
be computed in kernel space rather than copying every packet to userspace.
This is Linux specific and unnecessary at the traffic volumes involved here.

Backing the lookup with a key-value store such as Redis rather than a JSON
file, which matters once the database is large enough that per-flow lookup
latency is a consideration.

Reading the `User-Agent` from the traffic rather than accepting it as an
argument, which would require terminating TLS and was avoided deliberately.

## 12. Conclusion

The project produces a working pipeline from a packet capture to a named
client, using only the plaintext portion of the TLS handshake. It was
validated on five genuinely different clients producing five different
fingerprints, including two clients that share a crypto library and still
fingerprint differently on configuration alone, and independently
cross-checked against Wireshark on every capture.

Two findings came out of the experiments rather than the plan. The same Chrome
install fingerprinted differently across two runs, which is JA3 failing in the
way its critics describe, and implementing JA4 made it possible to say which
component of the handshake had moved. Cross-checking against Wireshark
surfaced a conformance defect in this project's own JA4 implementation, which
was fixed and covered by a regression test.

The limitations are as much a result as the successes. A fingerprint is a
signal to correlate with other evidence, not an identity, and a technique that
reads only bytes the client chose to send can always be imitated by a client
that chooses to send different ones.

## References

Salesforce, JA3: https://github.com/salesforce/ja3

FoxIO, JA4: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

RFC 5246, The Transport Layer Security (TLS) Protocol Version 1.2

RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3

RFC 8701, Applying Generate Random Extensions And Sustain Extensibility
(GREASE) to TLS Extensibility# Project Report: TLS Fingerprinting using JA3 / JA3S / JA4

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
| Chrome 151 (headless) | BoringSSL | `81a2542af844…f2a626` | `eb1d94daa7e0…fb6e7054` |
| Custom raw ClientHello | none | `c53113116bb0…6fedc9` | `ba02d4299a6e…7631993` |

**JA4 vs JA3, same real Chrome, two runs:**

| Run | JA3 | JA4 |
|---|---|---|
| First | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Second | `a00e551d2f4af85ede1156537ebf095a` | `t13d1517h2_8daaf6152771_541cd5a3d78e` |

JA3 changed completely; JA4's cipher-hash segment (`8daaf6152771`) is
identical in both — the reordering-immunity JA4 was designed to provide,
shown on real data.

**Bot detection:** a script sending a real Python-`ssl` handshake while
claiming Chrome was flagged `MISMATCH -- SUSPICIOUS ... matches: Python
3.14.6 stdlib ssl`. A 5-request burst (`experiments/bombard_demo.py`)
was flagged 5/5, each a genuinely separate live connection.

All 61 automated tests pass (`pytest`): JA3/JA3S checked against
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
