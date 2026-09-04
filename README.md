# TLS Fingerprinting (JA3 / JA3S / JA4)

Reads TLS handshakes out of a packet capture and works out which program
opened the connection, from the structure of the handshake alone.

The first two messages of a TLS connection travel in plaintext, because at
that point no keys exist. Those messages differ between clients: every TLS
library ships its own cipher list, extension list and ordering, and every
application configures them differently. JA3, JA3S and JA4 turn that
structure into a short identifier.

`docs/BACKGROUND.md` covers how the handshake works and how each of the three
fingerprints is built. Read that first if the terms are new.

## Install

Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install pytest
```

That puts `tls-fingerprint` on your PATH.

## Use

```bash
tls-fingerprint analyze pcaps/curl.pcap          # identify a capture
tls-fingerprint analyze pcaps/curl.pcap --json    # the same output as JSON
tls-fingerprint db list                            # list known fingerprints
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
```

`analyze` prints the flow endpoints, the SNI, the negotiated TLS version, then
each fingerprint with a database verdict:

```
JA3 (client)
--------------------------------
String: 771,4867-4866-4865-52393-...
Hash:   375c6162a492dfbf2795909110ce8424

Client Identification
--------------------------------
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)
```

A verdict is `known` when one database entry carries that hash, `possible`
when several entries with different names share it, and `unknown` when it is
not on file. `possible` is a real outcome, not a failure: two programs built
on the same library with the same settings do produce the same JA3.

`docs/IMPLEMENTATION.md` walks through the full demonstration command by
command.

## Results

Five programs, one server, five different JA3 hashes:

| Client | TLS library | JA3 | JA4 |
|---|---|---|---|
| curl 8.7.1 | SecureTransport over LibreSSL | `375c6162a492dfbf2795909110ce8424` | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | `0b85eb0d4981e69064e40753e4f0ac5f` | `t13d301100_1d37bd780c83_8e6e362c5eac` |
| Python 3.14.6 `ssl` | OpenSSL 3.6.2, same build | `f21f8e6cf70d5980ecfe9fa2e0ef401c` | `t13d171100_ab0a1bf427ad_8e6e362c5eac` |
| Chrome 151 headless | BoringSSL | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` |
| hand-built ClientHello | none, raw socket | `c53113116bb0508ad66a61bbbe6fedc9` | `t12d040400_4fe0dd5c3cea_1d42f82b3e0b` |

Rows two and three link against the same OpenSSL build and still differ,
because `ssl.create_default_context()` offers a shorter and differently
ordered cipher list than the `openssl` command line tool.

Running the same headless Chrome twice gave two different JA3 hashes. Chrome
has shuffled its extension order on every connection since version 110, and
JA3 hashes extensions in send order. JA4 sorts them first, and its cipher
segment came out identical across both runs. Its extension count still moved
from 16 to 17, because the second run offered one extra extension. See
section 7.2 of `docs/PROJECT_REPORT.md`.

`data/fingerprint_db.json` holds 15 entries for those 5 clients. Fourteen of
the values are distinct: two clients received the same JA3S from the same
server, which is expected, since a ServerHello reflects what the client
offered.

## Captures

The files in `pcaps/` were not taken from a network interface. Live capture
needs root, which was unavailable in the environment this was built in, so
`capture_proxy.py` was used instead: the client connects to a local relay,
the relay forwards every byte to the real server untouched while keeping a
copy, and `pcap_write.py` writes that copy out as a `.pcap`.

The TLS bytes are what the client sent and the server returned, and
certificate validation succeeded on every capture. The packet framing around
them is synthetic, so each file holds one packet per direction instead of a
full TCP conversation. Section 10 of `docs/PROJECT_REPORT.md` has the detail.

The analysis code has no such limitation. It reads ordinary captures,
including segmented handshakes, out-of-order delivery and concurrent flows.

## Checks

```bash
pytest
```

61 tests. JA3 and JA3S are checked against values worked out by hand from the
RFC layout. JA4 is checked against the examples published in the FoxIO
specification. The rest cover parser edge cases, database lookup, the
identity-claim comparison, an end-to-end run, and a check that every database
entry still reproduces from its source capture.

Wireshark implements JA3 and JA4 independently, so it can be used as a second
opinion:

```bash
tshark -r pcaps/curl.pcap -Y "tls.handshake.type==1" \
  -T fields -e tls.handshake.ja3 -e tls.handshake.ja4
```

The values agree with this tool on every capture in `pcaps/`.

## Layout

```
src/tls_fingerprint/
  parser.py             raw TLS bytes to ClientHello / ServerHello fields
  ja3.py, ja3s.py       JA3 and JA3S
  ja4.py                JA4
  database.py           reference database and lookup
  analyzer.py           per-flow pipeline
  report.py, cli.py     command line interface and output
  spoofing_detector.py  claimed identity against measured fingerprint
  capture_proxy.py      relay used to produce the captures
  pcap_write.py         writes captured bytes out as a .pcap

data/       the reference database
pcaps/      every capture used for a result here
experiments/ the client scripts that produced them
tests/      61 tests
screenshots/ terminal output for each demonstration step
docs/
  BACKGROUND.md       TLS handshakes and how JA3, JA3S and JA4 are built
  IMPLEMENTATION.md   step by step demonstration
  PROJECT_REPORT.md   full write-up
```

## References

JA3 and JA3S: https://github.com/salesforce/ja3

JA4: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

RFC 8446 (TLS 1.3), RFC 8701 (GREASE)
