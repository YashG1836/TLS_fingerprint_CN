# Study Guide: Networks, TLS, and TLS Fingerprinting from Zero

Short definitions + tiny examples, in the order you need them. Read once,
then use as reference.

## Networking basics

- **IP address** — which device. `93.184.216.34` is like a street address.
- **Port** — which service on that device. `443` is HTTPS. IP = building,
  port = apartment number.
- **TCP** — turns "send bytes to that IP:port" into a reliable, ordered
  byte stream, even though the network underneath can drop/reorder
  packets. Each chunk carries a sequence number so the receiver can put
  things back in order — this project's `reassemble_tcp_stream()` does
  exactly that.
- **TCP handshake** — `SYN → SYN-ACK → ACK`, a 3-packet "can you hear me"
  before any real data flows. We don't need to parse it — we only read
  the payload bytes that come after it.
- **Socket** — the programming handle a program uses to send/receive over
  TCP/IP. Like a phone handset picked up on the TCP/IP network.
- **Packet / packet capture** — a packet is one unit of data (headers +
  payload). A `.pcap` file is a recording of packets, like a security
  camera for network traffic.

## TLS basics

- **TLS** — adds encryption + identity verification on top of TCP.
  "HTTPS" = "HTTP inside TLS."
- **Certificate** — a signed statement binding a public key to an
  identity (e.g. "this key belongs to example.com"), signed by a
  Certificate Authority the client already trusts. This project never
  touches certificates — curl/OpenSSL/Chrome do that validation
  themselves during the real handshakes we relay.
- **The TLS handshake** (simplified):
  ```
  Client --- ClientHello ------------------> Server
  Client <-- ServerHello, Certificate ------ Server
  Client --- (key exchange) ---------------> Server
  Client <== both sides now encrypt =======> Server
  ```
  We stop caring the moment we've read the ClientHello/ServerHello —
  everything after is encrypted.
- **ClientHello** — the client's first, *unencrypted* message: TLS
  version, its ordered list of cipher suites, and a list of extensions.
  Different programs write this differently — that's the whole basis of
  fingerprinting. Parsed field-by-field in `parser.parse_client_hello_body()`.
- **ServerHello** — the server's unencrypted reply: version + the *one*
  cipher suite it picked, plus its own extensions.
- **Extensions** — optional `(type, length, data)` blocks in a hello that
  carry extra info: `server_name` (SNI, which hostname), `supported_groups`
  (elliptic curves), `ec_point_formats`, `ALPN` (HTTP/2 vs HTTP/1.1), etc.
- **Cipher suite** — one number standing for a whole bundle of algorithm
  choices, e.g. `0xC02B` = `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. The
  list (and its order) is the biggest ingredient of a JA3 fingerprint.

## TLS fingerprinting

**Why it's possible at all:** ClientHello/ServerHello are sent
*unencrypted*, by design. Different TLS libraries (SecureTransport,
OpenSSL, BoringSSL, a hand-rolled one...) each hard-code their own
defaults for which ciphers/extensions to send and in what order. Those
defaults are an unintentional signature — and passively watching them go
by needs no keys, no decryption, no interception.

### JA3

Published by Salesforce (2017). Build this string from a ClientHello:
```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```
each field a `-`-joined decimal list, **in the order the client sent
them**, then MD5-hash it. Real example (our own curl capture):
```
771,4867-4866-4865-...,43-51-0-11-10-13-16,29-23-24-25,0
-> 375c6162a492dfbf2795909110ce8424
```

### JA3S

Same idea for the **ServerHello**: `SSLVersion,Cipher,SSLExtension` (no
curve fields — the server already picked one thing, it doesn't offer a
list). Because it depends on what the client offered, the same server can
give *different* JA3S to different clients — in our own data, two
different clients got the *same* JA3S from the same server, since their
offers overlapped enough.

### JA4 (newer, fixes JA3's biggest weakness)

JA3 is order-*sensitive*. Modern Chrome shuffles its own ClientHello
extension order per connection specifically to defeat this — we caught
the *same real Chrome* giving two different JA3 hashes across two runs
(see `docs/IMPLEMENTATION.md`). JA4 sorts the cipher/extension lists
before hashing, so pure reordering no longer changes the fingerprint —
verified on that same real data.

## Security applications

- **Malware/C2 detection** — malware often uses an unusual TLS stack;
  its JA3 stands out even though a firewall can't read the encrypted
  traffic itself.
- **Bot/spoofing detection** — a program can lie about its identity via
  an HTTP header (`User-Agent`), but not as easily fake the TLS
  handshake its real library produces. Comparing the claim against the
  measured fingerprint catches the lie — this project implements exactly
  this (`spoofing_detector.py`).
- **Anomaly detection** — "never seen this JA3 before" is a useful signal
  even without knowing what produced it.

## Limitations — read this before trusting a match

- **GREASE (RFC 8701).** Chrome inserts random reserved placeholder
  values into cipher/extension lists on purpose, to stop the ecosystem
  hard-coding around today's exact value set. If not stripped, the same
  browser would hash differently every connection. Both JA3 and JA4
  strip it.
- **Extension-order randomization** actively fights JA3 (see JA4 above).
- **Identical hash ≠ identical software.** Two programs with the same
  library+config get the same JA3. This project's database reports that
  honestly as `possible` (ambiguous), never a silent guess.
- **Version drift.** The same tool can shift to a different JA3 after a
  library/OS update — a database entry is a snapshot, not a permanent
  truth.
- **Evadable.** A JA3 is entirely client-controlled bytes — anyone can
  copy another program's exact signature.
- **No confidentiality is broken.** Only the unencrypted handshake
  preamble is ever read here.

## What to remember

- IP = which machine, port = which service, TCP = reliable ordered
  bytes, TLS = encryption + identity on top of TCP.
- ClientHello/ServerHello are unencrypted — that's the only reason any
  of this works.
- JA3 = hash of `(version, ciphers, extensions, curves, point formats)`,
  in the order sent, GREASE stripped. JA3S = the server's mirror.
  JA4 = the same idea, sorted first, so reordering can't change it.
- A match is a hint about the client's library/config, never proof of a
  specific named app or intent.
