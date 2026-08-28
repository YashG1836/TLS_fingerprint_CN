# Study Guide: Networks, TLS, and TLS Fingerprinting from Zero

This guide assumes you know very little Computer Networks. Every topic gets:
a plain-English definition, an analogy, a tiny concrete example, and a note
on exactly where it shows up in this project's code. Read it top to bottom
once, then use it as a reference while you read `src/tls_fingerprint/`.

---

## 1. Networks, in one paragraph

A computer network is just computers that can send each other bytes.
The internet is a network of networks. To send bytes usefully, everyone
agrees on layered rules ("protocols") for *how* to address a computer,
*how* to keep a conversation reliable, and *how* to keep it private. This
project touches three layers: **IP** (addressing), **TCP** (reliable
delivery), and **TLS** (privacy/authentication) — with an application
(HTTP) riding on top, though we never actually need to look inside HTTP.

## 2. IP addresses

**Definition:** A number that identifies a device on a network, e.g.
`93.184.216.34` (IPv4) or `2606:2800:21f::1` (IPv6).

**Analogy:** A street address. It tells the postal system *where* to
deliver a letter, not *who* it's for or *what's* inside.

**Example:** When you visit `example.com`, your computer first resolves
that name to an IP address (DNS), then sends packets to that address.

**In this project:** every packet Scapy reads out of a pcap has a source
and destination IP — see `IP.src` / `IP.dst` in
[`src/tls_fingerprint/analyzer.py`](../src/tls_fingerprint/analyzer.py).
The CLI prints these under "Source" / "Destination".

## 3. Ports

**Definition:** A 16-bit number (0–65535) that identifies *which
application* on a device a packet is for. Port 443 is the well-known port
for HTTPS.

**Analogy:** If the IP address is the street address, the port is the
apartment number. One building (IP), many apartments (ports/services).

**Example:** `93.184.216.34:443` means "the HTTPS service on that host."

**In this project:** flows are grouped by the 4-tuple
`(src_ip, src_port, dst_ip, dst_port)` in
`analyzer._group_into_flows`. In our captures the client's port is a
random high number ("ephemeral port") and the server's is 443.

## 4. TCP (Transmission Control Protocol)

**Definition:** A protocol that turns "send some bytes to that IP:port"
into a reliable, ordered, two-way byte stream — even though the underlying
network (IP) only promises to try, and might drop, duplicate, or reorder
packets.

**Analogy:** Sending a novel by mailing individual numbered pages, where
the reader waits for missing pages and reassembles them in order before
reading — instead of shouting the whole novel at once and hoping.

**Example:** every TCP segment carries a **sequence number**. If segment
3 arrives before segment 2, the receiver still puts them back in order
before handing the data to the application.

**In this project:** this is *exactly* what `reassemble_tcp_stream()` in
[`parser.py`](../src/tls_fingerprint/parser.py) does — it takes
`(seq, payload)` pairs pulled out of a pcap and reassembles them into one
ordered byte stream, because a single TLS handshake message can be split
across more than one TCP segment.

## 5. The TCP three-way handshake

**Definition:** Before any data flows, TCP does a 3-packet setup:
`SYN` → `SYN-ACK` → `ACK`.

**Analogy:** "Can you hear me?" / "Yes, can you hear me?" / "Yes." — both
sides confirm they can send *and* receive before the real conversation
starts.

**In this project:** we don't need to parse this handshake at all — we
only care about the *payload* bytes of the segments that come after it
(which is where the TLS ClientHello lives). It's mentioned here because
if you open a pcap in Wireshark you'll see it before every flow, and it's
good to recognize it and know it's *not* what we're fingerprinting.

## 6. Sockets

**Definition:** The programming-level handle a program uses to send/receive
over TCP/IP — created by the OS, identified by the local+remote
`(ip, port)` pair.

**Analogy:** A phone handset. The phone *network* is TCP/IP; the handset
you pick up to actually talk is the socket.

**In this project:**
[`experiments/custom_client.py`](../experiments/custom_client.py) uses a
raw Python `socket` directly (no TLS library at all) to hand-send a
ClientHello we built byte-by-byte —
[`capture_proxy.py`](../src/tls_fingerprint/capture_proxy.py) also uses
raw sockets to relay bytes between a real client and a real server without
needing root.

## 7. Packets and packet capture

**Definition:** A packet is one unit of data with headers (who it's from,
who it's to, etc.) plus a payload. Packet capture ("sniffing") means
recording the packets that cross a network interface, usually into a
`.pcap` file.

**Analogy:** A security camera recording envelopes as they pass through a
mail sorting facility — you can read the outside of the envelope (headers)
and, if it's not sealed shut, the contents (payload).

**Why we don't need root for our captures:** normally, capturing packets
off a real network card needs elevated ("promiscuous mode") access, which
on macOS requires `sudo`. Since our experiments generate *our own*
traffic, we instead use a small TCP relay
([`capture_proxy.py`](../src/tls_fingerprint/capture_proxy.py)) that sits
between the client and the real server, logs the bytes it forwards, and
writes them into a real `.pcap` file using synthetic Ethernet/IP/TCP
headers. The TLS bytes inside are 100% real; only the *method* of
capturing them (a relay instead of a NIC tap) differs from classic
`tcpdump`. See `docs/SETUP_MAC.md` for the `sudo tcpdump` alternative.

**In this project:** `scapy.rdpcap()` reads a `.pcap` file into a list of
packet objects in [`analyzer.py`](../src/tls_fingerprint/analyzer.py).

## 8. TLS (Transport Layer Security)

**Definition:** The protocol that adds encryption, integrity, and server
(and optionally client) authentication on top of a TCP connection. "HTTPS"
is just "HTTP running inside TLS."

**Analogy:** TCP gets your letter reliably to the right apartment; TLS is
the sealed, tamper-evident envelope with a wax seal you can verify — so
even the mail carrier can't read or silently alter the contents.

**In this project:** everything after the TCP handshake, up until actual
encrypted application data starts, is TLS **handshake** messages — and
the first two of those (ClientHello, ServerHello) are sent *in the
clear* (unencrypted), which is exactly what makes JA3/JA3S possible from
passive observation.

## 9. Certificates

**Definition:** A digitally-signed document binding a public key to an
identity (e.g. "this key belongs to example.com"), signed by a Certificate
Authority (CA) the client already trusts.

**Analogy:** A notarized ID card. You trust it not because you know the
person, but because you trust the notary (CA) who checked their identity
and signed off.

**In this project:** we never validate or even parse certificates — that
job is fully handled by curl/OpenSSL/Chrome/Python themselves during the
real handshakes we relay. We only look at the ClientHello/ServerHello.
(`openssl s_client -brief`'s "Verification: OK" line in
`docs/EXPERIMENTS.md` is that real validation happening.)

## 10. The TLS handshake (simplified, TLS 1.2/1.3)

**Definition:** The message exchange that sets up an encrypted channel:

```
Client                                   Server
  |------ ClientHello --------------------->|
  |<----- ServerHello ------------------------|
  |<----- Certificate, ... (TLS 1.2 also) ---|
  |------ (key exchange material) ---------->|
  |<===== both sides now encrypt =========>|
```

**Analogy:** "Here's what ciphers/settings I support, pick one" (Client
Hello) → "OK, here's the one I picked, here's my proof of identity"
(ServerHello + Certificate) → both sides derive a shared secret key and
switch to encrypted communication.

**In this project:** this whole handshake is the thing we're passively
observing. We stop caring the moment we've extracted the ClientHello and
ServerHello — everything after that is encrypted and irrelevant to
JA3/JA3S.

## 11. ClientHello

**Definition:** The very first TLS message, sent unencrypted by the
client. It lists: the TLS version it's willing to speak, a list of cipher
suites it supports (in its preferred order), and a list of **extensions**
(optional features/parameters, also in order).

**Analogy:** Walking into a shop and announcing, in a specific order,
every payment method you accept, every language you can speak, and every
special request you might make — *before* the shop says anything back.
Two different people (a tourist vs. a local) will list these in
noticeably different ways — that's the whole basis of fingerprinting.

**In this project:** parsed byte-by-byte in
`parser.parse_client_hello_body()`. Try reading that function next to
this list — every field is commented with its exact byte layout.

## 12. ServerHello

**Definition:** The server's unencrypted reply: the TLS version and
*single* cipher suite it chose (from the client's list), plus its own
extensions.

**Analogy:** The shop clerk replying "I'll take card, and here's the
receipt language I'll use" — one specific choice from what you offered.

**In this project:** parsed in `parser.parse_server_hello_body()`. Note
it has *one* cipher suite (not a list) — a server picks exactly one.

## 13. TLS extensions

**Definition:** Optional `(type, length, data)` blocks in Client/ServerHello
that carry extra negotiation info. Examples: `server_name` (SNI — which
hostname the client wants, needed because one IP can host many HTTPS
sites), `supported_groups` (elliptic curves for key exchange),
`ec_point_formats`, `supported_versions`, `key_share`, `ALPN` (which
application protocol, e.g. HTTP/2, to use).

**Analogy:** The fine print / special-requests section of an order form —
optional, but *which* boxes you check, and in *what order*, is
distinctive.

**In this project:** `parser.Extension` + `_parse_extensions()`.
`supported_groups` (type `10`) and `ec_point_formats` (type `11`) are
specifically pulled out because JA3 needs them by name.

## 14. Cipher suites

**Definition:** A single number that stands for a whole bundle of
algorithm choices: key exchange + authentication + bulk encryption + hash.
E.g. `0xC02B` = `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.

**Analogy:** A restaurant "combo #12" — one number that means "this exact
set of dishes," instead of listing every dish separately.

**In this project:** `ClientHelloInfo.cipher_suites` / list of numbers;
`ServerHelloInfo.cipher_suite` / a single number. These lists (and their
*order*) are the single biggest ingredient of a JA3 fingerprint.

## 15. Passive monitoring

**Definition:** Observing traffic without participating in it or altering
it — as opposed to a proxy/firewall that actively intercepts and can
modify traffic. Passive TLS fingerprinting means: watch the unencrypted
ClientHello/ServerHello go by, don't touch anything, don't need any keys.

**In this project:** the whole tool is passive with respect to the
*production* traffic model (`analyzer.py` only ever *reads* a pcap).
Our experiment relay is a slight wrinkle — it forwards bytes to produce
a pcap without root — but it never decrypts or modifies the handshake
itself. See the limitations note in `docs/PROJECT_REPORT.md`.

## 16. TLS fingerprinting

**Definition:** Deriving a short, comparable identifier from the
*structure* of a ClientHello or ServerHello (not its content/meaning) —
so that connections from the same client software tend to produce the
same identifier, even though TLS itself doesn't include a "client name"
field anywhere.

**Why it works at all:** different TLS libraries (SecureTransport,
OpenSSL, BoringSSL, a hand-rolled implementation, ...) each have their own
hard-coded defaults for which ciphers to offer, in which order, which
extensions to include, and in which order. Those defaults are a kind of
unintentional signature.

## 17. JA3

**Definition:** A specific, published algorithm (Salesforce, 2017) for
turning a ClientHello into one hash. Build the string:

```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```

...where each field is a `-`-joined **decimal** list, taken **in the
order the client sent them**, then MD5-hash the whole string.

**Example (real, from this project's own curl capture):**
```
JA3 string: 771,4867-4866-4865-52393-...-255,43-51-0-11-10-13-16,29-23-24-25,0
JA3 hash:   375c6162a492dfbf2795909110ce8424
```
`771` is TLS 1.2's version number in decimal (`0x0303`) — used here as a
literal field value, not a semantic "negotiated version" (see §20 GREASE
and the TLS-1.3-legacy-version note in `report.py`).

**In this project:** `ja3.py`, function `build_ja3_string()` +
`compute_ja3()`. `tests/test_ja3.py` hand-derives the expected string from
scratch and checks the code against it.

## 18. JA3S

**Definition:** The same idea applied to a **ServerHello**:
```
SSLVersion,Cipher,SSLExtension
```
No curve/point-format fields, because a ServerHello doesn't list a set of
supported curves — the server already picked one thing.

**Important nuance:** JA3S depends on what the *client* offered (the
server can only choose from what it was given), so the same server can
produce *different* JA3S values against different clients. In this
project's own data, `openssl s_client` and our Python stdlib client
produced **the same** JA3S hash against the same server — because their
ClientHellos overlapped enough that Cloudflare made the same choice both
times. JA3S is best read as "this server, responding to this kind of
client" — not a context-free server identity. See `ja3s.py`'s docstring
and `docs/PROJECT_REPORT.md`'s limitations section.

## 19. Security applications

Why anyone cares about any of this:

- **Malware/C2 detection:** malware often uses a specific, unusual TLS
  library or hand-rolled stack. Its JA3 can stand out from normal
  browser/OS traffic even though the connection is fully encrypted and a
  firewall can't see the HTTP request inside it.
- **Anomaly detection:** "this JA3 has never been seen from this host
  before" is a useful signal even without knowing exactly *what* software
  produced it.
- **Inventory / policy:** identifying which library versions are actually
  talking on your network (e.g. finding legacy clients using outdated TLS
  stacks) without needing endpoint agents.
- **Pairing JA3+JA3S:** a specific malware family talking to its specific
  C2 server can sometimes be identified by the *combination* of JA3 (its
  client) and JA3S (its server's response to that specific client) —
  more specific than either alone.

## 20. Limitations, randomization, and evasion — read this carefully

TLS fingerprinting is a **hint**, never proof. Concretely:

- **GREASE (RFC 8701).** Chrome (and others following its lead)
  deliberately inserts random "meaningless" cipher/extension/group values
  from a reserved set on *every* connection, specifically to stop the
  ecosystem from calcifying around today's exact value set. If JA3 didn't
  strip these out, the *same* browser would get a *different* JA3 hash on
  every single connection. `ja3.GREASE_VALUES` lists the 16 reserved
  values (`0x0A0A, 0x1A1A, ..., 0xFAFA`); `is_grease()` filters them.
- **Extension order shuffling.** Modern Chrome also randomizes the
  *order* of ClientHello extensions per-connection specifically to weaken
  JA3 as a tracking mechanism. Standard JA3 (as implemented here) is
  order-*sensitive*, so this can make the *same* real Chrome install
  produce *different* JA3 hashes across connections. This is a genuine,
  documented weakness of order-sensitive JA3 — some tools respond by
  sorting extensions before hashing (a JA3-variant, not standard JA3);
  we do not do that here, to stay faithful to the published spec, but you
  should be able to explain this trade-off in a viva.
- **Identical hash ≠ identical software.** Two different programs using
  the same TLS library version with the same configuration will produce
  the *same* JA3 — the hash identifies "TLS stack + configuration," not a
  specific named application. Our `database.py` explicitly models this:
  a hash matching more than one distinct name in the DB is reported as
  `possible` (ambiguous), never silently collapsed to one guess.
  See `MatchResult.status` and `report._match_line()`.
- **Version/config drift.** The same tool can produce a *different* JA3
  after a library upgrade, an OS update, or a config change. A reference
  database entry is a snapshot, not a permanent truth — ours records
  the exact OS version and date it was measured on
  (`FingerprintEntry.source`).
- **Deliberate evasion.** Since a JA3 hash is entirely a function of bytes
  the *client* controls, any client — including malware — can trivially
  mimic a popular browser's JA3 by copying its cipher/extension list, or
  can rotate its own fingerprint per connection. JA3 raises the cost of
  blending in a little; it does not make evasion impossible.
- **No confidentiality is broken.** Nothing here decrypts anything.
  We only ever read the unencrypted handshake preamble that TLS always
  sends in the clear by design.

## 21. The whole project, end to end

```
.pcap file (real packets, real handshake bytes)
        |
        v  scapy.rdpcap()                              [analyzer.py]
list of packets
        |
        v  group by (ip,port) 4-tuple, per direction    [analyzer.py]
TCP segments per flow
        |
        v  reassemble_tcp_stream()                      [parser.py]
one ordered byte stream per direction
        |
        v  walk TLS records, find ClientHello/          [parser.py]
           ServerHello handshake messages
ClientHelloInfo / ServerHelloInfo (typed fields)
        |
        v  build_ja3_string() + md5()                   [ja3.py]
           build_ja3s_string() + md5()                  [ja3s.py]
JA3 hash (client) / JA3S hash (server)
        |
        v  FingerprintDatabase.lookup()                 [database.py]
known / possible / unknown match, with names+metadata
        |
        v  format_report()                               [report.py]
human-readable CLI output
```

Every arrow above is a real, separately-unit-tested function — there's no
step in this pipeline that isn't directly inspectable in the code.

## What I should remember

- IP = which machine, port = which service on it, TCP = reliable ordered
  bytes, TLS = encryption + identity on top of TCP.
- ClientHello and ServerHello are sent **unencrypted** — that's the only
  reason any of this is possible.
- JA3 = hash of `(version, ciphers, extensions, curves, point formats)`
  from the ClientHello, **in the order sent**, GREASE stripped.
- JA3S = hash of `(version, cipher, extensions)` from the ServerHello.
  Depends on both the server *and* what the client offered.
- A JA3 match is a strong **hint** about the client library/config, not
  proof of a specific named application, and not proof of intent.
- GREASE and extension-order randomization exist specifically to make
  fingerprinting harder — this is an active, ongoing arms race, not a
  solved problem.
