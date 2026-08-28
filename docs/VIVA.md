# Viva Questions and Short Answers

Answers are written to be *spoken*, not read — keep them this short in the
actual viva, then let the examiner ask follow-ups.

## CN Basics

**1. What's the difference between an IP address and a port?**
IP address identifies the device; port identifies which application/service
on that device. Same idea as street address vs. apartment number.

**2. Why does TCP need sequence numbers?**
Because IP can deliver packets out of order, duplicated, or drop them.
Sequence numbers let the receiver reorder and detect gaps, so the
application sees one clean, ordered byte stream.

**3. What's in the TCP three-way handshake, and do we parse it?**
SYN, SYN-ACK, ACK — both sides confirm two-way connectivity before data
flows. We don't parse it; we only read the payload of segments that come
after it.

**4. What is a socket?**
The OS-level handle a program uses to send/receive over a TCP/IP
connection, identified by local+remote IP:port.

**5. Why do we need TCP stream reassembly at all — isn't one packet one
message?**
No — a single TLS handshake message can be split across multiple TCP
segments if it's larger than one MTU. We reassemble by sequence number
before trying to parse TLS records.

## TLS Fundamentals

**6. What does TLS add on top of TCP?**
Encryption, integrity, and (usually) server authentication via
certificates. TCP alone is reliable but not private or authenticated.

**7. What is a certificate, in one sentence?**
A signed statement, from a CA the client already trusts, binding a public
key to an identity.

**8. Name the first two messages of a TLS handshake.**
ClientHello (from client), then ServerHello (from server).

**9. Are ClientHello and ServerHello encrypted?**
No — they're sent in the clear. That's the entire reason passive TLS
fingerprinting is possible without decrypting anything.

**10. What's in a ClientHello?**
TLS version, a random value, session ID, an ordered list of cipher
suites, compression methods, and a list of extensions.

**11. What's different about a ServerHello vs. a ClientHello?**
ServerHello has exactly one chosen cipher suite (not a list) and its own
extensions — it's the server's single pick from what the client offered.

**12. What is a cipher suite?**
One number that bundles a whole set of algorithm choices — key exchange,
authentication, bulk cipher, hash — e.g. `0xC02B` =
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.

**13. What's a TLS extension? Give two examples used in this project.**
An optional (type, length, data) block in Client/ServerHello.
`server_name` (SNI — which hostname), `supported_groups` (which elliptic
curves for key exchange).

**14. Why does the ClientHello version field sometimes not match the
actual negotiated version?**
For TLS 1.3, the legacy `version` field is kept at `0x0303` (TLS 1.2) for
middlebox compatibility; the real version is signaled via the
`supported_versions` extension instead. Our `report.py` specifically
checks that extension on the ServerHello side to show the true negotiated
version.

## Passive Capture

**15. What does "passive" monitoring mean here?**
Observing traffic without altering or participating in it — no keys
needed, no modification of what's sent.

**16. Why can't we just `tcpdump` freely on macOS?**
Raw packet capture needs kernel-level BPF device access, which macOS
restricts to root. That needs an interactive `sudo` password.

**17. How did you generate real captures without root, then?**
A small TCP relay (`capture_proxy.py`) that a real client connects
through instead of connecting directly to the real server. It forwards
every byte unmodified (TLS and cert validation stay fully real) while
logging what it forwards, then synthesizes a `.pcap` from those real
bytes.

**18. Is that relay-produced pcap "fake"?**
No — the TLS bytes are exactly what the real client sent and the real
server replied. Only the link-layer framing (Ethernet/IP/TCP headers) is
synthetic; that's documented explicitly, never hidden.

**19. How do you handle a TLS record split across multiple TCP
segments?**
`reassemble_tcp_stream()` reorders segments by sequence number into one
byte stream first; then a separate walker reads TLS records off that
stream using their own length fields, buffering across record boundaries
if a handshake message itself spans more than one record.

## JA3 / JA3S

**20. What is JA3, in one sentence?**
An MD5 hash of a specific ordered string built from five ClientHello
fields: TLS version, cipher suites, extensions, elliptic curves, and EC
point formats.

**21. Exactly which five fields, in order?**
`SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat` —
version is a single number, the rest are `-`-joined decimal lists.

**22. Does JA3 sort the cipher/extension lists?**
No — it preserves the order the client actually sent them in. Order is
part of the fingerprint.

**23. What is GREASE and why does JA3 remove it?**
RFC 8701 reserved values (`0x0A0A, 0x1A1A, ... 0xFAFA`) that Chrome and
others insert randomly into cipher/extension/group lists on purpose, to
stop the ecosystem from hard-coding assumptions about the exact value
set. If JA3 didn't strip them, the same browser would hash differently on
every connection.

**24. What's JA3S, and how is it different from JA3?**
Same idea for the ServerHello: `SSLVersion,Cipher,SSLExtension` — three
fields, no curves/point-formats, and Cipher is one value, not a list,
since a server picks exactly one.

**25. Why did two different clients in your experiments get the same
JA3S hash?**
`openssl s_client` and the Python stdlib client both hit the same
Cloudflare-fronted server, and their ClientHellos overlapped enough that
the server made the identical choice both times. JA3S reflects
"server + what it was offered," not a context-free server identity.

**26. Why did openssl and Python get *different* JA3 despite using the
same underlying OpenSSL 3.6.2 library?**
Because `ssl.create_default_context()` in Python curates its own,
shorter, differently-ordered cipher list than `openssl s_client`'s
default — JA3 fingerprints the *configuration a program presents*, not
just which crypto library is linked.

**27. Can two completely different programs share the same JA3?**
Yes, if they use the same TLS library with the same configuration. JA3
identifies "TLS stack + config," not a unique named application. My
database's `lookup()` reports this as a `possible` (ambiguous) match
rather than silently guessing one name.

**28. Why MD5? Isn't MD5 broken?**
MD5 is broken for cryptographic collision-resistance, but JA3 only uses
it to shrink a long string into a fixed, easy-to-compare/index token —
there's no security property being relied on here, just a compact
identifier. This is exactly what the published JA3 spec does.

## Database & Matching

**29. What three states can a lookup return, and what do they mean?**
`known` (hash matches exactly one name in the DB), `possible` (hash
matches, but more than one distinct name is recorded against it —
ambiguous), `unknown` (no match at all).

**30. Are your database entries invented or measured?**
Measured — every entry comes from `experiments/build_reference_db.py`
computing JA3/JA3S directly from the actual captured pcaps in `pcaps/`,
never hand-typed.

**31. What metadata does each database entry carry, and why?**
Hash, the full fingerprint string, a name, category (client/server), the
library, `source_type` (measured vs. published_reference), the OS/date it
was measured on, the exact command used, and free-text notes — enough to
reproduce or challenge the entry later, and to distinguish something we
personally verified from something we didn't.

## Security Applications & Limitations

**32. What's a real security use case for JA3?**
Detecting malware command-and-control traffic: malware often uses an
unusual or hand-rolled TLS stack, so its JA3 stands out from normal
browser/OS traffic even though the connection itself is fully encrypted
and a firewall can't see the HTTP request inside it.

**33. Can JA3 alone prove a connection is malicious?**
No. It's a hint that narrows down "what kind of client is this," to be
combined with other signals (destination reputation, timing, volume,
JA3S pairing) — never proof by itself.

**34. How would an attacker evade JA3-based detection?**
Copy a popular browser's exact cipher/extension list and order (since a
client fully controls every byte it sends), or rotate the ClientHello
fields per connection.

**35. What's the extension-order-randomization issue with modern Chrome?**
Recent Chrome versions shuffle ClientHello extension order per connection
specifically to weaken JA3 as a tracking/fingerprinting mechanism. Since
standard JA3 is order-sensitive, this can make the *same* real Chrome
install produce different JA3 hashes across connections — a known,
active weakness, not something this project claims to solve.

**36. If the same tool gets a different JA3 after a software update, is
that a bug in your project?**
No — it's expected. A JA3 hash reflects an exact library version and
configuration snapshot; upgrades legitimately change it. The DB records
the OS version and date an entry was measured, precisely so this drift is
visible rather than silently assumed away.

**37. Does this project decrypt any traffic?**
No. Only the ClientHello/ServerHello are read, and both are sent
unencrypted by design — nothing here breaks TLS's confidentiality
guarantees.

## Project / Implementation

**38. Why parse ClientHello/ServerHello bytes by hand instead of using
Scapy's TLS layer?**
To keep every byte offset auditable against the RFC directly (and
explainable in this viva), the same approach the original Salesforce JA3
implementation takes, rather than depending on a full TLS stack just to
read a handshake header.

**39. How is JA3 correctness actually tested?**
Unit tests hand-build ClientHello bytes field-by-field, independently
derive the expected JA3 string by hand from the RFC layout, and assert
the code produces exactly that string — not compared against some
externally-trusted "known" hash, but against a self-derived ground truth.

**40. What would you add if you had more time (stretch goals)?**
JA4/JA4S (a newer, more detail-rich fingerprint scheme), live capture UX
polish, a larger curated reference database across more tools/OS
versions, and (Linux-only) eBPF/XDP-based high-performance capture — all
explicitly out of scope for this MVP.
