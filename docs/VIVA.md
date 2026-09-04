# Viva Questions and Short Answers

Answers are written to be *spoken*. Keep them this short, let the
examiner ask follow-ups.

## Networking & TLS basics

**1. IP address vs. port?**
IP identifies the device; port identifies which service on it. Street
address vs. apartment number.

**2. Why does TCP need sequence numbers, and do we parse the 3-way handshake?**
IP can drop/reorder/duplicate packets; sequence numbers let TCP
reassemble one clean ordered stream. We don't parse the SYN/SYN-ACK/ACK
handshake itself — we only read payload bytes after it.

**3. Why does this project need TCP stream reassembly at all?**
A single TLS handshake message can be split across multiple TCP segments
if it's larger than one MTU. `reassemble_tcp_stream()` reorders by
sequence number before any TLS parsing happens.

**4. What does TLS add on top of TCP, and are the first two messages encrypted?**
Encryption, integrity, and server authentication via certificates.
ClientHello and ServerHello — the first two messages — are sent
**unencrypted**, by design. That's the entire reason passive TLS
fingerprinting is possible without decrypting anything.

**5. What's in a ClientHello / ServerHello?**
ClientHello: TLS version, an ordered list of cipher suites, and a list
of extensions. ServerHello: version + the *one* cipher suite the server
picked (not a list) + its own extensions.

**6. Why does the ClientHello version field sometimes not match the real negotiated version?**
TLS 1.3 keeps the legacy field at `0x0303` for middlebox compatibility;
the real version is in the `supported_versions` extension instead. We
check that extension to report the true version.

## Passive capture

**7. Why can't you just run `tcpdump` freely on macOS?**
Raw packet capture needs root (BPF device access), which needs an
interactive `sudo` password we don't have in this environment.

**8. How did you generate real captures without root?**
A small TCP relay (`capture_proxy.py`) that a client connects through
instead of the real server. It forwards every byte unmodified — TLS and
cert validation stay fully real — while logging what it forwards, then
builds a `.pcap` from those real bytes.

**9. Is a relay-produced pcap "fake"?**
No — the TLS bytes are exactly what the real client sent and server
replied. Only the link-layer framing (Ethernet/IP/TCP headers) is
synthetic, and that's documented, never hidden.

## JA3 / JA3S

**10. What is JA3, in one sentence?**
An MD5 hash of `SSLVersion,Cipher,SSLExtension,EllipticCurve,PointFormat`
built from a ClientHello, fields joined in the order the client sent them.

**11. Does JA3 sort the cipher/extension lists?**
No — it preserves send order. Order is part of the fingerprint (and is
exactly what makes it order-*sensitive*, see Q17).

**12. What is GREASE and why strip it?**
RFC 8701 reserved placeholder values Chrome (and others) insert on
purpose to stop the ecosystem hard-coding around today's value set. If
not stripped, the same browser would hash differently every connection.

**13. What's JA3S, and why did two of your clients get the same JA3S?**
Same idea for the ServerHello, 3 fields, one cipher not a list. Two of
our clients hit the same server with overlapping enough offers that it
made the identical choice both times — JA3S reflects "server + what it
was offered," not a standalone server identity.

**14. Why did openssl and Python get different JA3 despite the same underlying OpenSSL library?**
`ssl.create_default_context()` curates a shorter, differently-ordered
cipher list than `openssl s_client`'s default. JA3 fingerprints the
*configuration presented*, not just which library is linked.

**15. Can two different programs share the same JA3? How do you handle that?**
Yes, if same library + same config. The database reports this as
`possible` (ambiguous) rather than silently picking one name.

**16. Why MD5, if it's broken?**
JA3 only uses it to shrink a string into a fixed, easy-to-compare token —
no security property is being relied on, just a compact identifier.

## Limitations & security use

**17. What's the extension-order-randomization issue with modern Chrome?**
Chrome shuffles ClientHello extension order per connection specifically
to weaken JA3. We reproduced this live: the same real Chrome install
gave two different JA3 hashes across two runs.

**18. If the same tool gets a different JA3 after an update, is that a bug?**
No — expected. A JA3 reflects an exact library/config snapshot; the
database records the OS/date measured so drift is visible, not hidden.

**19. Real security use case for JA3?**
Malware C2 detection — unusual/hand-rolled TLS stacks stand out even
though a firewall can't read the encrypted traffic itself.

**20. Can JA3 alone prove a connection is malicious?**
No — a hint to combine with other signals, never proof by itself.

**21. How would an attacker evade JA3-based detection?**
Copy a popular browser's exact cipher/extension list, since a client
fully controls every byte it sends.

## Implementation

**22. Why parse ClientHello/ServerHello bytes by hand instead of Scapy's TLS layer?**
Keeps every byte offset auditable against the RFC directly — the same
approach the original Salesforce ja3.py takes.

**23. How is JA3 correctness actually tested?**
Unit tests hand-build ClientHello bytes, independently derive the
expected JA3 string from the RFC layout by hand, and assert the code
matches — not compared against itself, against a self-derived truth.

## JA4 (implemented on top of the base project)

**24. Why implement JA4?**
We hit a real JA3 weakness ourselves (Q17). JA4 sorts the cipher and
extension lists before hashing, so pure reordering can't change the hash.

**25. How did you validate the JA4 implementation?**
Fetched the official FoxIO spec and used its own published worked
examples as test vectors — e.g. asserting a specific cipher list hashes
to exactly `8daaf6152771`, the literal spec value. Also reproduced the
spec's full end-to-end example string exactly. External ground truth,
not self-referential.

**26. Did JA4 actually fix the instability you found?**
Partially, honestly: the cipher-hash segment stayed identical across
both real Chrome runs (the fix working). The extension-count segment
still changed, because Chrome genuinely sent one extra extension that
run — a real difference, which JA4 correctly reports instead of hiding.

## Bot/spoofing detection (implemented on top of the base project)

**27. What real-world scenario does this demonstrate?**
A client can freely lie about its identity via `User-Agent` (just a
string) but can't as easily fake the TLS handshake its real library
produced. Comparing the claim to the measured fingerprint catches the lie.

**28. Why does `check-spoofing` take the claimed identity as an argument instead of reading it from traffic?**
The User-Agent is inside the encrypted HTTP request, and this project
never decrypts anything. In a real deployment, a reverse proxy/WAF is
the one vantage point that legitimately has both signals together
(pre- and post-decryption) — we mirror that by taking the claim as input.

**29. Does firing many requests help an attacker evade detection?**
No, tested directly: 5 separate live connections, each with its own real
handshake, were flagged 5/5. The fingerprint is evidence about one
connection, not something that dilutes with volume.

**30. What would you add with more time?**
JA4S/JA4H, JARM (active server fingerprinting), a larger cross-platform
reference database, and (Linux-only) eBPF/XDP capture — out of scope here.
