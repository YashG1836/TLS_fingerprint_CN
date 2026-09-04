# Background: TLS handshakes and how the fingerprints are built

This explains the parts of TCP and TLS the tool depends on, and how JA3, JA3S
and JA4 are constructed. Examples are taken from the captures in `pcaps/`.

## TCP, and why reassembly is needed

IP moves packets between hosts and is allowed to drop, duplicate and reorder
them. TCP adds sequence numbers so the receiver can put the bytes back in
order and ask for anything missing. What an application sends is a stream of
bytes; what crosses the network is packets, and the split between them is
decided by the path, not by the application.

A ClientHello from Chrome is around two kilobytes. It usually fits in one
segment, but it does not have to, and a TLS handshake message is allowed to
span several TLS records which in turn span several packets. Anything reading
handshakes from a capture has to reassemble the stream first. Parsing packet
by packet works until it meets a large hello, then silently fails.

`parser.py` reassembles by sorting each direction's payloads on sequence
number. It also buffers handshake record payloads until a full message is
available, so a hello split across records is still read correctly.

A `.pcap` file is a recording of packets. Reading one needs no privileges.
Recording one from a live interface does, because it needs access to the
kernel packet filter.

## The TLS handshake

TLS provides encryption, integrity and server authentication on top of TCP.
The exchange starts like this:

```
Client  ---- ClientHello ------------------->  Server
Client  <--- ServerHello, Certificate -------  Server
Client  ---- key exchange ------------------>  Server
Client  <=== everything below is encrypted ==> Server
```

The first two messages cannot be encrypted, because they are how the two
sides agree on what to encrypt with. They are the only part this project
reads.

### What a ClientHello contains

* A legacy version field, two bytes.
* A 32 byte random value.
* A session ID, usually empty in TLS 1.3.
* An ordered list of cipher suites, two bytes each, in the client's order of
  preference.
* A list of compression methods, which in practice is always the single value
  `null`.
* A list of extensions, each one a type, a length and a body.

The extensions matter as much as the ciphers. The ones that show up in
fingerprints:

| Type | Name | Carries |
|---|---|---|
| `0x0000` | `server_name` | the hostname being requested (SNI) |
| `0x000a` | `supported_groups` | elliptic curve groups the client accepts |
| `0x000b` | `ec_point_formats` | point encodings the client accepts |
| `0x000d` | `signature_algorithms` | signature schemes the client accepts |
| `0x0010` | `application_layer_protocol_negotiation` | ALPN, for example `h2` |
| `0x002b` | `supported_versions` | the real TLS version list, in TLS 1.3 |

### What a ServerHello contains

The same shape, with two differences: the server names one cipher suite
rather than a list, and it picks a single compression method rather than
offering several. It carries its own extensions.

### The version field lies

Under TLS 1.3 the legacy version field in both messages stays at `0x0303`,
which means TLS 1.2. This is deliberate: middleboxes deployed before TLS 1.3
existed drop connections that claim a version they do not recognise, so 1.3
hides the real version in the `supported_versions` extension and leaves the
old field alone.

The tool reads `supported_versions` when it is present, so the version it
reports is the one in use rather than the placeholder. Note that JA3 uses the
legacy field regardless, which is why every JA3 string here starts with `771`,
the decimal form of `0x0303`, even for TLS 1.3 connections.

## Why the handshake identifies the client

The TLS specifications say what a ClientHello may contain. They do not say
what it should contain, or in what order.

So every implementation decides for itself. OpenSSL has a default cipher list.
BoringSSL, which Chrome uses, has a different one. LibreSSL has a third. On
top of that, an application can narrow or reorder the list, add extensions or
leave them out. Two of the clients in this project make the point directly:
`openssl s_client` and Python's `ssl` module are linked against the same
OpenSSL 3.6.2 build, and they fingerprint differently, because
`ssl.create_default_context()` offers a shorter and differently ordered set
than the command line tool's default.

The result is that the opening message of a connection encodes which library
built it, roughly which version, and how the calling program configured it.
None of this is secret and none of it needs decrypting. It is the first thing
on the wire.

## GREASE

RFC 8701 defines sixteen reserved values, `0x0a0a`, `0x1a1a`, `0x2a2a` and so
on up to `0xfafa`. They mean nothing. Clients insert them at random positions
in their cipher list, extension list, supported groups and signature
algorithms, and servers are required to ignore them.

The purpose is to keep the protocol extensible. Before GREASE, servers and
middleboxes accumulated hard-coded assumptions about which values could
appear, and any genuinely new value broke them. Sending random unknown values
on every connection means an implementation that cannot tolerate them fails
immediately and visibly, rather than years later when a real extension is
introduced.

For fingerprinting, GREASE has to be stripped before hashing. Chrome's
ClientHello starts with a GREASE cipher and ends with a GREASE extension, both
different on every connection. Leaving them in would give the same browser a
different hash every time.

Where GREASE is stripped differs between JA3 and JA4, and getting it wrong is
easy. Section 8 of `PROJECT_REPORT.md` describes a case where this project got
it wrong.

## JA3

Published by Salesforce in 2017. It builds one string from five fields of the
ClientHello:

```
SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
```

Values are decimal. Within a field they are joined by `-`, in the order the
client sent them. Fields are joined by `,`. A field with nothing in it is left
empty, so there are always five fields and four commas.

The hand-built client in this repository produces a short one:

```
771,49199-49195-47-53,0-10-11-13,29-23,0
```

Reading it: TLS 1.2 in the version field, four cipher suites, four extensions
(`server_name`, `supported_groups`, `ec_point_formats`, `signature_algorithms`),
two curve groups, one point format.

The JA3 is the MD5 of that string. Here that is
`c53113116bb0508ad66a61bbbe6fedc9`.

MD5 is used to compress a variable-length string into a fixed-length token
that is cheap to compare and index. No security property is being claimed for
it, and its collision weakness is irrelevant, because an attacker who wants to
match a fingerprint copies the ClientHello rather than searching for a
colliding one.

Order is preserved throughout, which is the design decision that JA4 later
reverses.

## JA3S

The same idea on the ServerHello, with three fields:

```
SSLVersion,Cipher,Extensions
```

The cipher is a single value, since a server picks one. There are no curve or
point format fields, because a ServerHello does not carry those lists.

Cloudflare's reply to the curl capture in this project is:

```
771,4867,51-43
```

giving `d75f9129bb5d05492a65ff78e081bcb2`.

A ServerHello is a response. What the server picks depends on what the client
offered, so the same server produces different JA3S values against different
clients, and different servers can produce the same JA3S against the same
client. In this project, `openssl s_client` and Python's `ssl` received an
identical JA3S from the same server. A JA3S describes a client and server pair
and is not a server identity by itself.

## JA4

Published by FoxIO in 2023. It exists because JA3's order sensitivity stopped
working on browsers: Chrome has randomised its ClientHello extension order on
every connection since version 110, specifically to break fingerprints like
JA3, and it succeeded. Section 7.2 of `PROJECT_REPORT.md` shows the same
Chrome install producing two different JA3 hashes minutes apart.

A JA4 has three segments separated by underscores. Chrome's, from
`pcaps/chrome.pcap`:

```
t13d1516h2_8daaf6152771_806a8c22fdea
```

The first segment is readable:

| Characters | Value | Meaning |
|---|---|---|
| 1 | `t` | TCP. `q` is QUIC, `d` is DTLS |
| 2 to 3 | `13` | TLS 1.3, from `supported_versions` when present |
| 4 | `d` | an SNI hostname was sent. `i` means a bare IP |
| 5 to 6 | `15` | fifteen cipher suites, GREASE excluded |
| 7 to 8 | `16` | sixteen extensions, GREASE excluded |
| 9 to 10 | `h2` | first and last character of the first ALPN value |

The extension count includes SNI and ALPN even though the third segment
excludes them from its hash.

The second segment, `8daaf6152771`, is the first twelve hex characters of the
SHA256 of the cipher list. The ciphers are written as four-digit hex, joined
by commas, and sorted numerically before hashing. GREASE is removed.

The third segment, `806a8c22fdea`, is the same truncated SHA256 over the
extension list, sorted, with SNI and ALPN removed since they already appear in
the first segment, followed by an underscore and the signature algorithms in
the order they were sent. The signature algorithms are not sorted, and GREASE
is not removed from them.

Two properties follow from this layout. Sorting means reordering no longer
changes the fingerprint. And because the first segment is readable and the
hashes are split, two JA4 values can be compared component by component, so
when a client's fingerprint changes you can see which part of the handshake
moved rather than only that something did.

## Where this is used, and where it fails

The technique is used for identifying clients behind encrypted traffic:
detecting malware command and control channels, taking inventory of TLS
libraries on a network without touching the endpoints, and bot detection,
where a fingerprint is checked against whatever the client claims to be in its
`User-Agent`.

It fails in specific ways, all of which show up in this project:

Two programs on the same library and configuration share a fingerprint, so a
match narrows the field rather than naming a program.

A fingerprint is entirely client-controlled bytes, so any client can copy
another's. curl-impersonate and uTLS do exactly that.

Chrome's randomisation defeats JA3 outright for browsers, and a real change in
what a client offers moves JA4 too.

Library and operating system updates move fingerprints over time, so a
reference database ages.

None of which makes it useless. It makes it a signal to correlate with others
rather than an identity to act on alone.
