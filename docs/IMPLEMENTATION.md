# Demonstration Guide

Every command here is copy-paste ready, and every output shown was produced by
running it against the captures committed to this repository. Run them in
order for a complete walkthrough.

## Before you start

```bash
source .venv/bin/activate
pytest -q
```

Expect `61 passed`. This establishes that the fingerprint arithmetic is
correct before any capture is involved.

If you have Wireshark installed you can also confirm the implementation
against an independent one at any point:

```bash
tshark -r pcaps/curl.pcap -Y "tls.handshake.type==1" \
  -T fields -e tls.handshake.ja3 -e tls.handshake.ja4
```

The values match what `tls-fingerprint` prints for the same file.

## A warning before running anything that captures

Three commands in this repository write into `pcaps/`: the two
`capture_proxy` invocations below and `experiments/bombard_demo.py`. They
overwrite the committed captures.

Two things go wrong if you run them casually.

Chrome sends a different ClientHello on every connection, so re-capturing
`chrome_live.pcap` produces a new JA3 and every hash quoted in this file and
in the presentation becomes stale. That has already happened once in this
project's history.

The reference database was measured on macOS 26.5 with a specific curl,
OpenSSL, Python and Chrome. Running a capture on a different machine records
that machine's libraries, which have different fingerprints, and the tool
correctly reports them as unknown.

Everything in Parts 1 to 3 works read-only against the committed captures.
Run the capture commands only if you intend to regenerate the database and
the documentation afterwards.

## Part 1: five clients, five fingerprints

The five captures were made by pointing five programs at `example.com`, a
domain IANA reserves for exactly this kind of use, through the relay in
`src/tls_fingerprint/capture_proxy.py`. The relay forwards bytes without
touching them, so the handshake and the certificate check are real. See
"How the captures were produced" in the README for what that does and does
not mean.

List what the tool already knows:

```bash
tls-fingerprint db list
```

Fifteen entries: five clients across JA3, JA3S and JA4. Fourteen of the
fifteen values are distinct, because two clients received an identical JA3S
from the same server. Section 9 of `PROJECT_REPORT.md` explains why that is
expected rather than a defect.

Identify one capture:

```bash
tls-fingerprint analyze pcaps/curl.pcap
```

```
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)
```

Then the other four:

```bash
tls-fingerprint analyze pcaps/openssl.pcap
tls-fingerprint analyze pcaps/python_ssl.pcap
tls-fingerprint analyze pcaps/chrome.pcap
tls-fingerprint analyze pcaps/custom_client.pcap
```

All five JA3 hashes differ:

| Client | TLS library | JA3 |
|---|---|---|
| curl 8.7.1 | SecureTransport over LibreSSL | `375c6162a492...ce8424` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | `0b85eb0d4981...f0ac5f` |
| Python stdlib `ssl` | OpenSSL 3.6.2, the same build | `f21f8e6cf70d...ef401c` |
| Chrome 151 headless | BoringSSL | `81a2542af844...f2a626` |
| hand-built ClientHello | none | `c53113116bb0...6fedc9` |

What this shows: rows two and three are the same OpenSSL build and still
fingerprint differently, because `ssl.create_default_context()` offers a
shorter and differently ordered cipher list than the `openssl` command line
tool. JA3 identifies the configuration a program presents, not simply which
library is linked.

To produce a capture live rather than reading a committed one, on the machine
the database was measured on:

```bash
python -m tls_fingerprint.capture_proxy --mode tcp --target example.com:443 \
    --listen-port 8480 --pcap pcaps/demo_live.pcap \
    -- curl --connect-to example.com:443:127.0.0.1:8480 -sS https://example.com/ -o /dev/null
tls-fingerprint analyze pcaps/demo_live.pcap
```

It reports `375c6162a492dfbf2795909110ce8424`, the same hash as
`pcaps/curl.pcap`. The same curl produces the same fingerprint every time.

## Part 2: where JA3 breaks and what JA4 does about it

`pcaps/chrome.pcap` was one headless Chrome capture. `pcaps/chrome_live.pcap`
is a second capture from the same browser install, taken with this command:

```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
python -m tls_fingerprint.capture_proxy --mode connect --listen-port 8462 \
    --pcap pcaps/chrome_live.pcap --expect-host example.com --accept-timeout 45 \
    -- "$CHROME" --headless=new --disable-gpu --no-first-run \
    --disable-background-networking --disable-search-engine-choice-screen \
    --user-data-dir=/tmp/chrome-live-test --proxy-server=127.0.0.1:8462 \
    --disable-quic --virtual-time-budget=8000 --dump-dom https://example.com/
```

`--expect-host` is needed because headless Chrome opens several background
connections on startup, to a network time service and to Google hosts, before
it reaches `example.com`. The relay rejects those and waits for the right one.
Expect up to a minute of no output while that happens.

Both captures are committed, so the comparison below runs without re-capturing
anything. Re-running the command above would overwrite `chrome_live.pcap` with
a third capture carrying a third JA3, which is exactly the situation the
warning at the top describes.

Compare the two JA3 hashes:

```bash
tls-fingerprint analyze pcaps/chrome.pcap      | grep "^Hash" | head -1
tls-fingerprint analyze pcaps/chrome_live.pcap | grep "^Hash" | head -1
```

```
Hash:   81a2542af8442fcd7802f178d9f2a626
Hash:   a00e551d2f4af85ede1156537ebf095a
```

The same browser install, two runs, two completely different JA3 hashes.
Chrome shuffles the order of its ClientHello extensions on every connection,
and since JA3 hashes those extensions in send order, the hash moves with them.
This has been Chrome's behaviour since version 110 and it is deliberate.

Now compare the same two files with JA4:

```bash
python3 -c "
import sys; sys.path.insert(0, 'src')
from tls_fingerprint.analyzer import analyze_pcap
from tls_fingerprint.ja4 import compute_ja4
for name in ['chrome.pcap', 'chrome_live.pcap']:
    r = analyze_pcap(f'pcaps/{name}')[0]
    print(name, '->', compute_ja4(r.client_hello).ja4_string)
"
```

```
chrome.pcap      -> t13d1516h2_8daaf6152771_806a8c22fdea
chrome_live.pcap -> t13d1517h2_8daaf6152771_541cd5a3d78e
```

What this shows: the middle segment, `8daaf6152771`, is the hash of the cipher
list after sorting, and it is byte for byte identical across both runs. That
is the reordering immunity JA4 was designed to provide, observed on real
traffic rather than quoted from the specification.

The rest of the fingerprint did change, and it should have. The extension
count moved from 16 to 17 because Chrome genuinely offered one extra extension
on the second run, which is a real difference and not a reordering. JA4 shows
which component moved. JA3 collapses everything into one number, so a
reordering and a genuine change look the same.

To see both fingerprints for one capture side by side:

```bash
tls-fingerprint analyze pcaps/chrome.pcap
```

The JA4 block appears below the JA3 block.

## Part 3: detecting a program that lies about its identity

An HTTP `User-Agent` header is a string the client picks, so a script can
claim to be Chrome in one line. The ClientHello was already sent before that
header existed, produced by whichever TLS library the script actually links
against.

`pcaps/bot_client.pcap` is a capture of `experiments/bot_client.py`, which
sends a Chrome `User-Agent` over a plain Python `ssl` handshake.

```bash
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
```

```
Identity Claim Check
--------------------------------
Claims to be: Chrome
Measured JA3: f21f8e6cf70d5980ecfe9fa2e0ef401c
Measured JA4: t13d171100_ab0a1bf427ad_8e6e362c5eac

VERDICT: *** MISMATCH -- SUSPICIOUS *** claims to be 'Chrome' but its real
TLS fingerprint matches: Python 3.14.6 stdlib ssl (ssl.create_default_context)
```

The claimed identity is passed as an argument rather than read from the
traffic, because reading it would require terminating TLS and this project
never decrypts anything. In a real deployment the reverse proxy that
terminates TLS is the one component that sees the ClientHello and the
`User-Agent` together.

To show that repeating the request does not help, on the machine the database
was measured on:

```bash
python experiments/bombard_demo.py 5
```

```
request 1/5: JA3=f21f8e6c...  -> FLAGGED
request 2/5: JA3=f21f8e6c...  -> FLAGGED
request 3/5: JA3=f21f8e6c...  -> FLAGGED
request 4/5: JA3=f21f8e6c...  -> FLAGGED
request 5/5: JA3=f21f8e6c...  -> FLAGGED

Result: 5/5 requests correctly flagged as lying about their identity.
```

Note that this rewrites `pcaps/bombard_1.pcap` through `bombard_5.pcap`.

What this shows: each connection is judged on its own handshake, so there is
no running average to dilute and no per-source threshold to stay under.
Spreading the same script across many IP addresses would not help either,
since the address is not part of what is checked.

What this does not show: the detection works because the script uses an
unmodified Python `ssl` handshake. A tool such as curl-impersonate or uTLS
that reproduces Chrome's ClientHello byte for byte would pass this check, and
so would a real browser driven by automation. This catches the cheap case,
which is also the common one.

## Command reference

```bash
tls-fingerprint analyze <pcap>                    identify a capture
tls-fingerprint analyze <pcap> --json             the same output as JSON
tls-fingerprint db list                           list known fingerprints
tls-fingerprint db add --hash H --type ja3 --name N --category client
tls-fingerprint check-spoofing <pcap> --claims Chrome
python experiments/bombard_demo.py 5              repeated-request demonstration
python experiments/build_reference_db.py          rebuild data/fingerprint_db.json
```
