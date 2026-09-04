# Implementation Guide — Run This Live For Your Demo

Every command below is copy-paste ready and every output shown is real —
captured while building this project, not invented. Run them in this
order for a complete, live demo.

## Setup (once per terminal session)

```bash
cd CN_tls_fingerprint
source .venv/bin/activate
pytest -q
```
Expect: `56 passed`. This proves the code logic is correct before you
touch the network at all.

---

## Part 1 — Five real clients, five real fingerprints

Everything below was captured by pointing 5 different real programs at
the real website `example.com` (a domain reserved by IANA specifically
for demos/tutorials — safe to hit repeatedly) through a small relay
(`capture_proxy.py`) that forwards bytes untouched so the handshake stays
100% real. No `sudo` needed.

```bash
tls-fingerprint db list
```
Shows the 15 fingerprints already on file (5 clients x JA3 + JA3S + JA4).

```bash
tls-fingerprint analyze pcaps/curl.pcap
```
```
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)
```

Repeat for the other four:
```bash
tls-fingerprint analyze pcaps/openssl.pcap
tls-fingerprint analyze pcaps/python_ssl.pcap
tls-fingerprint analyze pcaps/chrome.pcap
tls-fingerprint analyze pcaps/custom_client.pcap
```

**Result — all 5 JA3 hashes below are different:**

| Client | TLS library | JA3 hash |
|---|---|---|
| curl | SecureTransport/LibreSSL | `375c6162a492…ce8424` |
| openssl s_client | OpenSSL 3.6.2 | `0b85eb0d4981…f0ac5f` |
| Python stdlib `ssl` | OpenSSL 3.6.2 (same lib as above!) | `f21f8e6cf70d…ef401c` |
| Chrome (headless) | BoringSSL | `81a2542af844…f2a626` |
| hand-built ClientHello | none | `c53113116bb0…6fedc9` |

**Say out loud:** openssl and Python use the *identical* crypto library
and still get different fingerprints — JA3 fingerprints *configuration*,
not just which library is loaded.

**Make a fresh one live**, to prove nothing is pre-recorded/faked:
```bash
python -m tls_fingerprint.capture_proxy --mode tcp --target example.com:443 \
    --listen-port 8480 --pcap pcaps/demo_live.pcap \
    -- curl --connect-to example.com:443:127.0.0.1:8480 -sS https://example.com/ -o /dev/null
tls-fingerprint analyze pcaps/demo_live.pcap
```
Same hash as `curl.pcap` above, every time — same real curl, same real
fingerprint.

---

## Part 2 — JA3 vs JA4: a real weakness, and a real fix

`pcaps/chrome.pcap` (Part 1) was one headless Chrome capture. We then ran
the **exact same real Chrome command again, live**, to get a second,
independent sample:

```bash
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
python -m tls_fingerprint.capture_proxy --mode connect --listen-port 8462 \
    --pcap pcaps/chrome_live.pcap --expect-host example.com --accept-timeout 45 \
    -- "$CHROME" --headless=new --disable-gpu --no-first-run \
    --disable-background-networking --disable-search-engine-choice-screen \
    --user-data-dir=/tmp/chrome-live-test --proxy-server=127.0.0.1:8462 \
    --disable-quic --virtual-time-budget=8000 --dump-dom https://example.com/
```
(`--expect-host` matters here: headless Chrome opens a few background
connections — a network-time check, some Google/gstatic requests — before
it ever reaches `example.com`; the relay skips those and waits for the
right one. Can take up to ~60s of quiet output before it finishes — that's
normal, not stuck.)

The result, `pcaps/chrome_live.pcap`, is already saved — but re-running
the command above yourself produces a fresh one live, and the mismatch
below still holds.

**The exact same browser install, run twice, produced two different JA3
hashes:**

```bash
tls-fingerprint analyze pcaps/chrome.pcap      | grep "^Hash" | head -1
tls-fingerprint analyze pcaps/chrome_live.pcap | grep "^Hash" | head -1
```
```
Hash:   81a2542af8442fcd7802f178d9f2a626
Hash:   825cf36b22c9ab3e25a5bc094aecde86
```
Same real Chrome install, two different JA3 hashes. **Why:** Chrome
deliberately randomizes its ClientHello extension order per connection,
specifically to make fingerprinting harder.

**JA4 fixes this** by sorting the cipher/extension lists before hashing.
Compare both files with JA4 instead:
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
chrome_live.pcap -> t13d1517h2_8daaf6152771_cb7bf5808d99
```

**Say out loud:** the middle segment (`8daaf6152771`, the cipher hash)
is **identical** in both — that's the reordering-immunity working. The
extension count changed `16`→`17` because Chrome genuinely sent one
extra extension that run — JA4 reports that honestly instead of hiding
it in one opaque number, unlike JA3.

Or see both fingerprints together in the normal tool:
```bash
tls-fingerprint analyze pcaps/chrome.pcap
```
Look at the **JA4 (client, reorder-resistant)** section under the JA3 one.

---

## Part 3 — Catching a program that lies about its identity

This is the real security use case: a program can freely claim to be
Chrome (a `User-Agent` header is just text) — but it can't as easily fake
the TLS handshake its actual library produces.

`pcaps/bot_client.pcap` is a real capture of a Python script that sent a
genuine Python-`ssl` handshake while claiming, via `User-Agent`, to be
Chrome.

```bash
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
```
```
Claims to be: Chrome
Measured JA3: f21f8e6cf70d5980ecfe9fa2e0ef401c
Measured JA4: t13d171100_ab0a1bf427ad_8e6e362c5eac

VERDICT: *** MISMATCH -- SUSPICIOUS *** claims to be 'Chrome' but its
real TLS fingerprint matches: Python 3.14.6 stdlib ssl
(ssl.create_default_context)
```

**Stress test — does volume help it hide?** Fire 5 rapid, independent,
real connections, all claiming to be Chrome:
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

**Say out loud:** each of the 5 is a separate, real, live connection —
detection doesn't weaken as request volume grows, because every
connection is judged on its own handshake, not an average across many.

---

## Quick command reference

```bash
tls-fingerprint analyze <pcap>                        # identify a capture
tls-fingerprint analyze <pcap> --json                  # same, as JSON
tls-fingerprint db list                                 # show known fingerprints
tls-fingerprint db add --hash H --type ja3 --name N --category client   # add one
tls-fingerprint check-spoofing <pcap> --claims Chrome    # bot detection
python experiments/bombard_demo.py 5                     # stress test
python experiments/build_reference_db.py                 # rebuild data/fingerprint_db.json
```
