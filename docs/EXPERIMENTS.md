# Experiments: Distinguishing 5 Real TLS Clients

Every command below was actually executed while building this project (on
macOS 26.5.2, 2026-08-25) and every hash/result shown is real output, not
invented. Re-running these commands yourself may produce slightly
different hashes if library versions differ on your machine — that's
expected and is itself a demonstration of the "version drift" limitation
in `docs/STUDY_GUIDE.md` §20.

All five experiments target the same real server (`example.com`, actually
served by Cloudflare) so the *only* variable is the client's TLS
implementation.

Start every session with:
```bash
cd "CN_tls_fingerprint"
source .venv/bin/activate
```

## Why a relay, not `tcpdump`

macOS needs `sudo` (interactive password) for raw packet capture. All five
experiments instead route the client through
`src/tls_fingerprint/capture_proxy.py`, a small TCP relay that forwards
every byte to the real server unmodified while logging what it forwards
into a real `.pcap`. See `docs/SETUP_MAC.md` §6 for the `sudo tcpdump`
alternative if you'd rather capture off the wire directly.

---

## Experiment 1: curl (macOS system curl, SecureTransport/LibreSSL)

**How traffic is generated:** the OS-provided `/usr/bin/curl` making a
normal HTTPS GET, redirected at the TCP layer to our relay with
`--connect-to` (this does **not** change what curl believes it's talking
to — the `Host`/SNI stays `example.com` — only where the TCP connection
actually goes).

**Command:**
```bash
python -m tls_fingerprint.capture_proxy --mode tcp \
    --target example.com:443 --listen-port 8443 \
    --pcap pcaps/curl.pcap --show-client-output \
    -- curl --connect-to example.com:443:127.0.0.1:8443 -sS https://example.com/ -o /dev/null -w "curl_http_code=%{http_code}\n"
```

**Real result:** `curl_http_code=200`. Captured 585 bytes client→server,
4847 bytes server→client.

**Analyze:**
```bash
tls-fingerprint analyze pcaps/curl.pcap
```

**Result:**
- TLS version negotiated: TLS 1.3
- JA3 hash: `375c6162a492dfbf2795909110ce8424`
- JA3S hash: `d75f9129bb5d05492a65ff78e081bcb2`
- Library: SecureTransport backed by LibreSSL 3.3.6 (`curl -V` → `curl 8.7.1 (x86_64-apple-darwin25.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6`)

---

## Experiment 2: OpenSSL `s_client` (Homebrew OpenSSL 3.6.2)

**How traffic is generated:** the real `openssl s_client` command-line
tool doing a genuine handshake, `-servername` sets SNI explicitly since
`-connect` points at the relay's loopback address instead of a real
hostname.

**Command:**
```bash
python -m tls_fingerprint.capture_proxy --mode tcp \
    --target example.com:443 --listen-port 8444 \
    --pcap pcaps/openssl.pcap --show-client-output \
    -- openssl s_client -connect 127.0.0.1:8444 -servername example.com -brief < /dev/null
```

**Real result:**
```
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=example.com
Verification: OK
Negotiated TLS1.3 group: X25519MLKEM768
```
(Note the certificate was genuinely validated — `Verification: OK` — even
though the TCP connection went through our relay, because the relay never
touches the TLS bytes.)

**Analyze:**
```bash
tls-fingerprint analyze pcaps/openssl.pcap
```

**Result:**
- TLS version negotiated: TLS 1.3
- JA3 hash: `0b85eb0d4981e69064e40753e4f0ac5f`
- JA3S hash: `907bf3ecef1c987c889946b737b43de8`
- Library: OpenSSL 3.6.2 (`openssl version` → `OpenSSL 3.6.2 7 Apr 2026`)

---

## Experiment 3: Python stdlib `ssl` module

**How traffic is generated:**
[`experiments/python_client.py`](../experiments/python_client.py), a ~15
line script using `ssl.create_default_context()` — the same default
context that `urllib`, `http.client`, and (indirectly) `requests`/
`urllib3` build on.

**Command:**
```bash
python -m tls_fingerprint.capture_proxy --mode tcp \
    --target example.com:443 --listen-port 8445 \
    --pcap pcaps/python_ssl.pcap --show-client-output \
    -- python experiments/python_client.py 127.0.0.1 8445 example.com
```

**Real result:**
```
python_client: TLS version=TLSv1.3 cipher=('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
python_client: first response bytes=b'HTTP/1.1 200 OK\r\nDate: Tue, 25 Aug 2026 '
```

**Analyze:**
```bash
tls-fingerprint analyze pcaps/python_ssl.pcap
```

**Result:**
- TLS version negotiated: TLS 1.3
- JA3 hash: `f21f8e6cf70d5980ecfe9fa2e0ef401c`
- JA3S hash: `907bf3ecef1c987c889946b737b43de8` — **identical to Experiment
  2's JA3S.** Same server, and the client's offered extensions/curves
  overlapped enough that Cloudflare made the same choice both times. See
  `docs/STUDY_GUIDE.md` §18 for what this does and doesn't mean.
- Library: CPython 3.14.6 `ssl` module, linked against the same OpenSSL
  3.6.2 as Experiment 2 — yet the **JA3 hash is different**, because
  `ssl.create_default_context()` curates its own, shorter, differently-
  ordered cipher list than `openssl s_client`'s default. This is the
  clearest illustration in this project that JA3 fingerprints
  *configuration*, not just "which crypto library.so is loaded."

---

## Experiment 4: Google Chrome (headless, real browser)

**How traffic is generated:** a genuine headless Chrome process, given
`--proxy-server` so the browser itself makes an HTTP CONNECT tunnel
through our relay (this is why `capture_proxy.py` has a `--mode connect`:
it speaks just enough HTTP CONNECT to satisfy a real browser's proxy
protocol, then relays raw bytes exactly like `--mode tcp`).

**Command:**
```bash
python -m tls_fingerprint.capture_proxy --mode connect \
    --listen-port 8446 --pcap pcaps/chrome.pcap \
    --expect-host example.com --accept-timeout 45 --show-client-output \
    -- "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    --headless=new --disable-gpu --no-first-run \
    --disable-background-networking --disable-sync --disable-extensions \
    --disable-default-apps --disable-search-engine-choice-screen \
    --disable-component-update --disable-domain-reliability \
    --disable-client-side-phishing-detection --no-service-autorun \
    --user-data-dir=/tmp/chrome-experiment-profile \
    --proxy-server=127.0.0.1:8446 --disable-quic \
    --virtual-time-budget=8000 --dump-dom https://example.com/
```

**Why `--expect-host` and so many `--disable-*` flags:** headless Chrome
opens several other proxied connections on startup (a network-time check,
and — even with `--disable-search-engine-choice-screen` attempted first —
some `google.com`/`gstatic.com`/`accounts.google.com` requests tied to
Chrome's regional search-engine-choice logic) *before* it ever requests
`https://example.com/`. `capture_proxy.py`'s `--mode connect` loop
rejects (`502 Bad Gateway`) any CONNECT request whose host doesn't match
`--expect-host`, and keeps accepting new connections until the real one
arrives. This was discovered empirically while building this experiment —
the first attempt failed with the relay latching onto the network-time
request. `--accept-timeout 45` gives Chrome enough wall-clock time to work
through its startup requests first.

**Real result:** captured 1791 bytes client→server, 4269 bytes
server→client.

**Analyze:**
```bash
tls-fingerprint analyze pcaps/chrome.pcap
```

**Result:**
- TLS version negotiated: TLS 1.3
- JA3 hash: `81a2542af8442fcd7802f178d9f2a626`
- JA3S hash: `eb1d94daa7e0344597e756a1fb6e7054`
- Library: BoringSSL (Chromium's TLS stack), Chrome 151.0.7922.174
- **Caveat:** real Chrome (not headless) additionally randomizes
  ClientHello extension *order* per connection (see
  `docs/STUDY_GUIDE.md` §20) — running this experiment again may not
  reproduce this exact JA3 even on the identical Chrome build. Headless
  mode's behavior here was not separately verified against interactive
  Chrome — treat any exact-match claim beyond "distinct from the other 4
  clients" as `USER MUST VERIFY`.

---

## Experiment 5: Custom hand-built ClientHello (no TLS library at all)

**How traffic is generated:**
[`experiments/custom_client.py`](../experiments/custom_client.py) builds a
complete TLS record + ClientHello handshake message **by hand**, byte by
byte (see the file for the exact RFC 5246 §7.4.1.2 layout it follows), and
sends it over a bare `socket.create_connection()` — no `ssl` module, no
OpenSSL binding, nothing. It connects directly to the real server (no
relay needed, since the script already has full control of every byte it
sends and reads back).

**Command:**
```bash
python experiments/custom_client.py example.com 443 pcaps/custom_client.pcap
```

**Real result:**
```
custom_client: sent 106B ClientHello to example.com:443
custom_client: received 3902B in response
custom_client: wrote pcaps/custom_client.pcap
```
The server accepted our hand-built ClientHello and replied with a full
ServerHello + Certificate flight — proof the bytes were well-formed
enough to be a valid TLS 1.2 ClientHello.

**Analyze:**
```bash
tls-fingerprint analyze pcaps/custom_client.pcap
```

**Result:**
- TLS version negotiated: TLS 1.2 (deliberate — the script sends no
  `supported_versions`/`key_share` extension, so the server falls back to
  the legacy negotiation path; see the script's docstring for why)
- JA3 hash: `c53113116bb0508ad66a61bbbe6fedc9`
- JA3S hash: `ba02d4299a6e8c8482ecf2af07631993`
- Library: none — this *is* the "custom/other implementation" required by
  the project brief.

---

## Comparison: all 5 clients, one table

Regenerate this table any time with `tls-fingerprint db list` after
`python experiments/build_reference_db.py`.

| Client | TLS lib | TLS version | JA3 hash | JA4 | JA3S hash |
|---|---|---|---|---|---|
| curl 8.7.1 (macOS) | SecureTransport/LibreSSL | 1.3 | `375c6162a492dfbf2795909110ce8424` | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` | `d75f9129bb5d05492a65ff78e081bcb2` |
| openssl s_client 3.6.2 | OpenSSL 3.6.2 | 1.3 | `0b85eb0d4981e69064e40753e4f0ac5f` | `t13d301100_1d37bd780c83_8e6e362c5eac` | `907bf3ecef1c987c889946b737b43de8` |
| Python 3.14.6 `ssl` | OpenSSL 3.6.2 (same lib as above) | 1.3 | `f21f8e6cf70d5980ecfe9fa2e0ef401c` | `t13d171100_ab0a1bf427ad_8e6e362c5eac` | `907bf3ecef1c987c889946b737b43de8` |
| Chrome 151 (headless) | BoringSSL | 1.3 | `81a2542af8442fcd7802f178d9f2a626` | `t13d1516h2_8daaf6152771_806a8c22fdea` | `eb1d94daa7e0344597e756a1fb6e7054` |
| Custom raw ClientHello | none (hand-built) | 1.2 | `c53113116bb0508ad66a61bbbe6fedc9` | `t12d040400_4fe0dd5c3cea_1d42f82b3e0b` | `ba02d4299a6e8c8482ecf2af07631993` |

Note openssl and Python's JA4 middle segment (`part_b`, the cipher hash)
differs from each other (`1d37bd780c83` vs `ab0a1bf427ad`) even though
their JA3S was identical — JA4's cipher segment is sensitive to the
*actual* cipher list content, so two clients offering a different set of
ciphers to the same server still show up as different, exactly as they
should.

**The headline result:** all 5 JA3 hashes are distinct, including between
two clients (openssl, Python) sharing the exact same underlying crypto
library — proving JA3 fingerprints the *TLS configuration a specific
program presents*, not merely "which .so/.dylib is linked." The two
identical JA3S hashes (openssl vs. Python, same server) demonstrate the
matching limitation documented in `docs/STUDY_GUIDE.md` §18 and
`docs/PROJECT_REPORT.md`.

---

## Experiment 6 (stretch): JA4 vs JA3 stability, same real Chrome, two runs

Chrome's ClientHello extension order is known to be randomized between
connections specifically to weaken JA3 (`docs/STUDY_GUIDE.md` §20). We
hit this live, by accident, while re-testing Experiment 4: running the
*exact same* headless Chrome command a second time produced a
**different JA3 hash** than the first run.

**Two real captures of the same real Chrome 151.0.7922.174 install:**
- `pcaps/chrome.pcap` (first run) — JA3 `81a2542af8442fcd7802f178d9f2a626`
- `pcaps/chrome_live.pcap` (second run, re-run yourself with the same
  command as Experiment 4) — JA3 `825cf36b22c9ab3e25a5bc094aecde86`

**Same two pcaps, computed with JA4 instead:**
```bash
python3 -c "
import sys; sys.path.insert(0, 'src')
from tls_fingerprint.analyzer import analyze_pcap
from tls_fingerprint.ja4 import compute_ja4
for name in ['chrome.pcap', 'chrome_live.pcap']:
    r = analyze_pcap(f'pcaps/{name}')[0]
    print(name, compute_ja4(r.client_hello).ja4_string)
"
```
**Real result:**
```
chrome.pcap      t13d1516h2_8daaf6152771_806a8c22fdea
chrome_live.pcap t13d1517h2_8daaf6152771_cb7bf5808d99
```

**What actually happened, honestly (not "JA4 magically fixes everything"):**
- The cipher-list segment (`8daaf6152771`) is **byte-for-byte identical**
  in both runs — this is the specific problem JA4 was designed to fix,
  and here it demonstrably worked: sorting the cipher list before hashing
  made it immune to whatever reordering Chrome did.
- The extension **count** in part_a changed `16`→`17` between runs, and
  the extension-hash segment differs too (`806a8c22fdea` vs
  `cb7bf5808d99`) — because Chrome's second run genuinely included **one
  additional extension** (type `51764`) that the first run didn't send.
  That's a real difference in what Chrome transmitted, not a
  fingerprinting artifact — JA4 correctly reports it as a real difference
  instead of hiding it. `USER MUST VERIFY`: we did not identify exactly
  which named TLS extension `51764`/`0xca34` corresponds to; treat it as
  "an experimental/rotating Chrome feature," not a confirmed name.
- **Bonus cross-check:** our real Chrome's cipher list, in its real
  on-the-wire order, is identical to the official JA4 spec's own
  documentation example (`1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,
  c013,c014,009c,009d,002f,0035`) — strong evidence the spec's authors
  also used a real Chrome capture as their example, and that our
  implementation agrees with theirs on real data, not just on paper.

## Experiment 7 (stretch): catching a client that lies about its identity

The concrete security scenario motivating this whole project: a script
claims (via the HTTP `User-Agent` header — a header it's free to set to
anything) to be Chrome, while its real TLS handshake was produced by a
completely different, already-fingerprinted stack.

**How the "attacker" traffic is generated:**
[`experiments/bot_client.py`](../experiments/bot_client.py) — identical
TLS behavior to Experiment 3's Python client, but sends
`User-Agent: Mozilla/5.0 ... Chrome/120.0.0.0 ...` in its HTTP request.

**Command:**
```bash
python -m tls_fingerprint.capture_proxy --mode tcp --target example.com:443 \
    --listen-port 8470 --pcap pcaps/bot_client.pcap --show-client-output \
    -- python experiments/bot_client.py 127.0.0.1 8470 example.com
```

**Real result:** captured 1799 bytes client→server, 6456 bytes
server→client; real HTTP 200 response.

**The detection check:**
```bash
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome
```

**Real output:**
```
Identity Claim Check
--------------------------------
Claims to be: Chrome
Measured JA3: f21f8e6cf70d5980ecfe9fa2e0ef401c
Measured JA4: t13d171100_ab0a1bf427ad_8e6e362c5eac

VERDICT: *** MISMATCH -- SUSPICIOUS *** claims to be 'Chrome' but its real
TLS fingerprint matches: Python 3.14.6 stdlib ssl (ssl.create_default_context)
```
`check-spoofing` never reads the encrypted HTTP layer itself (see
`src/tls_fingerprint/spoofing_detector.py`'s docstring for why) — the
claimed identity is supplied by the caller, exactly like a real reverse
proxy/WAF would have it: that's the one place in a real deployment that
legitimately sees both the ClientHello and the decrypted User-Agent
together, because it's the box terminating TLS.

**Volume doesn't help it blend in — the "bombardment" demo:**
```bash
python experiments/bombard_demo.py 5
```
**Real result** (5 separate, fresh, real network connections):
```
  request 1/5: JA3=f21f8e6cf70d5980ecfe9fa2e0ef401c  -> FLAGGED (mismatch)
  request 2/5: JA3=f21f8e6cf70d5980ecfe9fa2e0ef401c  -> FLAGGED (mismatch)
  request 3/5: JA3=f21f8e6cf70d5980ecfe9fa2e0ef401c  -> FLAGGED (mismatch)
  request 4/5: JA3=f21f8e6cf70d5980ecfe9fa2e0ef401c  -> FLAGGED (mismatch)
  request 5/5: JA3=f21f8e6cf70d5980ecfe9fa2e0ef401c  -> FLAGGED (mismatch)

Result: 5/5 requests correctly flagged as lying about their identity.
```
Each request is an independent, real TCP connection with its own real
TLS handshake — the fingerprint doesn't degrade, average out, or get
easier to fake as the request count grows, because it's evidence about
*that single connection's* TLS stack, not a property of the traffic
volume.

---

## Rebuilding the reference database

After (re-)capturing any of the pcaps above:
```bash
python experiments/build_reference_db.py
```
This recomputes every hash directly from `pcaps/*.pcap` (never from
hard-coded values in the script) and rewrites
`data/fingerprint_db.json` from scratch.

## Optional stretch: a real (non-headless) browser, captured with `sudo tcpdump`

Not executed as part of this project (would require an interactive
`sudo` password and a GUI browsing session — see `docs/SETUP_MAC.md`
§6b). If you want to try it yourself:
```bash
sudo tcpdump -i en0 -w pcaps/browser_live.pcap 'tcp port 443 and host example.com'
# then, in a real browser window, visit https://example.com/
# Ctrl+C the tcpdump once the page has loaded, then:
tls-fingerprint analyze pcaps/browser_live.pcap
```
`NOT EXECUTED` by this project — mark any result you get as your own.
