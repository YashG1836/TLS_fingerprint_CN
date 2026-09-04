TLS FINGERPRINTING — SCREENSHOT EXPLANATIONS
==============================================
Each screenshot is real terminal output from this project, in the order
they were taken. Read top to bottom — they tell one continuous story.


01_pytest_all_tests_passing.png
--------------------------------
Runs "pytest" and gets "61 passed". Think of it as calibrating the tool
before using it — the code's logic is verified on its own, offline, with
zero network involved, BEFORE trusting any real capture that follows.

ARE THESE TESTS ACTUALLY PART OF THE PROJECT, OR JUST FILLER?
They're real, load-bearing, and were an explicit project requirement
(unit + integration tests were asked for from the start) — not padding.
What the 61 tests actually check:
  - JA3 / JA3S string construction, checked against hand-derived expected
    values worked out by hand from the RFC spec (not just re-checking the
    code against itself).
  - JA4, checked against the OFFICIAL FoxIO spec's own published worked
    examples -- an external ground truth we didn't invent.
  - Parser edge cases: a truncated TLS record, a ClientHello offering
    only GREASE ciphers, a handshake message split across two TLS
    records, a malformed extension length -- cases that would crash or
    silently misparse a naive implementation.
  - Database lookup logic: does "known" vs "possible" (ambiguous) vs
    "unknown" get reported correctly.
  - The spoofing-detector's mismatch logic (screenshots 11-12).
  - One end-to-end integration test: build a fake pcap, run the WHOLE
    pipeline on it, check the final printed answer is right.
Why it matters: without these, every "Known match" you see in the other
screenshots would just be "the code ran and printed something" -- these
tests are what let you say the JA3/JA3S/JA4 MATH itself is provably
correct, independent of whether any particular real capture happens to
look right.


02_reference_database_list.png
--------------------------------
"tls-fingerprint db list" — shows the 15 fingerprints already known:
5 real clients (curl, openssl, Python, Chrome, a hand-built client),
each with its JA3 and JA4 entry, plus the server's JA3S (Cloudflare)
for each. This is the "notebook" every later lookup gets checked against.
Every entry was computed from a real capture, never typed by hand.


03_analyze_curl.png
--------------------------------
"tls-fingerprint analyze pcaps/curl.pcap" — a real curl connection to
example.com. Shows the full pipeline output: JA3 string+hash, JA4
string, and JA3S for the server, each correctly matched as "Known match"
against the database. This is the baseline example: one real client,
correctly identified purely from its handshake shape.


04_analyze_openssl.png
--------------------------------
Same command, run on a real "openssl s_client" capture instead. Correctly
identified as openssl, with a JA3 hash completely different from curl's —
different TLS library (OpenSSL vs SecureTransport), different fingerprint.


05_analyze_python_stdlib_ssl.png
--------------------------------
Same command on a real Python (ssl.create_default_context) capture.
The important detail: Python and openssl both use the SAME underlying
OpenSSL 3.6.2 library, yet still get DIFFERENT JA3 hashes here — proof
that JA3 fingerprints the exact configuration a program presents
(its cipher list/order), not just which crypto library is linked.


06_analyze_chrome_headless.png
--------------------------------
Same command on a real headless Chrome capture. Identified correctly as
Chrome (BoringSSL). This is the sample used later as the "before"
picture in the JA3-vs-JA4 story (see screenshot 09).


07_analyze_custom_handbuilt_clienthello.png
--------------------------------
Same command on a ClientHello built entirely by hand — no TLS library at
all, just raw bytes over a socket. Negotiated plain TLS 1.2 (on purpose,
simplest to hand-build) and still got a valid reply from the real server,
matched correctly. Proves JA3 is purely a function of bytes on the wire,
nothing to do with which "real" software sent them.


08_fresh_live_capture_reproducibility.png
--------------------------------
Makes a BRAND NEW live connection with curl right there in the terminal
(not a pre-saved file) and analyzes it immediately. It produces the
exact same JA3/JA4 hash as the original curl capture (screenshot 03) —
the proof that nothing here is cached, faked, or pre-recorded: the same
real client always gives the same real fingerprint.


09_ja3_vs_ja4_chrome_comparison.png
--------------------------------
The core finding of this project. Compares two real Chrome captures
(same browser, two separate runs): JA3 gives two COMPLETELY DIFFERENT
hashes, because Chrome deliberately shuffles/jumbles its ClientHello
extension order every connection to resist fingerprinting. JA4, on the
same two files, sorts the cipher/extension lists before hashing — its
cipher-hash segment ("8daaf6152771") stays IDENTICAL both times, proving
JA4 is resistant to exactly the reordering that broke JA3.


10_live_chrome_recapture_new_mismatch.png
--------------------------------
Runs the live headless-Chrome capture command again, fresh, in front of
the camera. It produces a THIRD distinct JA3 hash — different from both
hashes already on file — so the database correctly reports it as
"Unknown" rather than guessing. This is a bonus, unplanned proof: Chrome
doesn't just differ between two runs, it can differ on every single run,
which is exactly the randomization behavior JA4 was built to survive.


11_bot_spoofing_detection.png
--------------------------------
"tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome" —
this pcap is a script that sent a fake "User-Agent: ...Chrome..." header
while its real handshake was plain Python. The tool ignores the claimed
label, computes the real JA3, and reports "MISMATCH -- SUSPICIOUS...
matches: Python stdlib ssl" — catching the lie purely from the TLS
handshake, which is much harder to fake than a text header.

HOW A FAKE REQUEST PRETENDS TO BE CHROME:
The cheapest, most common way (what our bot_client.py does) is just
setting the HTTP "User-Agent" header to Chrome's exact string — that
header is one line of code in any HTTP client (curl -A, Python requests,
etc.) and the server has no way to verify it's true on its own. Real
bots almost always do exactly this, because it's free and most naive
defenses only ever check that header.

HOW OUR SYSTEM CATCHES IT (the tech):
The User-Agent lie happens at the HTTP layer, which is INSIDE the
encrypted connection and sent AFTER the handshake. But the TLS
ClientHello is sent BEFORE any of that, straight from whatever TLS
library the program actually uses (Python's ssl module here) — the
script never touched that part, so it still looks exactly like Python,
not Chrome. Our tool: (1) computes the real JA3 from the captured
ClientHello bytes (ja3.py), (2) looks up every database entry whose
name contains the claimed word "Chrome" and collects Chrome's real known
hashes, (3) checks if the measured hash is one of them
(spoofing_detector.py). It isn't, so it flags a mismatch and reports
what the hash actually belongs to instead of just saying "fake".
(Note: this specific check would NOT catch a bot using a real Chrome
browser via automation tools like Selenium/Puppeteer, or a purpose-built
tool that deliberately copies Chrome's exact cipher/extension list --
both produce a genuinely Chrome-shaped ClientHello. It catches the
common, cheap case: fake label + an unmodified, off-the-shelf script.)


12_bombardment_stress_test.png
--------------------------------
"python experiments/bombard_demo.py 5" — fires 5 rapid, independent, REAL
connections, each lying about being Chrome the same way as screenshot 11.
All 5 are flagged.

WHY BOMBARDING NORMALLY HELPS BOTS HIDE (in real systems):
Most real-world bot defenses work by counting or averaging: rate-limits
per IP, "% of suspicious traffic" thresholds, or behavioral baselines.
A botnet defeats these by spreading requests across many different IPs/
machines or by staying under the per-IP threshold, so no single source
ever looks bad enough to trigger a block even though the total attack
is huge -- this is exactly why botnets exist instead of one machine
hammering a target.

WHY IT DOESN'T WORK AGAINST OUR SYSTEM:
Our check is per-connection, not a count or an average. Every single
request gets its OWN TLS handshake independently fingerprinted and
independently compared -- there's no running total to dilute and no
threshold to sneak under. Sending 5 or 5,000 requests just produces 5 or
5,000 pieces of equally damning evidence, because the bot uses the same
script/library every time, so every connection carries the identical
giveaway fingerprint. Screenshot 12 proves this directly: 5/5, not
diluted. It also means spreading the bot across many different IP
addresses (the usual botnet trick) wouldn't help either -- IP has
nothing to do with what gets checked here.


ONE-LINE SUMMARY OF THE WHOLE SET
==============================================
01-02 set up and show what's already known -> 03-07 prove 5 different
real clients get 5 different fingerprints -> 08 proves it's not faked ->
09-10 catch JA3 failing on the same real Chrome and show JA4 fixing it ->
11-12 turn the fingerprint into a real defense that catches a lying
script, even under repeated attempts.
