# The Simple Guide (read this if everything else feels like too much)

One page. No jargon. This is the "explain it to me like I'm tired" version.

## What is this project, actually?

When an app (browser, curl, whatever) connects to a website over HTTPS,
before the encryption locks in, the app sends one small unencrypted
"hello" message introducing itself: what it supports, in what order.

Different apps write this "hello" slightly differently — kind of like
handwriting. Chrome's hello looks different from curl's hello, which
looks different from a Python script's hello, even though a human reading
either of them would just see "yeah, that's a normal HTTPS request."

**This project reads that unencrypted hello message and guesses which app
sent it — purely from how it "wrote" its hello — without ever needing to
decrypt anything.**

That guess is called a **fingerprint**. The standard name for this
specific technique is **JA3** (for the client's hello) and **JA3S** (for
the server's reply hello).

## Why would anyone care about this?

Because almost everything on the internet is encrypted now, security
teams can't read what traffic is *saying*. But they can still see *how*
each app said hello — so they use this to spot weird/suspicious software
talking to the internet (e.g. malware calling home) even when they can't
read a single word of the actual conversation.

## How does the code actually do it? (the whole pipeline, in plain words)

Think of it like a mail-sorting facility that only ever looks at the
outside of envelopes, never opens them:

1. **We have a recording of network traffic** — a `.pcap` file. Think of
   it as a security-camera recording of a conversation.
2. **We find the client's first message** in that recording (the "hello"
   before encryption starts).
3. **We find the server's first reply** too.
4. **We turn each hello into a short code** — a few details from the
   hello, glued into one string of text, then run through a hashing
   function (think of it like a blender: same input always makes the same
   smoothie, and you can't easily un-blend it). That short code is the
   JA3 (for the client) or JA3S (for the server).
5. **We check a small notebook** ("the database") we built ourselves: "do
   I already know this exact code, and if so, who does it belong to?"
6. **We print an answer**: "this looks like curl" / "this looks like
   Chrome" / "never seen this exact code before."

That's the entire project. Everything else in this repo is either code
that does one of those 6 steps, a test that checks a step works, or a
doc explaining a step in more depth than you probably need right now.

## What does each file/folder actually do? (plain-language map)

```
src/tls_fingerprint/
  parser.py         reads the raw recording, finds the "hello" messages
  ja3.py / ja3s.py  turns a hello message into a short code
  database.py       the "notebook" that remembers known codes -> names
  analyzer.py       runs steps 1-5 above, one after another
  cli.py            the actual command you type in the terminal
  report.py         makes the printed output look nice/readable
  capture_proxy.py  a tool that records REAL traffic without needing
                     an admin password (macOS normally requires that)

data/fingerprint_db.json   the actual notebook file — 5 real apps we
                            already recorded and identified

pcaps/*.pcap        the actual recordings we made: curl, openssl, a
                    python script, chrome, and one we hand-built ourselves

experiments/        the scripts that made those 5 recordings, so you
                    could make a 6th one yourself the same way

tests/              automatic checks that prove the code works correctly
                    (run these with `pytest` any time you're unsure
                    something's broken)

docs/               longer explanations — only open these if you want to
                    go deeper on a specific thing (see the map at the
                    bottom of this file)
```

## What do I actually run? (copy-paste this)

Open a terminal in the project folder, then:

```bash
# 1. turn on the project's isolated Python setup (do this every time you open a new terminal)
source .venv/bin/activate

# 2. prove the code works — should say "36 passed"
pytest

# 3. see the notebook of known apps
tls-fingerprint db list

# 4. analyze one recording and see the identification happen
tls-fingerprint analyze pcaps/curl.pcap
```

That last command prints something like:

```
Likely Client: curl 8.7.1 (macOS system, SecureTransport/LibreSSL)
Match:         Known match (reference database)
```

...meaning: it read the recording, computed curl's fingerprint code, and
recognized it from the notebook.

Now do the same for the other four recordings, to see 5 different guesses:
```bash
tls-fingerprint analyze pcaps/openssl.pcap
tls-fingerprint analyze pcaps/python_ssl.pcap
tls-fingerprint analyze pcaps/chrome.pcap
tls-fingerprint analyze pcaps/custom_client.pcap
```

## What do I actually show/present as "the result"?

One sentence: **five completely different real apps talked to the same
real website, and this tool correctly told all five of them apart, purely
from their unencrypted "hello" message — without reading anything they
actually said.**

Concretely, show this table (it's also in `docs/EXPERIMENTS.md`):

| App | Fingerprint code (JA3) |
|---|---|
| curl | `375c6162a492dfbf2795909110ce8424` |
| openssl | `0b85eb0d4981e69064e40753e4f0ac5f` |
| Python script | `f21f8e6cf70d5980ecfe9fa2e0ef401c` |
| Chrome | `81a2542af8442fcd7802f178d9f2a626` |
| hand-built (no library at all) | `c53113116bb0508ad66a61bbbe6fedc9` |

All 5 codes are different — even though openssl and the Python script are
secretly built on the exact same underlying encryption library. That's
the single most interesting/presentable fact in the whole project: the
fingerprint reflects *how an app is configured*, not just *which library
it uses*.

Also worth mentioning out loud: this can be **wrong** sometimes on
purpose-ish — if two totally unrelated apps happen to say hello in the
exact same way, they'll get the exact same code. The tool is honest about
that (it says "possible match" instead of guessing), which is itself a
thing worth explaining if asked.

## If someone asks "so what did you actually build?"

*"A tool that watches the first, unencrypted handshake message every app
sends before HTTPS kicks in, turns it into a short fingerprint code the
same way a known security technique (JA3) does, and checks it against a
small list of apps I recorded myself — proving you can tell apps apart
from encrypted traffic just by how they say hello."*

## Where to go next if you want more depth (optional, in order of depth)

1. `docs/BIG_PICTURE.md` — why this matters, what's the catch, what came before/after this technique
2. `docs/STUDY_GUIDE.md` — the actual networking concepts (IP, TCP, TLS...) from zero
3. `docs/EXPERIMENTS.md` — exact commands + real output for all 5 recordings
4. `docs/VIVA.md` — likely questions + short answers
5. `docs/PROJECT_REPORT.md` — the formal write-up
