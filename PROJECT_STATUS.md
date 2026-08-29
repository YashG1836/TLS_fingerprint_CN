# Project Status

Last updated against the state of the repo after Phase 10 (final audit).
Re-run the commands in the "Evidence" column yourself any time to confirm
these are still accurate — nothing here is asserted without a command you
can reproduce.

| Requirement | Status | Evidence |
|---|---|---|
| Passive capture OR pcap reading | ✅ Done (pcap-first; live capture optional, needs `sudo`) | `tls-fingerprint analyze pcaps/curl.pcap`; live path: `cli.py live` subcommand, `docs/SETUP_MAC.md` §6b |
| TLS ClientHello parsing | ✅ Done | `src/tls_fingerprint/parser.py::parse_client_hello_body`; tested in `tests/test_parser.py`, `tests/test_parser_edge_cases.py` |
| TLS ServerHello parsing | ✅ Done | `src/tls_fingerprint/parser.py::parse_server_hello_body`; tested in `tests/test_parser.py` |
| JA3 calculation (spec-faithful) | ✅ Done | `src/tls_fingerprint/ja3.py`; `tests/test_ja3.py` checks against hand-derived expected strings, not just self-consistency |
| JA3S calculation (spec-faithful) | ✅ Done | `src/tls_fingerprint/ja3s.py`; `tests/test_ja3s.py` |
| GREASE handling (RFC 8701) | ✅ Done | `ja3.GREASE_VALUES` (16 values, generated not hard-coded per-value); `tests/test_ja3.py::test_grease_table_has_16_values` |
| Local fingerprint reference database | ✅ Done, 15 measured entries (5 JA3 + 5 JA3S + 5 JA4) | `data/fingerprint_db.json`, built by `experiments/build_reference_db.py` from real pcaps |
| Fingerprint lookup/matching | ✅ Done, 3-state (known/possible/unknown) | `src/tls_fingerprint/database.py::lookup`; `tests/test_database.py` |
| CLI output | ✅ Done (text + `--json`) | `tls-fingerprint analyze <pcap>`, `tls-fingerprint db list` |
| ≥5 distinct clients/tools demonstrated | ✅ Done — 5 real, distinct JA3 hashes | `docs/EXPERIMENTS.md`: curl, openssl, Python `ssl`, headless Chrome, custom raw ClientHello |
| Distinguish curl / browser / Python / custom | ✅ Done, all against the same real server | `docs/EXPERIMENTS.md` comparison table |
| Validation against reliable reference values | ⚠️ Partial — validated against hand-derived spec values, not third-party published hashes | `tests/test_ja3.py`/`test_ja3s.py` build ClientHello/ServerHello bytes by hand and independently derive the expected JA3/JA3S string field-by-field from the RFC layout; we deliberately did **not** fabricate "known-good" published hashes from memory (see `docs/PROJECT_REPORT.md` §10 future work) |
| Unit tests: JA3 construction | ✅ Done | `tests/test_ja3.py` |
| Unit tests: JA3 hashing | ✅ Done | `tests/test_ja3.py::test_compute_ja3_hashes_the_string_with_md5` |
| Unit tests: JA3S construction | ✅ Done | `tests/test_ja3s.py` |
| Unit tests: JA3S hashing | ✅ Done | `tests/test_ja3s.py::test_compute_ja3s_hashes_with_md5` |
| Unit tests: parser edge cases | ✅ Done | `tests/test_parser_edge_cases.py` — empty stream, non-handshake content type, truncated record, all-GREASE ciphers, multi-message record, malformed extension length |
| Integration tests: pcap → parser → JA3 → DB lookup | ✅ Done | `tests/test_integration.py` — builds a synthetic pcap with Scapy, runs the full pipeline |
| `pytest` passes | ✅ Done — 56/56 passing | Run `pytest` yourself; captured output at time of writing: `56 passed in 0.20s` |
| **Stretch: JA4 (client) implementation** | ✅ Done, spec-verified | `src/tls_fingerprint/ja4.py`; `tests/test_ja4.py` validated against the *official* FoxIO spec's own worked examples (cipher hash, extension hash, full end-to-end string), not just self-consistency |
| **Stretch: JA4 vs JA3 stability comparison** | ✅ Done — real, both-ways result | `docs/EXPERIMENTS.md` "Experiment 6" — same real Chrome, two runs: JA3 differed, JA4's cipher-hash segment stayed identical while its extension-count segment correctly changed (Chrome genuinely sent a different extension that run) |
| **Stretch: bot/spoofing detection (JA3 vs claimed identity)** | ✅ Done, real capture | `src/tls_fingerprint/spoofing_detector.py`, `tls-fingerprint check-spoofing`; `tests/test_spoofing_detector.py`; real demo in `docs/EXPERIMENTS.md` "Experiment 7" |
| **Stretch: "bombardment" detection-under-volume demo** | ✅ Done, real captures | `experiments/bombard_demo.py` — 5 real, separate live connections, each claiming to be Chrome, all 5 correctly flagged |
| macOS setup instructions | ✅ Done | `docs/SETUP_MAC.md` |
| Beginner study guide (CN → TLS → JA3 from zero) | ✅ Done | `docs/STUDY_GUIDE.md`, 21 sections + "what I should remember" |
| Viva questions | ✅ Done — 40 questions | `docs/VIVA.md` |
| Final demo procedure | ✅ Done | See "How to demo this project" below |
| Limitations explained (matching, GREASE, randomization, evasion) | ✅ Done | `docs/STUDY_GUIDE.md` §20, `docs/PROJECT_REPORT.md` §9 |
| Security-monitoring applications explained | ✅ Done | `docs/STUDY_GUIDE.md` §19, `docs/PROJECT_REPORT.md` §8 |
| No Linux-only tech (eBPF/XDP/TRex/Redis) in MVP | ✅ Confirmed — none used | `requirements.txt` / `pyproject.toml` only list `scapy` + `pytest` |
| Project report | ✅ Done, with placeholders where only you can fill in (name, date) | `docs/PROJECT_REPORT.md` |
| README | ✅ Done | `README.md` |

## What still needs YOUR action (cannot be completed on your behalf)

- **`docs/PROJECT_REPORT.md`** header: fill in your name/roll number and
  submission date (marked `USER MUST VERIFY`).
- **Non-headless browser capture**: the Chrome experiment used
  `--headless=new`. Whether *interactive* Chrome's documented
  extension-order randomization is visible on your machine is flagged
  `USER MUST VERIFY` in `docs/EXPERIMENTS.md` and
  `docs/PROJECT_REPORT.md` §9 — try it yourself with `sudo tcpdump` (see
  `docs/SETUP_MAC.md` §6b) if you want to demonstrate it live in your
  viva.
- **`sudo tcpdump` live capture path**: works but was not exercised in
  this session (no interactive `sudo` password available here). Try it
  yourself per `docs/SETUP_MAC.md` §6b if your evaluator wants to see a
  literal NIC-level capture rather than the relay method.
- **Published/external reference fingerprints**: deliberately not added
  to `data/fingerprint_db.json` to avoid fabricating data. If you want
  some, add them yourself from a trustworthy public source with
  `tls-fingerprint db add --source-type published_reference --source "<citation>"`.

## How to demo this project

```bash
source .venv/bin/activate

# 1. Show the tests pass
pytest

# 2. Show the reference database
tls-fingerprint db list

# 3. Analyze each of the 5 experiment pcaps, showing distinct JA3 hashes
#    and correct known-match identification against the database
for f in curl openssl python_ssl chrome custom_client; do
  echo "=== $f ==="
  tls-fingerprint analyze "pcaps/$f.pcap"
done

# 4. (Optional, live) re-capture curl right now and confirm the SAME real
#    client reproducibly gets the SAME JA3 hash and known match again:
python -m tls_fingerprint.capture_proxy --mode tcp --target example.com:443 \
    --listen-port 8450 --pcap pcaps/demo.pcap \
    -- curl --connect-to example.com:443:127.0.0.1:8450 -sS https://example.com/ -o /dev/null
tls-fingerprint analyze pcaps/demo.pcap   # -> known match, same hash as pcaps/curl.pcap

# 5. To see the "unknown" path instead, analyze a pcap for a client NOT in
#    the database yet (any tool not already in `tls-fingerprint db list`,
#    e.g. wget or a browser other than the one already captured) -- it will
#    report status "unknown" until you add it with `tls-fingerprint db add`.

# 6. (Stretch) show JA4's reorder-resistance: same command, richer output
tls-fingerprint analyze pcaps/chrome.pcap        # note the JA4 section

# 7. (Stretch) bot detection: a script lying about being Chrome gets caught
tls-fingerprint check-spoofing pcaps/bot_client.pcap --claims Chrome

# 8. (Stretch) the "bombardment" demo -- 5 fresh live connections, all flagged
python experiments/bombard_demo.py 5
```

## Test evidence (full detail)

```
$ pytest -q
........................................................                 [100%]
56 passed in 0.20s
```
