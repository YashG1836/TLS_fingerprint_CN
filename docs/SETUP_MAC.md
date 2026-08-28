# macOS Setup Guide (Beginner-Friendly)

Every command below was actually run on the development machine
(macOS 26.5.2 / Darwin 25F84, Apple Silicon) while building this project.
Where output is shown, it's real output from that run — not invented.

## 1. Check you have Python 3.10+

```bash
python3 --version
```
Explanation: this project needs Python 3.10 or newer (it uses modern type
hint syntax like `int | None`). The development machine had:
```
Python 3.14.6
```
If you're below 3.10, install a newer Python via
[Homebrew](https://brew.sh): `brew install python3`.

## 2. Clone/open the project and create a virtual environment

```bash
cd "CN_tls_fingerprint"
python3 -m venv .venv
source .venv/bin/activate
```
Explanation:
- `python3 -m venv .venv` creates an isolated Python environment in a
  `.venv/` folder, so this project's dependencies don't pollute (or get
  polluted by) anything else on your system.
- `source .venv/bin/activate` switches your current shell to use that
  environment. You'll see `(.venv)` appear in your prompt. **Run this in
  every new terminal tab/session before using the project.**

## 3. Install dependencies

```bash
pip install --upgrade pip
pip install -e .
pip install pytest
```
Explanation:
- `pip install -e .` reads `pyproject.toml` and installs this project
  itself in "editable" mode (so `import tls_fingerprint` works from
  anywhere, and code changes take effect immediately without
  reinstalling) along with its one real dependency, **Scapy** (used for
  reading/writing `.pcap` files and basic packet field access).
- `pytest` is the test runner, listed separately as a dev dependency.

Verify:
```bash
python3 -c "import scapy; print('scapy', scapy.VERSION)"
tls-fingerprint --help
```

## 4. Run the test suite

```bash
pytest
```
This should show all tests passing (36 tests at the time of writing — unit
tests for the parser, JA3, JA3S, database, and report formatting, plus
integration tests that build a synthetic pcap and run it through the full
pipeline). Nothing here needs network access or root.

## 5. Analyze a pcap (no special privileges needed)

```bash
tls-fingerprint analyze pcaps/curl.pcap
```
This is the main, reproducible path for the whole project: reading a
`.pcap` file needs no elevated privileges on macOS, unlike live capture.
All the experiment pcaps in `pcaps/` (see `docs/EXPERIMENTS.md`) can be
analyzed this way without needing `sudo` at all.

## 6. Two ways to get real TLS traffic into a pcap

### 6a. The relay method this project uses by default (no `sudo`)

macOS requires root to put a network interface into promiscuous/monitor
mode for packet sniffing. Rather than requiring you to type your password
for every experiment, this project ships
[`src/tls_fingerprint/capture_proxy.py`](../src/tls_fingerprint/capture_proxy.py):
a small TCP relay that a client connects through instead of connecting
directly to the real server. The relay forwards every byte unmodified
(the TLS handshake and certificate validation are 100% real) while also
logging what it forwards, then writes those bytes into a real `.pcap`.
No `sudo` required. See `docs/EXPERIMENTS.md` for exact commands per
client.

### 6b. Classic live capture with `tcpdump` (needs `sudo`)

This is the traditional approach, and works fine if you're comfortable
typing your password. It's **not** required for anything in this
project's MVP, but useful to know:

```bash
# List available network interfaces
networksetup -listallhardwareports

# Find your active interface (commonly en0 on Wi-Fi)
ifconfig | grep -B1 "status: active"

# Capture TLS traffic on port 443 into a pcap (Ctrl+C to stop)
sudo tcpdump -i en0 -w pcaps/live_capture.pcap 'tcp port 443'
```
Explanation:
- `sudo` is required because raw packet capture needs kernel-level BPF
  device access, which macOS restricts to root by default (Wireshark
  installs a helper, `ChmodBPF`, specifically to avoid this — not
  installed here, since we don't require Wireshark).
- `-i en0` selects the network interface to listen on (`en0` is typically
  Wi-Fi on a Mac; use the interface you found in the previous command).
- `-w pcaps/live_capture.pcap` writes captured packets to a file instead
  of printing them.
- `'tcp port 443'` is a **capture filter**: only TLS-typical traffic is
  recorded, not everything on the network.

While that's running, generate traffic in another terminal (e.g.
`curl https://example.com/`), then `Ctrl+C` the tcpdump. Analyze the
result the same way:
```bash
tls-fingerprint analyze pcaps/live_capture.pcap
```

There is also a scapy-based equivalent built into the CLI, for the same
`sudo` reason:
```bash
sudo .venv/bin/python -m tls_fingerprint.cli live --iface en0 --count 20 --out pcaps/live_capture.pcap
```
(Use the venv's own Python explicitly with `sudo`, since `sudo` by default
uses the system Python/PATH, not your activated virtualenv.)

## 7. Common macOS-specific issues

- **"Operation not permitted" / permission errors during `sudo tcpdump`**
  on modern macOS: open **System Settings → Privacy & Security → Local
  Network** (and, on some versions, **Full Disk Access**) and make sure
  your terminal app (Terminal.app / iTerm2) is allowed. This is a macOS
  privacy protection, not a bug in this project.
- **No Wireshark/tshark installed:** not required. This project reads and
  writes `.pcap` files itself via Scapy. Installing
  [Wireshark](https://www.wireshark.org/) is optional and only useful if
  you want to *visually* inspect a pcap yourself.
- **`curl -V` shows `SecureTransport`, not OpenSSL:** this is expected and
  is exactly the point of experiment #1 in `docs/EXPERIMENTS.md` — macOS's
  system `curl` uses Apple's native TLS stack (backed by LibreSSL), which
  is a different library from Homebrew's `openssl` binary or Python's
  `ssl` module, and produces a genuinely different JA3.
- **Homebrew `openssl` vs. system `openssl`:** macOS does not ship a
  usable system `openssl` CLI (it's LibreSSL-based and often absent from
  `PATH`). Install via `brew install openssl` and make sure
  `/opt/homebrew/bin` (Apple Silicon) or `/usr/local/bin` (Intel) is ahead
  of `/usr/bin` in your `PATH`. Check with `openssl version`.
- **Chrome headless flags changing between versions:** the exact flag set
  used in `experiments/` was verified against Chrome 151.0.7922.174. If a
  newer Chrome silently changes behavior, re-run
  `experiments/build_reference_db.py` after re-capturing — it always
  recomputes hashes from whatever is actually in `pcaps/`, never from
  hard-coded values.

## 8. Everyday commands cheat-sheet

```bash
source .venv/bin/activate            # activate the environment (every new shell)
pytest                               # run all tests
tls-fingerprint analyze <pcap>       # analyze a pcap, text output
tls-fingerprint analyze <pcap> --json  # same, JSON output
tls-fingerprint db list              # list the reference database
```
