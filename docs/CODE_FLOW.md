# Code Execution Flow: Which File Runs When

This is not "what does each file mean" (that's `SIMPLE_GUIDE.md`) and not
"what does each byte mean" (that's `STUDY_GUIDE.md`). This is: **you run
one command, and here is the exact order files/functions fire, with the
real handshake happening at a specific, identifiable step.**

There are two separate workflows in this project, run at different times:

1. **Capture workflow** — makes a `.pcap` recording. Already run once per
   client (that's how `pcaps/curl.pcap` etc. exist). You only re-run this
   if you want a fresh/new recording.
2. **Analyze workflow** — reads a `.pcap` and prints the identification.
   This is the one you'll run over and over, including on pcaps someone
   else gave you.

Everything below traces the **curl** experiment specifically, since it's
the simplest, but every other client follows the identical shape.

---

## Workflow 1: Capture — making `pcaps/curl.pcap`

**The command that kicks it off:**
```bash
python -m tls_fingerprint.capture_proxy --mode tcp \
    --target example.com:443 --listen-port 8443 --pcap pcaps/curl.pcap \
    -- curl --connect-to example.com:443:127.0.0.1:8443 -sS https://example.com/ -o /dev/null
```

```
   [capture_proxy.py]                        [real internet]
   1. open a listening socket
      on 127.0.0.1:8443
   2. launch curl as a subprocess  ---->  curl starts running
   3. accept curl's connection
   4. open ITS OWN connection to  ------------------->  example.com:443
      example.com:443                                   (real TCP handshake
                                                          happens right here)
   5. curl sends its TLS ClientHello
      into the relay        ------>  relay copies the bytes
                                      into memory, AND forwards
                                      them on            ----->  example.com
   6. example.com replies with its
      real ServerHello        <-----------------------  relay copies THESE
                                                          bytes too, forwards
                                                          them back to curl
   7. curl finishes its real HTTPS request/response, exits
   8. capture_proxy.py hands the two copied byte-buffers to
      [pcap_write.py] -> which calls Scapy's wrpcap()
      -> pcaps/curl.pcap is written to disk
```

**Step by step, by file and function:**

1. You run the command above. Python starts executing
   [`capture_proxy.py`](../src/tls_fingerprint/capture_proxy.py), function
   `main()`.
2. `main()` splits the command line at `--`: everything before is
   capture_proxy's own settings (`--mode`, `--target`, `--listen-port`,
   `--pcap`); everything after (`curl --connect-to ...`) is saved as
   `client_cmd` — the program we're about to launch.
3. `run(args)` starts. It opens a plain TCP listening socket on
   `127.0.0.1:8443` and calls `.listen()` on it — nothing has connected
   yet, it's just ready to accept.
4. **`subprocess.Popen(args.client_cmd, ...)`** — this is the literal
   line that starts `curl` running, as a real separate OS process, at
   this exact point in the script.
5. curl reads its `--connect-to` flag and, instead of connecting straight
   to `example.com`, opens a TCP connection to `127.0.0.1:8443` — our
   listening socket from step 3 — while still believing (and telling the
   server, via SNI) that it's talking to `example.com`.
6. Back in `capture_proxy.py`, `listen_sock.accept()` returns that
   connection as `conn`.
7. `capture_proxy.py` now opens a **second, brand-new** TCP connection —
   `upstream.connect((target_host, target_port))` — this time to the
   *real* `example.com:443`. **This is the actual real TCP three-way
   handshake with the real internet**, happening inside our own script.
8. Two background threads start, both running `_relay_direction()`:
   - Thread A reads whatever curl sends on `conn` (starting with curl's
     real **TLS ClientHello**), appends a copy of those bytes to the
     `client_to_server` buffer in memory, and immediately forwards the
     same bytes onward to `upstream` (the real server). **This is the
     exact moment/place the ClientHello gets captured.**
   - Thread B does the mirror image: reads example.com's real reply
     (starting with its **ServerHello**) off `upstream`, copies it into
     `server_to_client`, and forwards it back to curl on `conn`. **This
     is where the ServerHello gets captured.**
9. curl and the real server finish their handshake and the actual HTTPS
   request/response through this relay, exactly as if the relay wasn't
   there. curl exits.
10. `run()` waits for both threads to finish, closes the sockets, and
    waits for the curl subprocess to exit (and prints its output, because
    `--show-client-output` was passed).
11. `run()` calls
    [`write_synthetic_pcap()`](../src/tls_fingerprint/pcap_write.py),
    handing it the two byte buffers plus the real IP/port info it
    recorded along the way. That function builds two Scapy packet
    objects (`Ether()/IP()/TCP()/Raw()`, one per direction) and calls
    Scapy's `wrpcap()` — **this is the one and only place a `.pcap` file
    actually gets written to disk.**
12. `pcaps/curl.pcap` now exists on disk, containing the real
    ClientHello and real ServerHello bytes from step 8, wrapped in
    ordinary-looking packet headers.

Capture workflow done. Nothing above touches JA3/JA3S at all — this
workflow's only job is producing a `.pcap` file.

---

## Workflow 2: Analyze — reading `pcaps/curl.pcap` back

**The command:**
```bash
tls-fingerprint analyze pcaps/curl.pcap
```

```
pcaps/curl.pcap
      |
      v  scapy.rdpcap()                                    [analyzer.py]
list of packet objects
      |
      v  group by (ip,port) pairs, split by direction       [analyzer.py]
      v  reassemble_tcp_stream()                            [parser.py]
one ordered byte stream per direction
      |
      v  find_client_hello() / find_server_hello()          [parser.py]
ClientHelloInfo  +  ServerHelloInfo   (typed Python objects)
      |
      v  compute_ja3()          v  compute_ja3s()          [ja3.py / ja3s.py]
JA3 hash                        JA3S hash
      |                               |
      v  db.lookup()            v  db.lookup()             [database.py]
known/possible/unknown          known/possible/unknown
      |                               |
      \_______________  ______________/
                      v
              format_report()                               [report.py]
                      |
                      v
              printed to your terminal
```

**Step by step, by file and function:**

1. You run `tls-fingerprint analyze pcaps/curl.pcap`. This runs
   [`cli.py`](../src/tls_fingerprint/cli.py)'s `main()`, which parses
   `analyze` as the subcommand and calls `_cmd_analyze(args)`.
2. `_cmd_analyze` first calls
   `FingerprintDatabase.load(args.db)` — [`database.py`](../src/tls_fingerprint/database.py)
   reads `data/fingerprint_db.json` off disk into a Python object (our
   "notebook" from memory, loaded fresh every run — nothing is cached
   between runs).
3. `_cmd_analyze` calls `analyze_pcap("pcaps/curl.pcap", db=db)` in
   [`analyzer.py`](../src/tls_fingerprint/analyzer.py).
4. `analyze_pcap()` calls **`scapy.rdpcap()`** — this is the one and only
   place the `.pcap` file actually gets read off disk, turned into a list
   of packet objects Python can inspect.
5. `analyze_packets()` groups those packets into flows by
   `(src_ip, src_port, dst_ip, dst_port)` — for our one curl connection,
   this produces exactly one flow with two directions of traffic.
6. For that flow, `reassemble_tcp_stream()` in
   [`parser.py`](../src/tls_fingerprint/parser.py) puts each direction's
   segments back in the right order (matters if a message was ever split
   across more than one TCP segment — see `docs/STUDY_GUIDE.md` §4).
7. Still in `parser.py`: `find_client_hello()` walks the client→server
   stream looking for a TLS handshake record, finds the ClientHello, and
   `parse_client_hello_body()` pulls out its fields (version, cipher
   list, extensions, curves, ...) into a `ClientHelloInfo` object.
   `find_server_hello()` does the same for the reply, producing a
   `ServerHelloInfo`.
8. `compute_ja3(client_hello)` in
   [`ja3.py`](../src/tls_fingerprint/ja3.py) builds the JA3 text string
   (stripping GREASE values via `is_grease()`) and MD5-hashes it.
   `compute_ja3s(server_hello)` in
   [`ja3s.py`](../src/tls_fingerprint/ja3s.py) does the equivalent for
   the server side.
9. Back in `analyzer.py`: both hashes get handed to
   `db.lookup(hash, "ja3")` / `db.lookup(hash, "ja3s")` — this is where
   `database.py` checks the notebook loaded in step 2 and returns
   `known`, `possible`, or `unknown`.
10. Everything from steps 6–9 (the parsed hellos, both hashes, both
    lookup results) gets bundled into one `FlowReport` object and handed
    back to `cli.py`.
11. `cli.py` calls `format_report()` in
    [`report.py`](../src/tls_fingerprint/report.py), which turns that
    object into the readable text block (`Flow` / `TLS` / `JA3` /
    `Client Identification` / ...).
12. `cli.py` `print()`s that text. This is what you see in your
    terminal — the end of the pipeline.

---

## Two workflows you'll also use, briefly

**Rebuilding the whole database at once:**
```bash
python experiments/build_reference_db.py
```
This script just calls `analyze_pcap()` (Workflow 2, steps 4–10) once for
*each* pcap in `pcaps/`, in a loop, and instead of printing a report,
calls `db.add()` + `db.save()` (`database.py`) to write every computed
hash into a fresh `data/fingerprint_db.json`. It's how that file was
built in the first place, and how you'd rebuild it if you captured a new
pcap.

**Running the automated checks:**
```bash
pytest
```
`pytest` finds every `tests/test_*.py` file and runs each `test_*()`
function inside it. These call the exact same functions listed above
(`parse_client_hello_body`, `build_ja3_string`, `db.lookup`, ...)
directly, on hand-built byte sequences instead of real pcaps — so they
run in milliseconds with zero network access, and catch it immediately if
an edit to any file above accidentally changes its behavior.

## The one experiment that skips Workflow 1's relay entirely

[`experiments/custom_client.py`](../experiments/custom_client.py) (the
hand-built-ClientHello experiment) connects **directly** to
`example.com:443` — no `capture_proxy.py` relay in the middle — because
it already builds and sends every byte itself, so it just keeps its own
copy of what it sent and reads the reply directly off its own socket,
then calls `write_synthetic_pcap()` itself (same function as step 11 in
Workflow 1). Same ending, one less hop in the middle.
