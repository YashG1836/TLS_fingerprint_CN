"""JA3S fingerprint computation.

JA3S is the server-side counterpart to JA3, computed from the ServerHello
the server sends back. Same Salesforce spec as ja3.py.

JA3S string format (3 comma-separated fields):

    SSLVersion,Cipher,SSLExtension

- SSLVersion: the ServerHello's version field (decimal).
- Cipher: the single cipher suite the server chose (decimal, not a list --
  a server picks exactly one).
- SSLExtension: extension type IDs from the ServerHello, in order.

There is no EllipticCurve / EllipticCurvePointFormat field in JA3S: a
ServerHello doesn't carry a list of supported groups (that's a ClientHello
concept -- the server already picked, if anything, a single key_share).

Because JA3S only reflects the server's *chosen* cipher/extensions -- which
depend on what the client offered -- the same server can produce different
JA3S values against different clients. JA3S is best read as "JA3 of this
client paired with JA3S of this server", not as a server identity on its
own. See docs/PROJECT_REPORT.md limitations.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .ja3 import is_grease
from .parser import ServerHelloInfo


@dataclass(frozen=True)
class JA3SResult:
    ja3s_string: str
    ja3s_hash: str


def build_ja3s_string(server_hello: ServerHelloInfo) -> str:
    version = server_hello.version
    cipher = server_hello.cipher_suite
    extensions = [e for e in server_hello.extension_types if not is_grease(e)]

    fields = [
        str(version),
        str(cipher),
        "-".join(str(v) for v in extensions),
    ]
    return ",".join(fields)


def compute_ja3s(server_hello: ServerHelloInfo) -> JA3SResult:
    ja3s_string = build_ja3s_string(server_hello)
    ja3s_hash = hashlib.md5(ja3s_string.encode("ascii")).hexdigest()
    return JA3SResult(ja3s_string=ja3s_string, ja3s_hash=ja3s_hash)
