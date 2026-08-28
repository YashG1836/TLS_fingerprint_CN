"""JA3 fingerprint computation.

Implements the JA3 spec as published by Salesforce Engineering
("TLS Fingerprinting with JA3 and JA3S", John B. Althouse et al.,
https://github.com/salesforce/ja3). JA3 is built purely from fields already
present in the ClientHello -- nothing here is inferred or invented.

JA3 string format (5 comma-separated fields, each a "-"-joined decimal list):

    SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat

- SSLVersion: the ClientHello's own version field (decimal).
- Cipher: cipher suites offered, in the order the client listed them.
- SSLExtension: extension type IDs, in the order they appear.
- EllipticCurve: the supported_groups (elliptic curves) extension list.
- EllipticCurvePointFormat: the ec_point_formats extension list.

Any field that has no data (extension absent) is left empty -- the commas
still appear, so the field count in the string is always 5.

GREASE values (RFC 8701) are reserved by some clients (Chrome, and others
that follow suit) as placeholder cipher/extension/group IDs whose only
purpose is to catch servers that break on unknown values. They are
intentionally randomized per-connection, so JA3 strips them out everywhere
they can appear -- otherwise every GREASE-using client would fingerprint as
a different JA3 hash on every single connection, defeating the point of a
fingerprint.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .parser import ClientHelloInfo

# RFC 8701: GREASE values are the 16 uint16s of the form 0x?A?A where both
# nibbles are the same value (0x0A0A, 0x1A1A, ..., 0xFAFA).
GREASE_VALUES = frozenset(
    (b << 12) | (0xA << 8) | (b << 4) | 0xA for b in range(16)
)


def is_grease(value: int) -> bool:
    return value in GREASE_VALUES


def _filter_grease(values: list[int]) -> list[int]:
    return [v for v in values if not is_grease(v)]


@dataclass(frozen=True)
class JA3Result:
    ja3_string: str
    ja3_hash: str


def build_ja3_string(client_hello: ClientHelloInfo) -> str:
    version = client_hello.version
    ciphers = _filter_grease(client_hello.cipher_suites)
    extensions = _filter_grease(client_hello.extension_types)
    curves = _filter_grease(client_hello.supported_groups)
    point_formats = client_hello.ec_point_formats  # not a GREASE-able field

    fields = [
        str(version),
        "-".join(str(v) for v in ciphers),
        "-".join(str(v) for v in extensions),
        "-".join(str(v) for v in curves),
        "-".join(str(v) for v in point_formats),
    ]
    return ",".join(fields)


def compute_ja3(client_hello: ClientHelloInfo) -> JA3Result:
    ja3_string = build_ja3_string(client_hello)
    ja3_hash = hashlib.md5(ja3_string.encode("ascii")).hexdigest()
    return JA3Result(ja3_string=ja3_string, ja3_hash=ja3_hash)
