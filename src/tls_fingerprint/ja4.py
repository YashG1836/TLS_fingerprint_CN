"""JA4 fingerprint computation (client-side only; JA4, not JA4S/JA4H/...).

Implements the JA4 spec published by FoxIO
(https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).
JA4 fixes JA3's biggest weakness: JA3 is order-sensitive, and Chrome
randomizes its ClientHello extension order per connection specifically to
defeat that -- we saw this happen live (same real Chrome, two runs, two
different JA3 hashes; see docs/IMPLEMENTATION.md). JA4 sorts the cipher
and extension lists before hashing, so pure reordering no longer changes
the fingerprint.

JA4 string shape (3 underscore-joined segments):

    <a>_<b>_<c>

  a = t13d1516h2
      t            protocol: "t" (TLS/TCP), "q" (QUIC), "d" (DTLS) -- this
                   project only ever sees TCP/TLS pcaps, so always "t"
      13           TLS version (from supported_versions ext if present,
                   else the legacy version field), 2-char code
      d            "d" if SNI extension present, else "i"
      15           2-digit cipher count, GREASE excluded, capped at 99
      16           2-digit extension count, GREASE excluded, SNI/ALPN
                   INCLUDED in the count (they're just excluded later,
                   from the hashed lists in b/c, not from this count)
      h2           first+last char of the first ALPN value, "00" if none
  b = truncated SHA256 of the cipher list, sorted numerically, hex
  c = truncated SHA256 of (sorted extension list, SNI+ALPN removed) +
      "_" + (signature_algorithms list, IN THE ORDER THEY WERE SENT --
      not sorted)

GREASE values (RFC 8701) are stripped everywhere, using the same table
ja3.py already defines -- it's the identical reserved value set, so we
reuse it rather than duplicating it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .ja3 import is_grease
from .parser import ClientHelloInfo, Extension

EXT_SNI = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_SIGNATURE_ALGORITHMS = 0x000D

_TLS_VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    # DTLS versions, included for spec fidelity even though this project
    # only ever parses TLS-over-TCP pcaps:
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}


@dataclass(frozen=True)
class JA4Result:
    ja4_string: str
    part_a: str
    part_b: str
    part_c: str


def _find_extension(extensions: list[Extension], ext_type: int) -> Extension | None:
    for ext in extensions:
        if ext.ext_type == ext_type:
            return ext
    return None


def _parse_u16_list_1byte_len(data: bytes) -> list[int]:
    """ClientHello's supported_versions uses a 1-byte length prefix
    (RFC 8446 4.2.1) -- unlike most other extensions here."""
    if len(data) < 1:
        return []
    list_len = data[0]
    body = data[1 : 1 + list_len]
    return [int.from_bytes(body[i : i + 2], "big") for i in range(0, len(body) - 1, 2)]


def _parse_u16_list_2byte_len(data: bytes) -> list[int]:
    """signature_algorithms (RFC 8446 4.2.3) uses a 2-byte length prefix."""
    if len(data) < 2:
        return []
    list_len = int.from_bytes(data[0:2], "big")
    body = data[2 : 2 + list_len]
    return [int.from_bytes(body[i : i + 2], "big") for i in range(0, len(body) - 1, 2)]


def _parse_alpn_first_value(data: bytes) -> bytes | None:
    """ALPN extension data: 2B ProtocolNameList length, then a sequence of
    [1B length][name bytes] entries. Returns the first entry's bytes."""
    if len(data) < 2:
        return None
    list_len = int.from_bytes(data[0:2], "big")
    body = data[2 : 2 + list_len]
    if len(body) < 1:
        return None
    name_len = body[0]
    name = body[1 : 1 + name_len]
    return name if name else None


def _is_ascii_alnum(b: int) -> bool:
    return 0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A


def _alpn_chars(first_alpn: bytes | None) -> str:
    if not first_alpn:
        return "00"
    if len(first_alpn) == 1:
        first_b, last_b = first_alpn[0], first_alpn[0]
    else:
        first_b, last_b = first_alpn[0], first_alpn[-1]

    if _is_ascii_alnum(first_b) and _is_ascii_alnum(last_b):
        return chr(first_b) + chr(last_b)

    # Fall back to the hex representation of the WHOLE first ALPN value,
    # then take the first and last characters of THAT hex string --
    # verified against every worked example in the spec's ALPN section.
    hex_str = first_alpn.hex()
    return hex_str[0] + hex_str[-1]


def _tls_version_code(client_hello: ClientHelloInfo) -> str:
    sv_ext = _find_extension(client_hello.extensions, EXT_SUPPORTED_VERSIONS)
    if sv_ext is not None:
        versions = [v for v in _parse_u16_list_1byte_len(sv_ext.data) if not is_grease(v)]
        if versions:
            return _TLS_VERSION_CODES.get(max(versions), "00")
    return _TLS_VERSION_CODES.get(client_hello.version, "00")


def _cipher_hash(ciphers: list[int]) -> str:
    non_grease = sorted(c for c in ciphers if not is_grease(c))
    if not non_grease:
        return "000000000000"
    joined = ",".join(f"{c:04x}" for c in non_grease)
    return hashlib.sha256(joined.encode("ascii")).hexdigest()[:12]


def _extension_hash(extensions: list[Extension], sig_algs: list[int]) -> str:
    non_grease_sorted = sorted(
        e.ext_type
        for e in extensions
        if not is_grease(e.ext_type) and e.ext_type not in (EXT_SNI, EXT_ALPN)
    )
    if not non_grease_sorted:
        return "000000000000"
    ext_part = ",".join(f"{e:04x}" for e in non_grease_sorted)
    if sig_algs:
        sig_part = ",".join(f"{s:04x}" for s in sig_algs if not is_grease(s))
        full = f"{ext_part}_{sig_part}" if sig_part else ext_part
    else:
        full = ext_part
    return hashlib.sha256(full.encode("ascii")).hexdigest()[:12]


def compute_ja4(client_hello: ClientHelloInfo) -> JA4Result:
    protocol = "t"  # this project only ever parses TLS-over-TCP pcaps
    version_code = _tls_version_code(client_hello)
    sni_flag = "d" if _find_extension(client_hello.extensions, EXT_SNI) is not None else "i"

    cipher_count = min(99, sum(1 for c in client_hello.cipher_suites if not is_grease(c)))
    ext_count = min(
        99, sum(1 for e in client_hello.extensions if not is_grease(e.ext_type))
    )

    alpn_ext = _find_extension(client_hello.extensions, EXT_ALPN)
    alpn_chars = _alpn_chars(_parse_alpn_first_value(alpn_ext.data) if alpn_ext else None)

    part_a = f"{protocol}{version_code}{sni_flag}{cipher_count:02d}{ext_count:02d}{alpn_chars}"

    part_b = _cipher_hash(client_hello.cipher_suites)

    sig_alg_ext = _find_extension(client_hello.extensions, EXT_SIGNATURE_ALGORITHMS)
    sig_algs = _parse_u16_list_2byte_len(sig_alg_ext.data) if sig_alg_ext else []
    part_c = _extension_hash(client_hello.extensions, sig_algs)

    return JA4Result(
        ja4_string=f"{part_a}_{part_b}_{part_c}",
        part_a=part_a,
        part_b=part_b,
        part_c=part_c,
    )
