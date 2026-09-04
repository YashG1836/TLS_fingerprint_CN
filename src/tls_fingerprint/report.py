"""Human-readable CLI report formatting for a FlowReport.

Kept separate from cli.py (argument parsing) and analyzer.py (computation)
so the text format can be unit tested without touching stdout.
"""

from __future__ import annotations

from .analyzer import FlowReport
from .database import MatchResult

TLS_VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def version_name(version: int) -> str:
    return TLS_VERSION_NAMES.get(version, f"Unknown (0x{version:04x})")


def effective_tls_version(report: FlowReport) -> int | None:
    """TLS 1.3 ServerHellos keep the legacy 0x0303 in the version field for
    middlebox compatibility and signal the real version via the
    supported_versions extension (type 43, 2-byte value) instead. Prefer
    that when present so the reported version is the one actually
    negotiated, not the legacy placeholder."""
    if report.server_hello is not None:
        for ext in report.server_hello.extensions:
            if ext.ext_type == 0x002B and len(ext.data) >= 2:
                return int.from_bytes(ext.data[0:2], "big")
        return report.server_hello.version
    if report.client_hello is not None:
        return report.client_hello.version
    return None


def _match_line(match: MatchResult | None) -> tuple[str, str]:
    """Return (likely_name_line, match_line) for the Identification block."""
    if match is None:
        return "Not looked up", "No database provided"
    if match.status == "known":
        name = match.entries[0].name
        return name, "Known match (reference database)"
    if match.status == "possible":
        names = ", ".join(sorted({e.name for e in match.entries}))
        return f"Possibly one of: {names}", "Possible match (hash shared by multiple entries)"
    return "Unknown", "Unknown fingerprint (not in reference database)"


def _fingerprint_block(lines, title, string, extra_hash_line, match, who_label):
    lines.append(title)
    lines.append("-" * 32)
    lines.append(f"String: {string}")
    if extra_hash_line:
        lines.append(extra_hash_line)
    lines.append("")

    name_line, match_line = _match_line(match)
    lines.append(f"{who_label} Identification")
    lines.append("-" * 32)
    prefix = f"Likely {who_label}: "
    lines.append(f"{prefix}{name_line}")
    lines.append(f"Match:{' ' * (len(prefix) - len('Match:'))}{match_line}")
    lines.append("")


def format_report(report: FlowReport, index: int | None = None) -> str:
    lines: list[str] = []
    header = "Flow" if index is None else f"Flow #{index}"
    lines.append(header)
    lines.append("-" * 32)
    lines.append(f"Source:      {report.client_endpoint[0]}:{report.client_endpoint[1]}")
    lines.append(f"Destination: {report.server_endpoint[0]}:{report.server_endpoint[1]}")
    if report.client_hello and report.client_hello.server_name:
        lines.append(f"SNI:         {report.client_hello.server_name}")
    lines.append("")

    lines.append("TLS")
    lines.append("-" * 32)
    version = effective_tls_version(report)
    lines.append(f"Version: {version_name(version) if version is not None else 'Unknown'}")
    lines.append("")

    if report.ja3:
        _fingerprint_block(
            lines, "JA3 (client)", report.ja3.ja3_string,
            f"Hash:   {report.ja3.ja3_hash}", report.ja3_match, "Client",
        )

    if report.ja4:
        _fingerprint_block(
            lines, "JA4 (client, reorder-resistant)", report.ja4.ja4_string,
            None, report.ja4_match, "Client",
        )

    if report.ja3s:
        _fingerprint_block(
            lines, "JA3S (server)", report.ja3s.ja3s_string,
            f"Hash:   {report.ja3s.ja3s_hash}", report.ja3s_match, "Server Stack",
        )
    else:
        lines.append("JA3S (server)")
        lines.append("-" * 32)
        lines.append("No ServerHello captured for this flow.")
        lines.append("")

    return "\n".join(lines)
