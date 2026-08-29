"""Orchestrates: pcap -> TCP flows -> ClientHello/ServerHello -> JA3/JA3S ->
database lookup. This is the "pipeline glue" box in the architecture
diagram; parser.py, ja3.py, ja3s.py and database.py each stay independently
testable and this module just wires them together per flow.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, IPv6, TCP, Raw, rdpcap

from .database import FingerprintDatabase, MatchResult
from .ja3 import JA3Result, compute_ja3
from .ja3s import JA3SResult, compute_ja3s
from .ja4 import JA4Result, compute_ja4
from .parser import (
    ClientHelloInfo,
    ServerHelloInfo,
    find_client_hello,
    find_server_hello,
    reassemble_tcp_stream,
)

Endpoint = tuple[str, int]


@dataclass(frozen=True)
class FlowKey:
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int


@dataclass
class FlowReport:
    client_endpoint: Endpoint
    server_endpoint: Endpoint
    client_hello: ClientHelloInfo | None
    server_hello: ServerHelloInfo | None
    ja3: JA3Result | None = None
    ja3s: JA3SResult | None = None
    ja3_match: MatchResult | None = None
    ja3s_match: MatchResult | None = None
    ja4: JA4Result | None = None
    ja4_match: MatchResult | None = None


def _canonical_key(ip1: str, port1: int, ip2: str, port2: int):
    """Map a packet's (src, dst) endpoints to a direction-independent flow
    key plus which stored slot ("a_to_b" / "b_to_a") this packet's payload
    belongs in."""
    if (ip1, port1) <= (ip2, port2):
        return FlowKey(ip1, port1, ip2, port2), "a_to_b"
    return FlowKey(ip2, port2, ip1, port1), "b_to_a"


def _group_into_flows(packets) -> dict[FlowKey, dict[str, list[tuple[int, bytes]]]]:
    flows: dict[FlowKey, dict[str, list[tuple[int, bytes]]]] = {}
    for pkt in packets:
        if TCP not in pkt:
            continue
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            continue
        tcp = pkt[TCP]
        payload = bytes(pkt[Raw].load) if Raw in pkt else b""
        if not payload:
            continue

        key, direction = _canonical_key(src_ip, int(tcp.sport), dst_ip, int(tcp.dport))
        slot = flows.setdefault(key, {"a_to_b": [], "b_to_a": []})
        slot[direction].append((int(tcp.seq), payload))
    return flows


def analyze_packets(packets, db: FingerprintDatabase | None = None) -> list[FlowReport]:
    flows = _group_into_flows(packets)
    reports: list[FlowReport] = []

    for key, directions in flows.items():
        stream_ab = reassemble_tcp_stream(directions["a_to_b"])
        stream_ba = reassemble_tcp_stream(directions["b_to_a"])

        client_hello = find_client_hello(stream_ab)
        client_dir = "a_to_b"
        if client_hello is None:
            client_hello = find_client_hello(stream_ba)
            client_dir = "b_to_a"
        if client_hello is None:
            continue  # this flow has no ClientHello we could extract

        server_stream = stream_ba if client_dir == "a_to_b" else stream_ab
        server_hello = find_server_hello(server_stream)

        if client_dir == "a_to_b":
            client_endpoint: Endpoint = (key.ip_a, key.port_a)
            server_endpoint: Endpoint = (key.ip_b, key.port_b)
        else:
            client_endpoint = (key.ip_b, key.port_b)
            server_endpoint = (key.ip_a, key.port_a)

        report = FlowReport(
            client_endpoint=client_endpoint,
            server_endpoint=server_endpoint,
            client_hello=client_hello,
            server_hello=server_hello,
        )

        report.ja3 = compute_ja3(client_hello)
        if db is not None:
            report.ja3_match = db.lookup(report.ja3.ja3_hash, "ja3")
        report.ja4 = compute_ja4(client_hello)
        if db is not None:
            report.ja4_match = db.lookup(report.ja4.ja4_string, "ja4")

        if server_hello is not None:
            report.ja3s = compute_ja3s(server_hello)
            if db is not None:
                report.ja3s_match = db.lookup(report.ja3s.ja3s_hash, "ja3s")

        reports.append(report)

    return reports


def analyze_pcap(path: str | Path, db: FingerprintDatabase | None = None) -> list[FlowReport]:
    packets = rdpcap(str(path))
    return analyze_packets(packets, db=db)
