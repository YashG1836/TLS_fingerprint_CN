"""Write raw captured TLS handshake bytes out as a synthetic-but-real PCAP.

Used by capture_proxy.py and the raw-socket custom client experiment: both
capture genuine TLS bytes exchanged with a real server, just not via a NIC
promiscuous-mode tap (which needs root on macOS). We wrap the real bytes in
hand-built Ethernet/IP/TCP headers so downstream tooling (analyzer.py, the
CLI, Wireshark) sees an ordinary-looking pcap. This does NOT fabricate any
handshake content -- only the link-layer framing around real bytes is
synthetic. Every pcap produced this way is documented as such in
data/fingerprint_db.json and docs/EXPERIMENTS.md.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

# Locally-administered, clearly-fake MAC addresses (the "02" prefix marks
# them as locally administered per IEEE 802 -- guaranteed not a real vendor
# OUI). Using explicit MACs avoids Scapy trying to ARP-resolve real ones.
_CLIENT_MAC = "02:00:00:00:00:01"
_SERVER_MAC = "02:00:00:00:00:02"


def write_synthetic_pcap(
    path: str | Path,
    client_ip: str,
    client_port: int,
    server_ip: str,
    server_port: int,
    client_bytes: bytes,
    server_bytes: bytes,
) -> None:
    packets = []
    if client_bytes:
        packets.append(
            Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, seq=1000, flags="PA")
            / Raw(load=bytes(client_bytes))
        )
    if server_bytes:
        packets.append(
            Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, seq=2000, flags="PA")
            / Raw(load=bytes(server_bytes))
        )
    wrpcap(str(path), packets)
