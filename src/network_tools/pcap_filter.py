"""PCAP filtering utilities derived from the old pcap_parser project."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

MAC_PREFIX = "00:c0:17"
TARGET_PORT = 3842


def _scapy():  # pragma: no cover
    try:
        from scapy.all import rdpcap
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.packet import Raw
    except Exception as exc:
        raise RuntimeError("scapy is required for PCAP filtering. Install network-tools with its default dependencies.") from exc
    return rdpcap, Ether, IP, TCP, UDP, Raw


def format_record(record: Dict[str, str]) -> str:
    lines = [
        f"Source MAC: {record['src_mac']}",
        f"Source IP: {record['src_ip']}",
        f"Destination IP: {record['dst_ip']}",
        f"Protocol: {record['protocol']}",
        f"Source Port: {record['src_port']}",
        f"Destination Port: {record['dst_port']}",
    ]
    if payload := record.get("payload"):
        lines.append(f"Payload (hex): {payload}")
    lines.append("-" * 30)
    return "\n".join(lines)


def filter_pcap(input_path: Path, output_path: Path) -> None:  # pragma: no cover
    rdpcap, Ether, IP, TCP, UDP, Raw = _scapy()
    packets = rdpcap(str(input_path))
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("Filtered Packet Details\n" + "=" * 30 + "\n")
        for pkt in packets:
            if not pkt.haslayer(Ether):
                continue
            src_mac = pkt[Ether].src
            if not src_mac.startswith(MAC_PREFIX):
                continue
            protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else None
            if protocol is None:
                continue
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else None
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else None
            if TARGET_PORT not in (src_port, dst_port):
                continue
            payload = pkt[Raw].load.hex() if pkt.haslayer(Raw) else ""
            record = {
                "src_mac": src_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": str(src_port or "N/A"),
                "dst_port": str(dst_port or "N/A"),
                "payload": payload,
            }
            handle.write(format_record(record) + "\n")
