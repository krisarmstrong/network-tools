"""PCAP filtering utilities derived from the old pcap_parser project."""

from __future__ import annotations

from pathlib import Path

MAC_PREFIX = "00:c0:17"
TARGET_PORT = 3842


def _scapy():  # pragma: no cover
    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
    except Exception as exc:
        raise RuntimeError(
            "scapy is required for PCAP filtering. "
            "Install network-tools with its default dependencies."
        ) from exc
    return rdpcap, Ether, IP, TCP, UDP, Raw


def format_record(record: dict[str, str]) -> str:
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
    rdpcap, ether, ip, tcp, udp, raw = _scapy()
    packets = rdpcap(str(input_path))
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("Filtered Packet Details\n" + "=" * 30 + "\n")
        for pkt in packets:
            if not pkt.haslayer(ether):
                continue
            src_mac = pkt[ether].src
            if not src_mac.startswith(MAC_PREFIX):
                continue
            protocol = "TCP" if pkt.haslayer(tcp) else "UDP" if pkt.haslayer(udp) else None
            if protocol is None:
                continue
            src_ip = pkt[ip].src if pkt.haslayer(ip) else "N/A"
            dst_ip = pkt[ip].dst if pkt.haslayer(ip) else "N/A"
            src_port = (
                pkt[tcp].sport
                if pkt.haslayer(tcp)
                else pkt[udp].sport
                if pkt.haslayer(udp)
                else None
            )
            dst_port = (
                pkt[tcp].dport
                if pkt.haslayer(tcp)
                else pkt[udp].dport
                if pkt.haslayer(udp)
                else None
            )
            if TARGET_PORT not in (src_port, dst_port):
                continue
            payload = pkt[raw].load.hex() if pkt.haslayer(raw) else ""
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
