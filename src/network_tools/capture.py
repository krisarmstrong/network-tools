"""Discovery protocol capture helpers."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Dict, Optional

# Destination MACs for common discovery protocols
PROTO_MAP = {
    "01:00:0c:cc:cc:cc": "CDP",
    "01:80:c2:00:00:0e": "LLDP",
    "01:e0:52:cc:cc:cc": "EDP",
    "01:e0:2f:00:00:00": "FDP",
}


def _scapy():  # pragma: no cover - heavy dependency
    try:
        from scapy.all import sniff, rdpcap
        from scapy.layers.l2 import Dot3, SNAP
        from scapy.packet import Packet, Raw
        from scapy.contrib.lldp import LLDPDU
    except Exception as exc:
        raise RuntimeError("scapy is required for capture operations. Install network-tools with its default dependencies.") from exc

    return sniff, rdpcap, Dot3, SNAP, Packet, LLDPDU, Raw


def parse_packet(pkt) -> Optional[Dict[str, str]]:  # pragma: no cover (requires scapy objects)
    sniff, rdpcap, Dot3, SNAP, Packet, LLDPDU, Raw = _scapy()
    if not pkt.haslayer(Dot3) or not pkt.haslayer(SNAP):
        return None
    proto = PROTO_MAP.get(pkt[Dot3].dst)
    if not proto:
        return None
    record = {
        "timestamp": time.ctime(),
        "protocol": proto,
        "src_mac": pkt[Dot3].src,
        "dst_mac": pkt[Dot3].dst,
    }
    if pkt.haslayer(Raw):
        record["payload"] = pkt[Raw].load.hex()
    return record


def listen(interface: str, output: Path, daemon: bool = False) -> None:  # pragma: no cover - requires root
    sniff, rdpcap, Dot3, SNAP, Packet, LLDPDU, Raw = _scapy()

    def handler(pkt):
        record = parse_packet(pkt)
        if record:
            _write_record(record, output)

    if not daemon:
        logging.info("Listening on %s", interface)
    sniff(iface=interface, prn=handler, store=0)


def parse_pcap(path: Path, output: Path) -> None:  # pragma: no cover - requires scapy
    sniff, rdpcap, Dot3, SNAP, Packet, LLDPDU, Raw = _scapy()
    logging.info("Parsing PCAP %s", path)
    packets = rdpcap(str(path))
    for pkt in packets:
        record = parse_packet(pkt)
        if record:
            _write_record(record, output)


def _write_record(record: Dict[str, str], output: Path) -> None:
    line = [
        f"Time: {record.get('timestamp')}",
        f"Protocol: {record.get('protocol')}",
        f"Source MAC: {record.get('src_mac')}",
        f"Destination MAC: {record.get('dst_mac')}",
    ]
    if payload := record.get("payload"):
        line.append(f"Payload (hex): {payload}")
    line.append("=" * 40)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(line) + "\n")
