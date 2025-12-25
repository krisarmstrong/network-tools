"""Parse NetAlly discovery.json payloads."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List

SENSITIVE_PATTERNS = ["api_key", "password"]


def load_hosts(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    detail = data.get("Detail") or {}
    hosts = detail.get("host_list")
    if not isinstance(hosts, list):
        raise ValueError("JSON must contain Detail.host_list array")
    return hosts


def contains_sensitive_text(path: Path) -> bool:
    payload = path.read_text(encoding="utf-8")
    return any(marker in payload for marker in SENSITIVE_PATTERNS)


def count_valid_ipv4(hosts: List[Dict[str, Any]]) -> int:
    count = 0
    for host in hosts:
        ip_addr = (host.get("host") or {}).get("ip_v4_address")
        if ip_addr:
            try:
                ipaddress.IPv4Address(ip_addr)
                count += 1
            except ipaddress.AddressValueError:
                pass
    return count


def format_host(host: Dict[str, Any], index: int) -> str:
    data = host.get("host", {})
    lines = [f"Host {index}:"]
    for field in (
        "host_id",
        "mac_address",
        "ip_v4_address",
        "ip_v4_subnet",
        "ip_v6_address",
        "mdns_name",
        "user_name",
    ):
        lines.append(f"  {field}: {data.get(field, 'N/A')}")
    return "\n".join(lines)
