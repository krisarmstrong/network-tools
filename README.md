# network-tools
[![Checks](https://github.com/krisarmstrong/network-tools/actions/workflows/checks.yml/badge.svg)](https://github.com/krisarmstrong/network-tools/actions/workflows/checks.yml)


[![CI](https://github.com/krisarmstrong/network-tools/workflows/CI/badge.svg)](https://github.com/krisarmstrong/network-tools/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Everything from `network_discovery`, `network_discovery_listener`, `network_discovery_parser`,
`pcap_parser`, and `packet_listener_linux_perf_test` now lives here.

```bash
pip install .
network-tools --help
```

## Commands

### `network-tools listen`
Capture CDP/LLDP/EDP/FDP packets either live (`--interface eth0`) or from a PCAP (`--pcap capture.pcap`).
Results are appended to `--output` (default `discovery_log.txt`).

### `network-tools parse-json`
Parse NetAlly `discovery.json` host lists, print formatted host info, and count valid IPv4 addresses.

```bash
network-tools parse-json discovery.json
```

### `network-tools filter-pcap`
Filter NetAlly reflector traffic (MAC prefix `00:c0:17`, UDP/TCP port 3842) and dump packet details.

```bash
network-tools filter-pcap reflector_capture.pcap reflector_report.txt
```

## Development & CI
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[test]
python -m pytest
```

The repo ships with `nox -s tests` and `.github/workflows/ci.yml`; versions are stored in `pyproject.toml` and
release-please manages tags and changelog entries.

## Packet Performance Listener
The original C-based high-performance listener from `packet_listener_linux_perf_test` is preserved under
`extras/packet_listener_linux/`. Build with `cmake` or `gcc` on Linux hosts when you need raw-socket throughput testing.

## WiFi Analysis

Comprehensive Wi-Fi packet parsing and analysis capabilities (merged from wi-fi-packet-parser).

### Features
- PCAP file parsing
- Wi-Fi frame analysis
- OUI lookup and vendor identification
- Channel and signal strength analysis

## Switch Management

Network switch port querying and management (merged from switch-port-query).

### Features
- SNMP-based port queries
- Port configuration management
- VLAN information retrieval
- PoE status monitoring

## Network Monitoring

TCP connectivity monitoring tools (merged from tping-monitor).

### Features
- TCP ping (tcping) functionality
- Continuous network monitoring
- Connection latency tracking
- Availability reporting

## Documentation

- [WiFi Packet Parser](docs/WIFI_PARSER.md)
- [Switch Port Query](docs/SWITCH_QUERY.md)
- [TCP Ping Monitor](docs/TPING_MONITOR.md)

---

Enhanced from:
- wi-fi-packet-parser
- switch-port-query
- tping-monitor

## Development

Run the full local checks:

```bash
./check.sh
```
