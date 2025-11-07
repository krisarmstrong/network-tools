# network-tools

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

The repo ships with `nox -s tests` and `.github/workflows/ci.yml`; versions are derived from annotated git tags via
`setuptools_scm`.

## Packet Performance Listener
The original C-based high-performance listener from `packet_listener_linux_perf_test` is preserved under
`extras/packet_listener_linux/`. Build with `cmake` or `gcc` on Linux hosts when you need raw-socket throughput testing.
