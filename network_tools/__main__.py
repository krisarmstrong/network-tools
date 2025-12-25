"""CLI entry point for network-tools."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import capture, json_parser, pcap_filter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unified network discovery toolkit.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    parser.add_argument("--logfile", type=Path, help="Optional log file.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    listen_parser = subparsers.add_parser(
        "listen", help="Capture discovery protocols live or from PCAP."
    )
    listen_parser.add_argument("--interface", help="Interface to sniff (live mode).")
    listen_parser.add_argument(
        "--pcap", type=Path, help="Read packets from a pcap file instead of live capture."
    )
    listen_parser.add_argument("--output", type=Path, default=Path("discovery_log.txt"))
    listen_parser.add_argument("--daemon", action="store_true", help="Suppress console messages.")

    json_parser_cmd = subparsers.add_parser(
        "parse-json", help="Parse NetAlly discovery.json host data."
    )
    json_parser_cmd.add_argument("input", type=Path)

    filter_parser = subparsers.add_parser(
        "filter-pcap", help="Filter pcaps for NetAlly reflector traffic."
    )
    filter_parser.add_argument("input", type=Path)
    filter_parser.add_argument("output", type=Path)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose, args.logfile)

    if args.command == "listen":
        if args.pcap:
            capture.parse_pcap(args.pcap, args.output)
        else:
            if not args.interface:
                parser.error("--interface is required for live capture.")
            capture.listen(args.interface, args.output, daemon=args.daemon)
    elif args.command == "parse-json":
        hosts = json_parser.load_hosts(args.input)
        count = json_parser.count_valid_ipv4(hosts)
        for idx, host in enumerate(hosts, 1):
            print(json_parser.format_host(host, idx))
        print(f"\nTotal Valid IPv4 Address(es): {count}")
    elif args.command == "filter-pcap":
        pcap_filter.filter_pcap(args.input, args.output)
    else:
        parser.error("Unknown command")
    return 0


def setup_logging(verbose: bool, logfile: Path | None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(
        level=level, handlers=handlers, format="%(asctime)s [%(levelname)s] %(message)s"
    )


if __name__ == "__main__":
    sys.exit(main())
