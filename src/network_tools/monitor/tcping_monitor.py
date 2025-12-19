#!/usr/bin/env python3
"""
Project Title: TCP Ping Monitor

This script tracks and trends the TCP response time of given hosts using either Python sockets
or the third-party 'tcping' tool. Results are logged over time for trend analysis.

Author: Your Name
"""
__version__ = "1.1.0"

import argparse
import csv
import logging
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import List, Tuple, Optional

# Constants
LOG_FILE = "tcping_monitor.log"
CSV_FILE = "tcping_monitor.csv"
DEFAULT_INTERVAL = 600
DEFAULT_METHOD = "python"

# Configure logging
logger = logging.getLogger("tcping_monitor")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor TCP response times to specified hosts.")
    parser.add_argument(
        "--method",
        choices=["python", "tcping"],
        default=DEFAULT_METHOD,
        help="Method: 'python' or 'tcping'",
    )
    parser.add_argument(
        "--interval", type=int, default=DEFAULT_INTERVAL, help="Time in seconds between checks"
    )
    return parser.parse_args()


def check_tcp_python(host: str, port: int = 80, timeout: float = 3.0) -> Optional[float]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout):
            return round(time.time() - start, 3)
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        logger.error("Python TCP check failed for %s: %s", host, str(e))
        return None


def check_tcp_tcping(host: str) -> Optional[float]:
    try:
        result = subprocess.run(
            ["tcping", host, "-n", "1"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and "time=" in result.stdout:
            for line in result.stdout.splitlines():
                if "time=" in line:
                    return float(line.split("time=")[1].split("ms")[0].strip()) / 1000
    except Exception as e:
        logger.error("tcping call failed for %s: %s", host, str(e))
    return None


def write_csv(timestamp: str, results: List[Tuple[str, Optional[float]]]) -> None:
    new_file = not os.path.exists(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["timestamp"] + [host for host, _ in results])
        writer.writerow(
            [timestamp]
            + [str(latency) if latency is not None else "fail" for _, latency in results]
        )


def main():
    args = parse_args()
    hosts = ["8.8.8.8", "1.1.1.1", "example.com"]

    logger.info("Starting TCP Ping Monitor using method: %s", args.method)

    try:
        while True:
            timestamp = datetime.utcnow().isoformat()
            results = []
            for host in hosts:
                if args.method == "python":
                    latency = check_tcp_python(host)
                else:
                    latency = check_tcp_tcping(host)
                results.append((host, latency))
                if latency is not None:
                    logger.info("%s latency: %.3f sec", host, latency)
                else:
                    logger.warning("%s failed to respond.", host)
            write_csv(timestamp, results)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("Shutting down TCP Ping Monitor.")
        sys.exit(0)


if __name__ == "__main__":
    main()
