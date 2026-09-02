"""Run the lab HTTP echo server on Laptop B for two-machine IDS tests."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from traffic_generator.connectivity import (
    local_ip_addresses,
    recommended_receiver_pipeline_command,
)
from traffic_generator.lab_server import LabEchoServer

logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Start the MLCN lab HTTP echo server on the receiver laptop (Laptop B). "
            "Required for BENIGN / DDoS / DoS / Brute Force two-machine tests."
        )
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind address (default: 0.0.0.0 — all interfaces on Laptop B)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="TCP port to listen on (default: 8080)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    server = LabEchoServer(host=args.host, port=args.port)
    server.start()
    if not server.running:
        logger.error("failed to bind %s:%s — port may be in use", args.host, args.port)
        return 1

    print(
        f"MLCN lab echo server listening on {args.host}:{args.port}\n"
        "Leave this running while Laptop A generates traffic toward this host.\n"
        "Press Ctrl+C to stop.\n",
        flush=True,
    )
    local_ips = ", ".join(sorted(local_ip_addresses()))
    print(f"This host local IPs: {local_ips}")
    print("\nRecommended receiver pipeline command (run in a second Admin terminal):")
    print(f"  {recommended_receiver_pipeline_command(port=args.port)}")
    print(
        "\nWhy: on Windows, traffic to this PC's own IP often bypasses Wi-Fi capture "
        "and only outbound Internet traffic (e.g. :443) appears. "
        "Use --lab-port to hide that noise and capture loopback + Wi-Fi together.\n",
        flush=True,
    )

    stop = False

    def _handle_signal(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    try:
        while not stop:
            time.sleep(0.25)
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
