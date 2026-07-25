"""Command-line interface for the live packet capture engine."""

from __future__ import annotations

import argparse
import logging
import sys

from packet_capture.capture import PacketCaptureEngine
from packet_capture.interfaces import list_interfaces


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet_capture",
        description="Live Packet Capture Engine (MLCN Module 1)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture on (e.g. en0, lo0, eth0). "
        "Defaults to Scapy's default interface.",
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser


def _print_interfaces() -> None:
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces detected.")
        return

    print(f"{'INTERFACE':<20} {'ADDRESS':<20}")
    print("-" * 40)
    for iface in interfaces:
        address = iface.address or "-"
        print(f"{iface.name:<20} {address:<20}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    if args.list_interfaces:
        _print_interfaces()
        return 0

    try:
        engine = PacketCaptureEngine(interface=args.interface)
        engine.start()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
