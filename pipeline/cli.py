"""CLI for the integrated MLCN Modules 1–5 pipeline."""

from __future__ import annotations

import argparse
import logging
import sys

from packet_capture.interfaces import list_interfaces

from pipeline.engine import IntrusionDetectionPipeline
from pipeline.models import PipelineResult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipeline",
        description="MLCN end-to-end intrusion detection pipeline (Modules 1–5)",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture on (e.g. Ethernet, Wi-Fi, lo0). "
        "Defaults to Scapy's default interface.",
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--inactivity-timeout",
        type=float,
        default=60.0,
        help="Module 3 idle timeout in seconds (default: 60).",
    )
    parser.add_argument(
        "--max-duration",
        type=float,
        default=300.0,
        help="Module 3 max flow duration in seconds (default: 300).",
    )
    parser.add_argument(
        "--lab-port",
        type=int,
        metavar="PORT",
        help=(
            "Laboratory mode: capture/print only flows involving this TCP port "
            "(e.g. 8080 for traffic-generator tests). Filters out background Internet traffic."
        ),
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


def _print_result(result: PipelineResult) -> None:
    flow = result.flow
    detection = result.detection
    print(
        f"[{detection.predicted_class}] "
        f"conf={detection.confidence:.4f} "
        f"{flow.protocol} {flow.src_ip}:{flow.src_port} → "
        f"{flow.dst_ip}:{flow.dst_port} "
        f"pkts={flow.packet_count} bytes={flow.byte_count} "
        f"dur={flow.duration:.3f}s",
        flush=True,
    )


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
        pipeline = IntrusionDetectionPipeline(
            interface=args.interface,
            inactivity_timeout=args.inactivity_timeout,
            max_duration=args.max_duration,
            on_detection=_print_result,
            lab_port=args.lab_port,
        )
    except Exception as exc:
        print(f"Error initializing pipeline: {exc}", file=sys.stderr)
        return 1

    iface_label = args.interface or "default"
    print(f"MLCN pipeline starting on interface: {iface_label}")
    if args.lab_port:
        print(f"Lab filter active: TCP port {args.lab_port}")
    print("Modules: Capture → Parse → Flow → Features → XGBoost")
    print("Press Ctrl+C to stop and flush active flows.\n")

    try:
        results = pipeline.run_live()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"\nPipeline stopped. "
        f"Accepted {pipeline.packets_accepted} packet(s), "
        f"skipped {pipeline.packets_skipped}, "
        f"detections {len(results)}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
